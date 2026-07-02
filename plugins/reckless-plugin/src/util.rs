use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr,
    time::Duration,
};

use anyhow::anyhow;
use cln_plugin::{Plugin, options};
use cln_rpc::{
    codec::MultiLineCodec,
    model::{requests::PluginRequest, responses::PluginResponse},
    notifications::LogLevel,
    primitives::PluginSubcommand,
};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
    time::timeout,
};
use tokio_util::codec::FramedRead;
use url::Url;
use which::which;

use crate::structs::{
    GetManifestResponse, Installer, PluginOrigin, PluginState, RecklessLogger, RecklessManifest,
    RecklessPlugin, parse_key_val,
};

const DEFAULT_REPO: &str = "https://github.com/lightningd/plugins";
const RECKLESS_CONFIG_HEADER: &str = "# This configuration file is managed by reckless to \
activate and disable\n# reckless-installed plugins\n\n";

pub async fn run_logged_command(
    mut command: Command,
    logger: &mut RecklessLogger<'_>,
) -> Result<String, anyhow::Error> {
    let mut cmd_str = format!(
        "`{} {}`",
        command
            .as_std()
            .get_program()
            .to_str()
            .ok_or_else(|| anyhow!("command program contains invalid utf-8"))?,
        command
            .as_std()
            .get_args()
            .map(|arg| arg
                .to_str()
                .ok_or_else(|| anyhow!("command argument contains invalid utf-8")))
            .collect::<Result<Vec<_>, anyhow::Error>>()?
            .join(" "),
    );
    if let Some(cwd) = command.as_std().get_current_dir() {
        cmd_str = format!("{} (cwd: {})", cmd_str, cwd.display());
    }
    logger
        .log(&format!("running command: {cmd_str}"), LogLevel::INFO)
        .await?;

    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command.spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture stdout"))?;

    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture stderr"))?;

    let mut stdout_lines = BufReader::new(stdout).lines();
    let mut stderr_lines = BufReader::new(stderr).lines();

    let mut stdout_done = false;
    let mut stderr_done = false;

    let mut stdout_buf = String::new();
    let mut stderr_last = String::new();

    loop {
        if stdout_done && stderr_done {
            break;
        }

        tokio::select! {
            line = stdout_lines.next_line(), if !stdout_done => {
                match line? {
                    Some(line) => {
                        logger.log(&line, LogLevel::INFO).await?;
                        stdout_buf.push_str(&line);
                        stdout_buf.push('\n');
                    }
                    None => {
                        stdout_done = true;
                    }
                }
            }

            line = stderr_lines.next_line(), if !stderr_done => {
                match line? {
                    Some(line) => {
                        logger.log(&line, LogLevel::UNUSUAL).await?;
                        stderr_last = line;
                    }
                    None => {
                        stderr_done = true;
                    }
                }
            }
        }
    }

    let status = child.wait().await?;

    if !status.success() {
        return Err(anyhow!("command {cmd_str} failed: {stderr_last}"));
    }

    Ok(stdout_buf.trim().to_owned())
}

pub async fn get_plugin_manifest(
    entrypoint: &PathBuf,
    logger: &mut RecklessLogger<'_>,
) -> Result<GetManifestResponse, anyhow::Error> {
    let line = format!("getmanifest: {}", entrypoint.display());
    logger.log(&line, LogLevel::DEBUG).await?;

    let mut child = Command::new(entrypoint)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let line = format!("spawned: {}", entrypoint.display());
    logger.log(&line, LogLevel::DEBUG).await?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("could not take stdin handle"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("could not take stdout handle"))?;

    logger.log("took stdin/stdout", LogLevel::DEBUG).await?;

    let mut reader = FramedRead::new(stdout, MultiLineCodec::default());

    // CLN plugin handshake: simulate lightningd sending getmanifest
    let getmanifest = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "reckless-1",
        "method": "getmanifest",
        "params": {}
    });

    stdin.write_all(getmanifest.to_string().as_bytes()).await?;
    stdin.write_all(b"\n\n").await?;
    stdin.flush().await?;

    logger.log("requested manifest", LogLevel::DEBUG).await?;

    let result = timeout(Duration::from_secs(10), async {
        let mut message_count = 0;

        loop {
            let message = reader
                .next()
                .await
                .ok_or_else(|| anyhow!("plugin exited before sending getmanifest response"))??;

            message_count += 1;

            if message_count > 100 {
                return Err(anyhow!("plugin send alot, but no manifest found"));
            }

            let line = format!("got message: `{message}`");
            logger.log(&line, LogLevel::TRACE).await?;

            let mut json = match serde_json::from_str::<serde_json::Value>(&message) {
                Ok(v) => v,
                Err(e) => {
                    logger.log(&e.to_string(), LogLevel::TRACE).await?;
                    continue;
                }
            };

            let line = format!("got json: {json:#?}");
            logger.log(&line, LogLevel::TRACE).await?;

            if json.get("id") == Some(&serde_json::Value::String("reckless-1".into())) {
                let result = json
                    .get_mut("result")
                    .ok_or_else(|| anyhow!("invalid getmanifest response, no `result`"))?
                    .take();

                return Ok(result);
            }
        }
    })
    .await
    .map_err(|_| anyhow!("timed out reading getmanifest response"))??;

    let parsed: GetManifestResponse = serde_json::from_value(result.clone())?;
    let line = format!("got manifest: {parsed:#?}");
    logger.log(&line, LogLevel::DEBUG).await?;

    drop(stdin);
    logger.log("dropped stdin", LogLevel::DEBUG).await?;

    let _ = child.start_kill();
    logger.log("child exited", LogLevel::DEBUG).await?;

    let _ = child.wait().await?;
    logger.log("waited for child", LogLevel::DEBUG).await?;

    Ok(parsed)
}

pub fn parse_options(
    manifest: &GetManifestResponse,
    options: &[(String, Option<String>)],
) -> Result<Vec<(String, Option<options::Value>)>, anyhow::Error> {
    let manifest_options: HashMap<_, _> = manifest
        .options
        .iter()
        .map(|opt| (&opt.name, opt))
        .collect();

    let mut seen = HashSet::new();

    let mut result = Vec::new();

    for (option_name, value_str) in options {
        let manifest_opt = manifest_options
            .get(option_name)
            .ok_or_else(|| anyhow!("option {option_name} not found in manifest"))?;

        if !manifest_opt.is_multi() && !seen.insert(option_name) {
            return Err(anyhow!("{option_name} is not a multi option"));
        }

        let value = match (&manifest_opt.value_type, value_str) {
            (cln_plugin::options::ValueType::String, Some(v)) => {
                Some(options::Value::String(v.clone()))
            }
            (cln_plugin::options::ValueType::Integer, Some(v)) => {
                Some(options::Value::Integer(i64::from_str(v)?))
            }
            (cln_plugin::options::ValueType::Boolean, Some(v)) => {
                Some(options::Value::Boolean(bool::from_str(v)?))
            }
            (cln_plugin::options::ValueType::Flag, None) => None,
            _ => {
                return Err(anyhow!(
                    "Invalid option value, expected {:#?} for {option_name}",
                    manifest_opt.value_type
                ));
            }
        };

        result.push((option_name.clone(), value));
    }

    Ok(result)
}

pub fn repo_path_from_url(url: &Url) -> Result<PathBuf, anyhow::Error> {
    let mut segments = url
        .path_segments()
        .ok_or_else(|| anyhow!("No paths in git URL"))?;
    let last = segments
        .next_back()
        .ok_or(anyhow!("Missing repo name in git URL"))?;

    let repo_name = last.trim_end_matches(".git");

    if repo_name.is_empty() {
        return Err(anyhow!("could not determine repo name"));
    }

    let repo_owner = segments
        .next_back()
        .ok_or(anyhow!("Missing repo owner in git URL"))?;

    for segment in segments {
        if segment == "tree" {
            return Err(anyhow!(
                "Please provide a URL with only the repo owner and name, not a tree reference. \
                You can specify a branch when installing a plugin."
            ));
        }
    }

    Ok(PathBuf::from(repo_owner).join(repo_name))
}

pub async fn init_plugin_repo(
    plugin: &Plugin<PluginState>,
    url: &Url,
    logger: &mut RecklessLogger<'_>,
) -> Result<PathBuf, anyhow::Error> {
    let repo_path = plugin.state().reckless_dir.join(repo_path_from_url(url)?);
    let line = format!("initializing repo `{url}` in: `{}`", repo_path.display());
    logger.log(&line, LogLevel::DEBUG).await?;

    if let Some(domain) = url.domain() {
        if domain == "github.com" {
            if let Some(github_redir) = &plugin.state().github_redir {
                return Ok(PathBuf::from_str(github_redir)?);
            }
        }
    }

    if repo_path.exists() {
        let mut command = Command::new("git");
        command
            .args(["remote", "set-head", "origin", "-a"])
            .current_dir(&repo_path);
        run_logged_command(command, logger).await?;

        let mut command = Command::new("git");
        command
            .args(["symbolic-ref", "refs/remotes/origin/HEAD", "--short"])
            .current_dir(&repo_path);
        let default_branch = run_logged_command(command, logger).await?;
        let default_branch = default_branch.trim_start_matches("origin/");

        let mut command = Command::new("git");
        command
            .args(["checkout", default_branch])
            .current_dir(&repo_path);
        run_logged_command(command, logger).await?;

        let mut command = Command::new("git");
        command.args(["pull", "--ff-only"]).current_dir(&repo_path);
        run_logged_command(command, logger).await?;
    } else {
        let repo_path_str = repo_path
            .to_str()
            .ok_or_else(|| anyhow!("path is invalid"))?;
        let mut command = Command::new("git");
        command.args(["clone", "--recursive", url.as_str(), repo_path_str]);
        run_logged_command(command, logger).await?;
    }

    let mut command = Command::new("git");
    command
        .args(["submodule", "sync", "--recursive"])
        .current_dir(&repo_path);
    run_logged_command(command, logger).await?;

    let mut command = Command::new("git");
    command
        .args(["submodule", "update", "--init", "--recursive"])
        .current_dir(&repo_path);
    run_logged_command(command, logger).await?;

    Ok(repo_path)
}

pub async fn find_plugin_locs(
    reckless_dir: &Path,
    origin: String,
    repo_dir: PathBuf,
    max_depth: usize,
    logger: &mut RecklessLogger<'_>,
) -> Result<HashMap<String, RecklessPlugin>, anyhow::Error> {
    let line = format!("trying to find plugins in: `{}`", repo_dir.display());
    logger.log(&line, LogLevel::DEBUG).await?;

    let mut plugin_locs = HashMap::new();

    let mut queue = VecDeque::new();
    queue.push_back((repo_dir.clone(), 0usize));

    while let Some((path, depth)) = queue.pop_front() {
        if depth > max_depth {
            continue;
        }

        if depth == 1 {
            if let Some(name) = path.file_name().and_then(|p| p.to_str()) {
                if name.contains("archive")
                    || name.eq(".git")
                    || name.eq(".venv")
                    || name.eq(".ci")
                    || name.eq(".github")
                {
                    continue;
                }
            }
        }

        let Some(name) = path.file_name().and_then(|p| p.to_str()) else {
            continue;
        };

        let rl_manifest = read_reckless_manifest(&path).await?;
        let mut rl_manifest = rl_manifest.unwrap_or_default();

        match detect_installer(&path, &mut rl_manifest).await {
            Ok(installer) => {
                let plugin_origin = PluginOrigin::new(&origin)?;
                plugin_locs.insert(
                    normalize_plugin_name(name),
                    RecklessPlugin::new(
                        plugin_origin,
                        path.clone(),
                        repo_dir.clone(),
                        name.to_owned(),
                        reckless_dir,
                        installer,
                        rl_manifest,
                    ),
                );

                continue;
            }
            Err(e) => {
                let line = format!("could not detect installer for {}: {e}", path.display());
                logger.log(&line, LogLevel::UNUSUAL).await?;
            }
        }

        if depth == max_depth {
            continue;
        }

        let Ok(mut entries) = fs::read_dir(&path).await else {
            continue;
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let Ok(file_type) = entry.file_type().await else {
                continue;
            };

            if file_type.is_symlink() {
                continue;
            }

            if !file_type.is_dir() {
                continue;
            }

            queue.push_back((entry.path(), depth + 1));
        }
    }

    Ok(plugin_locs)
}

async fn file_hash(path: &Path) -> Result<Vec<u8>, anyhow::Error> {
    let file = fs::File::open(path).await?;
    let mut reader = BufReader::new(file);

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        hasher.update(&buf[..n]);
    }

    Ok(hasher.finalize().to_vec())
}

async fn files_differ(src: &Path, dst: &Path) -> Result<bool, anyhow::Error> {
    let Ok(dst_meta) = fs::metadata(dst).await else {
        return Ok(true);
    };

    let src_meta = fs::metadata(src).await?;

    if src_meta.len() != dst_meta.len() {
        return Ok(true);
    }

    let src_hash = file_hash(src).await?;
    let dst_hash = file_hash(dst).await?;

    Ok(src_hash != dst_hash)
}

pub async fn copy_dir_all(
    src: &Path,
    dst: &Path,
    logger: &mut RecklessLogger<'_>,
) -> Result<(), anyhow::Error> {
    let line = format!("copying from: {} -> {}", src.display(), dst.display());
    logger.log(&line, LogLevel::DEBUG).await?;

    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];

    while let Some((src, dst)) = stack.pop() {
        fs::create_dir_all(&dst).await?;

        let line = format!("reading dir: {}", src.display());
        logger.log(&line, LogLevel::DEBUG).await?;

        let mut entries = fs::read_dir(&src).await?;

        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();

            let line = format!("processing: {}", name.to_string_lossy());
            logger.log(&line, LogLevel::DEBUG).await?;

            if name == ".venv" || name == ".git" {
                let line = format!("skipping {}", entry.path().display());
                logger.log(&line, LogLevel::DEBUG).await?;
                continue;
            }

            let src_path = entry.path();
            let dst_path = dst.join(&name);

            // IMPORTANT: do not follow symlinks here
            let meta = fs::symlink_metadata(&src_path).await?;
            let file_type = meta.file_type();

            if meta.file_type().is_symlink() {
                match fs::metadata(&src_path).await {
                    Ok(target_meta) => {
                        if target_meta.is_dir() {
                            stack.push((src_path, dst_path));
                        } else {
                            fs::copy(&src_path, &dst_path).await?;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        let line = format!("skipping broken symlink: {}", src_path.display());
                        logger.log(&line, LogLevel::UNUSUAL).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            } else if file_type.is_dir() {
                stack.push((src_path, dst_path));
            } else if file_type.is_file() && files_differ(&src_path, &dst_path).await? {
                let line = format!("copying file {}", src_path.display());
                logger.log(&line, LogLevel::DEBUG).await?;
                fs::copy(&src_path, &dst_path).await?;
            }
        }
    }

    let line = "copying: done";
    logger.log(line, LogLevel::DEBUG).await?;
    Ok(())
}

pub async fn write_metadata(rl_plugin: &RecklessPlugin) -> Result<(), anyhow::Error> {
    let install_dir = Path::new(rl_plugin.path());

    if !install_dir.is_dir() {
        return Err(anyhow!("{} is not a directory", install_dir.display()));
    }

    fs::write(
        install_dir.join(".metadata.json"),
        serde_json::to_string_pretty(rl_plugin)?,
    )
    .await?;

    Ok(())
}

pub async fn read_metadata(
    plugin_name: &str,
    plugin_dir: &Path,
) -> Result<RecklessPlugin, anyhow::Error> {
    if !plugin_dir.exists() {
        return Err(anyhow!("{plugin_name} is not installed"));
    }

    let metadata_file = plugin_dir.join(".metadata.json");

    let contents = fs::read_to_string(metadata_file).await?;

    let rl_plugin = serde_json::from_str(&contents)?;

    Ok(rl_plugin)
}

pub fn parse_target(target: &str) -> Result<(String, Option<String>), anyhow::Error> {
    let (name, git_ref) = if let Some(x) = target.split_once('@') {
        (normalize_plugin_name(x.0), Some(x.1.to_owned()))
    } else {
        (normalize_plugin_name(target), None)
    };
    if name.contains('/') {
        return Err(anyhow!("invalid plugin name"));
    }
    let name = if let Some((base, extension)) = name.split_once('.') {
        if extension.contains('.') {
            return Err(anyhow!("invalid plugin name, too many `.`"));
        }
        // We don't want file extensions in the name but we also had plugin names
        // like go-lnmetrics.reporter
        if extension.len() > 4 {
            name
        } else {
            base.to_owned()
        }
    } else {
        name
    };
    Ok((name, git_ref))
}

pub fn validate_path(input: &str) -> Result<PathBuf, anyhow::Error> {
    let path = PathBuf::from(input);

    if !path.exists() {
        return Err(anyhow!("path does not exist"));
    }

    path.canonicalize()
        .map_err(|e| anyhow!("invalid path: {e}"))?;

    Ok(path)
}

pub async fn parse_install_target(
    logger: &mut RecklessLogger<'_>,
    target: &str,
    search_results: &mut HashMap<String, RecklessPlugin>,
    reckless_dir: &Path,
) -> Result<(String, Option<String>), anyhow::Error> {
    let (name, git_ref) = match parse_target(target) {
        Ok(o) => o,
        Err(e1) => match validate_path(target.trim()) {
            Ok(local_path) => {
                let plugin_name = local_path
                    .file_name()
                    .ok_or_else(|| {
                        anyhow!("local_dir has no final component: {}", local_path.display())
                    })?
                    .to_str()
                    .ok_or_else(|| anyhow!("not a valid path: {}", local_path.display()))?
                    .to_owned();

                let rl_manifest = read_reckless_manifest(&local_path).await?;
                let mut rl_manifest = rl_manifest.unwrap_or_default();
                let installer = detect_installer(&local_path, &mut rl_manifest).await?;

                let plugin_origin = PluginOrigin::new(local_path.to_str().ok_or_else(|| {
                    anyhow!("path contains invalid utf-8: {}", local_path.display())
                })?)?;
                search_results.insert(
                    plugin_name.clone(),
                    RecklessPlugin::new(
                        plugin_origin,
                        local_path.clone(),
                        local_path,
                        plugin_name.clone(),
                        reckless_dir,
                        installer,
                        rl_manifest,
                    ),
                );
                (plugin_name, None)
            }
            Err(e2) => {
                logger.log(&e1.to_string(), LogLevel::BROKEN).await?;
                logger.log(&e2.to_string(), LogLevel::BROKEN).await?;
                return Err(anyhow!("neither a valid target or path"));
            }
        },
    };
    Ok((name, git_ref))
}

pub async fn read_sources_file(
    plugin: &Plugin<PluginState>,
) -> Result<(Vec<PluginOrigin>, PathBuf), anyhow::Error> {
    if !plugin.state().reckless_dir.exists() {
        fs::create_dir_all(&plugin.state().reckless_dir).await?;
    }

    let source_file = plugin.state().reckless_dir.join(".sources");

    if !source_file.exists() {
        fs::write(&source_file, format!("{DEFAULT_REPO}\n")).await?;
    }

    let contents = fs::read_to_string(&source_file).await?;
    let lines = contents.lines().collect::<Vec<&str>>();

    let mut sources: Vec<PluginOrigin> = Vec::new();

    for line in &lines {
        let origin = PluginOrigin::new(line)?;
        sources.push(origin);
    }

    Ok((sources, source_file))
}

async fn find_entryfile(path: &Path, plugin_name: &str) -> Result<PathBuf, anyhow::Error> {
    if !path.exists() {
        return Err(anyhow!("{} not found", path.display()));
    }

    let mut entries = fs::read_dir(&path).await?;

    let guesses = vec![format!("{plugin_name}.py"), format!("{plugin_name}.js")];

    let mut python_candidates = Vec::new();
    let mut js_candidates = Vec::new();

    while let Ok(Some(entry)) = entries.next_entry().await {
        let Ok(file_type) = entry.file_type().await else {
            continue;
        };
        if file_type.is_dir() {
            continue;
        }
        if let Some(file_name) = entry.file_name().to_str() {
            if normalized_eq(file_name, plugin_name) {
                return Ok(PathBuf::from_str(file_name)?);
            }

            for guess in &guesses {
                if normalized_eq(file_name, guess) {
                    return Ok(PathBuf::from_str(file_name)?);
                }
            }

            if file_name.starts_with("test") {
                continue;
            }

            let fn_path = Path::new(file_name);
            if fn_path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("py"))
            {
                python_candidates.push(file_name.to_owned());
            } else if fn_path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("js"))
            {
                js_candidates.push(file_name.to_owned());
            }
        }
    }

    if !python_candidates.is_empty() {
        for file in &python_candidates {
            let file_path = path.join(file);
            let content = fs::read_to_string(&file_path).await?;
            if content.contains("plugin.run()") {
                return Ok(PathBuf::from_str(file)?);
            }
        }
    }

    if js_candidates.len() == 1 {
        return Ok(PathBuf::from_str(js_candidates.first().unwrap())?);
    }

    if js_candidates.is_empty() && python_candidates.len() == 1 {
        return Ok(PathBuf::from_str(python_candidates.first().unwrap())?);
    }

    Err(anyhow!(
        "{plugin_name} entryfile not found in {}",
        path.display()
    ))
}

pub async fn detect_installer(
    plugin_path: &Path,
    rl_manifest: &mut RecklessManifest,
) -> Result<Installer, anyhow::Error> {
    let mut entries = fs::read_dir(plugin_path).await?;
    let mut files = Vec::new();

    while let Some(entry) = entries.next_entry().await? {
        if let Ok(name) = entry.file_name().into_string() {
            files.push(name);
        }
    }

    let has = |name: &str| files.iter().find(|f| normalized_eq(f, name));

    let plugin_name = plugin_path
        .file_name()
        .ok_or_else(|| anyhow!("no filename"))?
        .to_str()
        .ok_or_else(|| anyhow!("not a valid path"))?;

    if rl_manifest.install_cmd.as_ref().is_some() && rl_manifest.entrypoint.as_ref().is_some() {
        return Ok(Installer::Custom);
    }

    let entry_file = if let Some(et) = &rl_manifest.entrypoint {
        Some(et.clone())
    } else {
        find_entryfile(plugin_path, plugin_name).await.ok()
    };

    if let Some(ef) = &entry_file {
        rl_manifest.entrypoint = Some(ef.clone());
    }

    if has("Cargo.toml").is_some() {
        if entry_file.is_none() {
            rl_manifest.entrypoint = Some(PathBuf::from_str(plugin_name)?);
        }
        if which("cargo").is_ok() {
            return Ok(Installer::Rust);
        }
        return Err(anyhow!("rust plugin requires cargo"));
    }

    if has("go.mod").is_some() {
        if entry_file.is_none() {
            rl_manifest.entrypoint = Some(PathBuf::from_str(plugin_name)?);
        }
        if which("go").is_ok() {
            return Ok(Installer::Go);
        }
        return Err(anyhow!("go plugin requires go"));
    }

    if has("package.json").is_some() {
        if entry_file.is_none() {
            return Err(anyhow!("node plugin entrypoint not found"));
        }
        if which("npm").is_ok() {
            return Ok(Installer::Nodejs);
        }
        return Err(anyhow!("node plugin requires npm"));
    }

    let actual_python_entry =
        plugin_path.join(entry_file.ok_or_else(|| anyhow!("entryfile not found"))?);

    if !actual_python_entry.exists() {
        return Err(anyhow!("entry file not found"));
    }

    if !actual_python_entry
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("py"))
    {
        return Err(anyhow!("python entry file must end with .py"));
    }

    if has_uv_shebang(plugin_path.join(actual_python_entry)).await? {
        if which("uv").is_ok() {
            return Ok(Installer::PythonUvShebang);
        }
        return Err(anyhow!("python plugin uses uv shebang but uv not found"));
    }

    if has("uv.lock").is_some() {
        if which("uv").is_ok() {
            return Ok(Installer::PythonUv);
        }
        return Err(anyhow!("python plugin uses uv but uv not found"));
    }

    if has("poetry.lock").is_some() {
        if which("poetry").is_ok() {
            return Ok(Installer::PoetryVenv);
        }
        return Err(anyhow!("python plugin uses poetry but poetry not found"));
    }

    if has("pyproject.toml").is_some() {
        if which("pip").is_ok() {
            return Ok(Installer::PyprojectViaPip);
        }
        return Err(anyhow!("python pyproject.toml detected but no pip found"));
    }

    if has("requirements.txt").is_some() {
        if which("uv").is_ok() {
            return Ok(Installer::PythonUvLegacy);
        }
        if which("pip").is_ok() {
            return Ok(Installer::Python);
        }
        return Err(anyhow!("python requirements.txt detected but no pip found"));
    }

    Err(anyhow!(
        "plugin language could not be detected or is unsupported"
    ))
}

async fn has_uv_shebang(path: PathBuf) -> Result<bool, anyhow::Error> {
    let file = fs::File::open(path).await?;
    let mut reader = BufReader::new(file);

    let mut line = String::new();

    loop {
        line.clear();

        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            return Ok(false);
        }

        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        if !trimmed.starts_with("#!") {
            return Ok(false);
        }

        let shebang = &trimmed[2..];

        let has_uv = shebang.split_whitespace().any(|part| part == "uv");

        return Ok(has_uv);
    }
}

pub fn create_symlink(src: &Path, dst: &Path) -> std::io::Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(dst) {
        if meta.is_dir() {
            std::fs::remove_dir_all(dst)?;
        } else {
            std::fs::remove_file(dst)?;
        }
    }

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(src, dst)
    }

    #[cfg(windows)]
    {
        use std::fs as stdfs;
        use std::os::windows::fs;

        let metadata = stdfs::metadata(src);

        match metadata {
            Ok(m) if m.is_dir() => fs::symlink_dir(src, dst),
            _ => fs::symlink_file(src, dst),
        }
    }
}

pub fn normalize_plugin_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

pub fn normalized_eq(a: &str, b: &str) -> bool {
    a.replace('-', "_").eq(&b.replace('-', "_"))
}

fn normalized_line(line: &str) -> &str {
    line.trim_start_matches('#').trim_start()
}

pub async fn update_config_file(
    path: &Path,
    plugin_line: &str,
    removing: bool,
    option_lines: &mut Vec<(String, String)>,
    remove_options: &mut HashSet<String>,
    old_options: &mut Vec<(String, Option<String>)>,
) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }

    let contents = fs::read_to_string(path).await?;
    let mut lines: Vec<String> = contents.lines().map(str::to_owned).collect();

    let mut changed = false;
    let mut plugin_enabled = false;

    for line in &mut lines {
        let normalized_line = normalized_line(line);

        if normalized_line == plugin_line {
            if removing && !line.starts_with('#') {
                *line = format!("#{normalized_line}");
                changed = true;
            } else if !removing && line.starts_with('#') {
                plugin_line.clone_into(line);
                changed = true;
            }

            plugin_enabled = true;

            continue;
        }

        if let Some(pos) = option_lines
            .iter()
            .position(|(name, _)| normalized_line.starts_with(name))
        {
            let (name, expected) = option_lines[pos].clone();

            if *line != expected {
                *line = expected;
                changed = true;
            }

            // remove ONLY this occurrence (supports multi)
            option_lines.remove(pos);
            remove_options.insert(name);
            continue;
        }

        for name in remove_options.iter() {
            if line.starts_with(name) {
                *line = format!("#{line}");
                changed = true;
                old_options.push(parse_key_val(line).unwrap());
                break;
            }
        }
    }

    if changed {
        fs::write(path, format!("{}\n", lines.join("\n"))).await?;
    }

    Ok(plugin_enabled)
}

async fn read_reckless_manifest(source: &Path) -> Result<Option<RecklessManifest>, anyhow::Error> {
    let manifest_path = source.join("manifest.json");

    if manifest_path.exists() {
        let contents = fs::read_to_string(&manifest_path).await?;
        Ok(serde_json::from_str(&contents)?)
    } else {
        Ok(None)
    }
}

pub async fn cln_list_plugins(
    plugin: Plugin<PluginState>,
    logger: &mut RecklessLogger<'_>,
) -> Result<Vec<String>, anyhow::Error> {
    let mut rpc = plugin.state().rpc.lock().await;
    let plugins = rpc
        .call_typed(&PluginRequest {
            directory: None,
            plugin: None,
            options: None,
            subcommand: PluginSubcommand::LIST,
        })
        .await?;

    let mut plugin_names = Vec::new();

    for plugin in plugins
        .plugins
        .ok_or_else(|| anyhow!("empty plugin list response"))?
    {
        let Some(name) = Path::new(&plugin.name).file_name() else {
            let line = format!("plugin entry path has no filename: {}", plugin.name);
            logger.log(&line, LogLevel::UNUSUAL).await?;
            continue;
        };
        plugin_names.push(name.to_string_lossy().to_string());
    }

    Ok(plugin_names)
}

pub async fn cln_start_plugin(
    plugin: Plugin<PluginState>,
    plugin_name: &str,
    plugin_entry: &Path,
    options: Vec<(String, Option<String>)>,
    logger: &mut RecklessLogger<'_>,
) -> Result<(), anyhow::Error> {
    let options_str = options
        .iter()
        .map(|(k, v)| match v {
            Some(v) => format!("{k}={v}"),
            None => k.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let line = if options.is_empty() {
        format!("Starting {plugin_name}")
    } else {
        format!("Starting {plugin_name} with options: {options_str}")
    };
    logger.log(&line, LogLevel::INFO).await?;

    // Can not pass options with cln-rpc because of
    // <https://github.com/ElementsProject/lightning/issues/9171>
    // so we use .call_raw
    let mut obj = serde_json::Map::new();

    obj.insert(
        "subcommand".to_owned(),
        serde_json::Value::String("start".to_owned()),
    );
    obj.insert(
        "plugin".to_owned(),
        serde_json::Value::String(
            plugin_entry
                .to_str()
                .ok_or_else(|| anyhow!("plugin path invalid: {}", plugin_entry.display()))?
                .to_string(),
        ),
    );

    let options_val = options
        .iter()
        .map(|(k, v)| Ok((k.clone(), serde_json::to_value(v)?)))
        .collect::<Result<Vec<_>, serde_json::Error>>()?;

    obj.extend(options_val);

    let line = format!("{obj:#?}");
    logger.log(&line, LogLevel::TRACE).await?;

    let mut rpc = plugin.state().rpc.lock().await;
    match rpc
        // .call_typed(&PluginRequest {
        //     directory: None,
        //     plugin: Some(
        //         path.to_str()
        //             .ok_or_else(|| anyhow!("plugin path invalid: {}", path.display()))?
        //             .to_string(),
        //     ),
        //     options: Some(options),
        //     subcommand: PluginSubcommand::START,
        // })
        .call_raw::<PluginResponse, serde_json::Value>("plugin", &serde_json::Value::Object(obj))
        .await
    {
        Ok(_) => {
            let line = format!("{plugin_name} started");
            logger.log(&line, LogLevel::INFO).await?;
        }
        Err(e) => {
            return Err(anyhow!("{plugin_name} failed to start: {}", e.message));
        }
    }

    Ok(())
}

pub async fn cln_stop_plugin(
    plugin: Plugin<PluginState>,
    plugin_name: &str,
    plugin_entry: &Path,
    logger: &mut RecklessLogger<'_>,
) -> Result<(), anyhow::Error> {
    let mut rpc = plugin.state().rpc.lock().await;

    match rpc
        .call_typed(&PluginRequest {
            directory: None,
            plugin: Some(
                plugin_entry
                    .to_str()
                    .ok_or_else(|| anyhow!("plugin path invalid: {}", plugin_entry.display()))?
                    .to_string(),
            ),
            options: None,
            subcommand: PluginSubcommand::STOP,
        })
        .await
    {
        Ok(_) => {
            let line = format!("{plugin_name} stopped");
            logger.log(&line, LogLevel::INFO).await?;
        }
        Err(e) => {
            let line = format!("{plugin_name} NOT stopped: {e}");
            logger.log(&line, LogLevel::UNUSUAL).await?;
        }
    }

    Ok(())
}

pub async fn search_sources(
    plugin: &Plugin<PluginState>,
    search_name: Option<String>,
    logger: &mut RecklessLogger<'_>,
) -> Result<HashMap<String, RecklessPlugin>, anyhow::Error> {
    let (sources, _source_file) = read_sources_file(plugin).await?;
    let mut rl_plugins = HashMap::new();

    let mut urls: Vec<String> = Vec::new();
    let mut paths: Vec<PathBuf> = Vec::new();

    for source in sources {
        match source {
            PluginOrigin::Url(url) => urls.push(url),
            PluginOrigin::LocalPath(path) => paths.push(path),
        }
    }

    for url_str in &urls {
        let url = Url::from_str(url_str)?;
        let repo_dir = init_plugin_repo(plugin, &url, logger).await?;
        rl_plugins.extend(
            find_plugin_locs(
                &plugin.state().reckless_dir,
                url.as_str().to_owned(),
                repo_dir,
                5,
                logger,
            )
            .await?,
        );
    }

    for path in paths {
        rl_plugins.extend(
            find_plugin_locs(
                &plugin.state().reckless_dir,
                path.to_str().unwrap().to_owned(),
                path,
                3,
                logger,
            )
            .await?,
        );
    }

    let mut exact_matches = HashMap::new();

    let mut found_match = false;
    for (plugin_name, rl_plugin) in &rl_plugins {
        if search_name
            .as_ref()
            .is_some_and(|search| plugin_name.contains(search))
        {
            if !found_match {
                let line = format!("Plugins matching '{}':", search_name.as_ref().unwrap());
                logger.log(&line, LogLevel::INFO).await?;
            }
            let line = format!("  {plugin_name} ({})", rl_plugin.origin());
            logger.log(&line, LogLevel::INFO).await?;
            found_match = true;
        }
    }

    for (plugin_name, rl_plugin) in rl_plugins {
        if search_name
            .as_ref()
            .is_none_or(|search| normalized_eq(&plugin_name, search))
        {
            let line = format!("found {plugin_name} in source: {}", rl_plugin.origin());
            logger.log(&line, LogLevel::INFO).await?;

            exact_matches.insert(plugin_name, rl_plugin);
            found_match = true;
        }
    }

    if !found_match {
        let line = "Search exhausted all sources";
        logger.log(line, LogLevel::INFO).await?;
    }

    Ok(exact_matches)
}

pub async fn add_plugin_to_config(
    plugin: Plugin<PluginState>,
    path: PathBuf,
    options: Vec<(String, Option<options::Value>)>,
    manifest: GetManifestResponse,
) -> Result<(), anyhow::Error> {
    include_reckless_config(plugin.clone()).await?;

    let plugin_line = format!("plugin={}", path.display());

    let mut option_lines: Vec<(String, String)> = options
        .iter()
        .map(|(name, value)| {
            let value_str = match value {
                Some(v) => match v {
                    options::Value::String(s) => s.clone(),
                    options::Value::Integer(i) => i.to_string(),
                    options::Value::Boolean(b) => b.to_string(),
                    _ => panic!("Unsupported value type"),
                },
                None => name.clone(),
            };
            let line = format!("{name}={value_str}");
            Ok((name.clone(), line))
        })
        .collect::<anyhow::Result<_>>()?;

    let mut remove_options: HashSet<_> = manifest
        .options
        .into_iter()
        .map(|o| o.name)
        .filter(|name| !option_lines.iter().any(|(n, _)| n == name))
        .collect();

    let mut old_options: Vec<(String, Option<String>)> = Vec::new();

    let mut plugin_enabled = false;

    for config in plugin.state().get_cln_configs() {
        plugin_enabled |= update_config_file(
            config,
            &plugin_line,
            false,
            &mut option_lines,
            &mut remove_options,
            &mut old_options,
        )
        .await?;
    }

    if !plugin.state().reckless_conf.exists() {
        fs::write(&plugin.state().reckless_conf, RECKLESS_CONFIG_HEADER).await?;
    }

    plugin_enabled |= update_config_file(
        &plugin.state().reckless_conf,
        &plugin_line,
        false,
        &mut option_lines,
        &mut remove_options,
        &mut old_options,
    )
    .await?;

    let mut file = OpenOptions::new()
        .append(true)
        .open(&plugin.state().reckless_conf)
        .await?;

    if !plugin_enabled {
        file.write_all(format!("{plugin_line}\n").as_bytes())
            .await?;
    }

    for (_name, line) in option_lines {
        file.write_all(format!("{line}\n").as_bytes()).await?;
    }

    Ok(())
}

pub async fn remove_plugin_from_config(
    plugin: Plugin<PluginState>,
    plugin_entry: PathBuf,
    manifest: GetManifestResponse,
) -> Result<Vec<(String, Option<String>)>, anyhow::Error> {
    include_reckless_config(plugin.clone()).await?;

    let plugin_line = format!("plugin={}", plugin_entry.display());

    let mut option_lines: Vec<(String, String)> = Vec::new();

    let mut remove_options: HashSet<_> = manifest.options.into_iter().map(|o| o.name).collect();

    let mut old_options: Vec<(String, Option<String>)> = Vec::new();

    for config in &plugin.state().get_cln_configs() {
        update_config_file(
            config,
            &plugin_line,
            true,
            &mut option_lines,
            &mut remove_options,
            &mut old_options,
        )
        .await?;
    }

    if !plugin.state().reckless_conf.exists() {
        fs::write(&plugin.state().reckless_conf, RECKLESS_CONFIG_HEADER).await?;
    }

    update_config_file(
        &plugin.state().reckless_conf,
        &plugin_line,
        true,
        &mut option_lines,
        &mut remove_options,
        &mut old_options,
    )
    .await?;

    Ok(old_options)
}

async fn include_reckless_config(plugin: Plugin<PluginState>) -> Result<(), anyhow::Error> {
    let rl_conf_path_str = plugin
        .state()
        .reckless_conf
        .to_str()
        .ok_or_else(|| anyhow!("path to reckless config contains invalid utf-8"))?;

    if !plugin.state().cln_conf.exists() {
        fs::write(
            &plugin.state().cln_conf,
            format!("# This config was autopopulated by reckless\n\ninclude {rl_conf_path_str}\n"),
        )
        .await?;
        return Ok(());
    }

    let contents = fs::read_to_string(&plugin.state().cln_conf).await?;
    let lines = contents.lines().collect::<Vec<&str>>();

    let include_line = format!("include {rl_conf_path_str}");

    for line in lines {
        if line.trim() == include_line {
            return Ok(());
        }
    }

    let mut file_handle = OpenOptions::new()
        .append(true)
        .open(&plugin.state().cln_conf)
        .await?;

    file_handle
        .write_all(format!("\ninclude {rl_conf_path_str}\n").as_bytes())
        .await?;

    Ok(())
}
