use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
};

use anyhow::anyhow;
use cln_rpc::notifications::LogLevel;
use tokio::{fs, process::Command};

use crate::{
    structs::{RecklessLogger, RecklessPlugin},
    util::{create_symlink, run_logged_command},
};

pub async fn install_custom_plugin(
    rl_plugin: &RecklessPlugin,
    logger: &mut RecklessLogger<'_>,
) -> Result<PathBuf, anyhow::Error> {
    let line = "using installer custom";
    logger.log(line, LogLevel::INFO).await?;

    let entrypoint = Path::new(
        rl_plugin
            .manifest()
            .entrypoint
            .as_ref()
            .ok_or_else(|| anyhow!("custom installer requires entrypoint in manifest"))?,
    );
    let install_cmds = rl_plugin
        .manifest()
        .install_cmd
        .as_ref()
        .ok_or_else(|| anyhow!("custom installer requires install_cmd in manifest"))?;

    let line = format!(
        "running install commands for {}, this might take a while...",
        rl_plugin.name()
    );
    logger.log(&line, LogLevel::INFO).await?;

    for install_cmd in install_cmds {
        let cmd_parts = install_cmd.split_whitespace().collect::<Vec<_>>();

        if cmd_parts.is_empty() {
            return Err(anyhow!("install_cmd in manifest is empty!?"));
        }

        let mut cmd = Command::new(cmd_parts.first().unwrap());
        if cmd_parts.len() > 1 {
            cmd.args(&cmd_parts[1..]);
        }
        cmd.current_dir(rl_plugin.source_path());
        run_logged_command(cmd, logger).await?;
    }

    let entrypoint_path = rl_plugin.source_path().join(entrypoint);

    if !entrypoint_path.exists() {
        return Err(anyhow!("plugin entry not present after install_cmd"));
    }

    set_executable(&entrypoint_path).await?;

    let symlink_path = rl_plugin.get_entrypath()?;

    create_symlink(&entrypoint_path, &symlink_path)?;

    Ok(symlink_path)
}

pub async fn install_nodejs_plugin(
    rl_plugin: &RecklessPlugin,
    logger: &mut RecklessLogger<'_>,
) -> Result<PathBuf, anyhow::Error> {
    let line = "using installer nodejs";
    logger.log(line, LogLevel::INFO).await?;

    let line = "installing dependencies with `npm install`...";
    logger.log(line, LogLevel::INFO).await?;

    let mut npm_install = Command::new("npm");
    npm_install
        .arg("install")
        .current_dir(rl_plugin.source_path());
    run_logged_command(npm_install, logger).await?;

    let line = "dependencies installed successfully";
    logger.log(line, LogLevel::INFO).await?;

    let Some(plugin_entry) = &rl_plugin.manifest().entrypoint else {
        return Err(anyhow!("plugin entrypoint not found"));
    };

    let plugin_path = rl_plugin.source_path().join(plugin_entry);
    set_executable(&plugin_path).await?;

    let symlink_path = rl_plugin.get_entrypath()?;

    create_symlink(&plugin_path, &symlink_path)?;

    Ok(symlink_path)
}

pub async fn install_rust_plugin(
    rl_plugin: &RecklessPlugin,
    logger: &mut RecklessLogger<'_>,
    developer: bool,
) -> Result<PathBuf, anyhow::Error> {
    let line = "using installer rust_cargo";
    logger.log(line, LogLevel::INFO).await?;

    let line = "compiling with `cargo`, this might take a while...";
    logger.log(line, LogLevel::INFO).await?;

    let mut cargo_build = Command::new("cargo");
    cargo_build.arg("build");
    if !developer {
        cargo_build.arg("--release");
    }
    cargo_build.current_dir(rl_plugin.source_path());

    run_logged_command(cargo_build, logger).await?;

    let mut cargo_metadata = Command::new("cargo");
    cargo_metadata
        .arg("metadata")
        .arg("--no-deps")
        .arg("--format-version")
        .arg("1")
        .current_dir(rl_plugin.source_path());

    let metadata_str = run_logged_command(cargo_metadata, logger).await?;

    let metadata: serde_json::Value = serde_json::from_str(&metadata_str)?;

    let packages = if let Some(p) = metadata.get("packages").and_then(|t| t.as_array()) {
        p.clone()
    } else {
        Vec::new()
    };

    if packages.len() > 1 {
        return Err(anyhow!("Multiple packages found in Cargo.toml"));
    }

    let mut targets = packages
        .first()
        .and_then(|p| p.get("targets").and_then(|t| t.as_array().cloned()))
        .unwrap_or_default();

    targets.retain(|p| {
        if let Some(serde_json::Value::Array(arr)) = p.get("kind") {
            return arr == &["bin"];
        }
        false
    });

    if targets.len() > 1 {
        return Err(anyhow!("Multiple binaries found in Cargo.toml"));
    }

    if let Some(package_name) = targets
        .first()
        .and_then(|n| n.get("name").and_then(|n| n.as_str()))
    {
        let profile = if developer { "debug" } else { "release" };
        let binary = rl_plugin
            .source_path()
            .join("target")
            .join(profile)
            .join(package_name);
        if !binary.exists() {
            return Err(anyhow!(
                "Binary {package_name} not found in target/{profile}"
            ));
        }

        let destination = rl_plugin.get_entrypath()?;

        let line = format!("moving {} to {}", binary.display(), destination.display());
        logger.log(&line, LogLevel::DEBUG).await?;

        fs::copy(&binary, &destination).await?;

        if !developer {
            let mut cargo_clean = Command::new("cargo");
            cargo_clean.arg("clean");
            cargo_clean.current_dir(rl_plugin.source_path());
            run_logged_command(cargo_clean, logger).await?;
        }

        Ok(destination)
    } else {
        Err(anyhow!("No binary found in Cargo.toml"))
    }
}

pub async fn install_go_plugin(
    rl_plugin: &RecklessPlugin,
    logger: &mut RecklessLogger<'_>,
) -> Result<PathBuf, anyhow::Error> {
    let line = "using installer go";
    logger.log(line, LogLevel::INFO).await?;

    let main_packages = find_go_main_packages(rl_plugin.source_path().to_owned()).await?;
    if main_packages.len() > 1 {
        return Err(anyhow!(
            "Multiple main packages found, can't install: {main_packages:?}"
        ));
    }
    if main_packages.is_empty() {
        return Err(anyhow!("No main package found, can't install"));
    }

    let destination = rl_plugin.get_entrypath()?;
    let main_path = main_packages
        .first()
        .unwrap()
        .parent()
        .ok_or_else(|| anyhow!("main package has no parent directory"))?;

    let line = "compiling with `go`, this might take a moment...";
    logger.log(line, LogLevel::INFO).await?;

    let mut command = Command::new("go");
    command.arg("build");
    command.arg("-o");
    command.arg(&destination);
    command.arg(main_path);
    command.current_dir(rl_plugin.source_path());

    run_logged_command(command, logger).await?;

    if !destination.exists() {
        return Err(anyhow!("Binary {} not found", destination.display()));
    }

    Ok(destination)
}

const GO_SKIP_DIRS: &[&str] = &[
    "examples",
    "example",
    "testdata",
    "tests",
    "docs",
    "doc",
    ".git",
    ".github",
    ".vscode",
    ".idea",
    "vendor",
    "node_modules",
    "target",
    "dist",
    "build",
    "tmp",
    "bench",
    "benchmark",
    "benchmarks",
];

async fn find_go_main_packages(root: PathBuf) -> Result<Vec<PathBuf>, anyhow::Error> {
    let mut results: Vec<PathBuf> = Vec::new();

    let mut queue = VecDeque::new();
    queue.push_back((root.clone(), 0usize));

    while let Some((path, depth)) = queue.pop_front() {
        if depth > 256 {
            continue;
        }

        let Ok(mut read_dir) = fs::read_dir(&path).await else {
            continue;
        };

        while let Some(entry) = read_dir.next_entry().await? {
            let path = entry.path();
            let file_type = entry.file_type().await?;

            let Some(file_name) = path.file_name().and_then(|p| p.to_str()) else {
                continue;
            };

            if file_type.is_dir() {
                if !GO_SKIP_DIRS.contains(&file_name) {
                    queue.push_back((path, depth + 1));
                }
                continue;
            }

            if !file_type.is_file() {
                continue;
            }

            if path.extension().and_then(|e| e.to_str()) != Some("go") {
                continue;
            }

            let Ok(content) = fs::read_to_string(&path).await else {
                continue;
            };

            if !content.contains("package main") {
                continue;
            }

            if !content.contains("func main(") {
                continue;
            }

            results.push(path.clone());
        }
    }

    Ok(results)
}

pub async fn install_poetry_plugin(
    rl_plugin: &RecklessPlugin,
    logger: &mut RecklessLogger<'_>,
) -> Result<PathBuf, anyhow::Error> {
    let line = "using installer poetryvenv";
    logger.log(line, LogLevel::INFO).await?;

    let venv_dir = rl_plugin.source_path().join(".venv");
    create_venv(rl_plugin.source_path(), &venv_dir, logger).await?;

    let mut env: HashMap<String, String> = std::env::vars().collect();

    env.insert("VIRTUAL_ENV".into(), venv_dir.to_string_lossy().to_string());
    env.remove("POETRY_VIRTUAL_ENV");

    env.insert("LANG".to_string(), "C.UTF-8".to_string());
    env.insert("LC_ALL".to_string(), "C.UTF-8".to_string());
    env.insert("PYTHONUTF8".to_string(), "1".to_string());
    env.insert("PYTHONIOENCODING".to_string(), "utf-8".to_string());
    env.insert(
        "POETRY_VIRTUALENVS_PATH".into(),
        venv_dir.to_string_lossy().into_owned(),
    );

    let line = "installing dependencies with `poetry install`, this might take a moment...";
    logger.log(line, LogLevel::INFO).await?;

    let mut command = Command::new("poetry");
    command
        .arg("install")
        .arg("--no-root")
        .arg("--no-interaction")
        .current_dir(rl_plugin.source_path())
        .env_clear()
        .envs(&env);

    run_logged_command(command, logger).await?;

    let line = "dependencies installed successfully";
    logger.log(line, LogLevel::INFO).await?;

    let wrapper = rl_plugin.manifest().entry_filename()?;
    let wrapper_path = rl_plugin.get_entrypath()?;

    let wrapper = create_wrapper(rl_plugin, wrapper, &venv_dir).await?;
    fs::write(&wrapper_path, wrapper).await?;

    set_executable(&wrapper_path).await?;

    Ok(wrapper_path)
}

pub async fn install_uv_plugin(
    rl_plugin: &RecklessPlugin,
    logger: &mut RecklessLogger<'_>,
) -> Result<PathBuf, anyhow::Error> {
    let line = "using installer pythonuv";
    logger.log(line, LogLevel::INFO).await?;

    let mut command = Command::new("uv");
    command.arg("sync").current_dir(rl_plugin.source_path());
    run_logged_command(command, logger).await?;

    let line = "dependencies installed successfully";
    logger.log(line, LogLevel::INFO).await?;

    let wrapper = rl_plugin.manifest().entry_filename()?;
    let wrapper_path = rl_plugin.get_entrypath()?;
    let venv_dir = rl_plugin.source_path().join(".venv");

    let wrapper = create_wrapper(rl_plugin, wrapper, &venv_dir).await?;
    fs::write(&wrapper_path, wrapper).await?;

    set_executable(&wrapper_path).await?;

    Ok(wrapper_path)
}

pub async fn install_uv_shebang_plugin(
    rl_plugin: &RecklessPlugin,
    logger: &mut RecklessLogger<'_>,
) -> Result<PathBuf, anyhow::Error> {
    let line = "using installer pythonuvshebang";
    logger.log(line, LogLevel::INFO).await?;

    let entryfile = rl_plugin.manifest().entry_filename()?;

    let plugin_path = rl_plugin.source_path().join(entryfile);
    set_executable(&plugin_path).await?;

    let symlink_path = rl_plugin.get_entrypath()?;

    create_symlink(&plugin_path, &symlink_path)?;

    Ok(symlink_path)
}

pub async fn install_uv_legacy_plugin(
    rl_plugin: &RecklessPlugin,
    logger: &mut RecklessLogger<'_>,
) -> Result<PathBuf, anyhow::Error> {
    let line = "using installer pythonuvlegacy";
    logger.log(line, LogLevel::INFO).await?;

    let mut command = Command::new("uv");
    command
        .arg("venv")
        .arg("--clear")
        .current_dir(rl_plugin.source_path());

    run_logged_command(command, logger).await?;

    let python = python_bin(&rl_plugin.source_path().join(".venv"));

    let mut command = Command::new("uv");
    command
        .arg("pip")
        .arg("install")
        .arg("--python")
        .arg(python)
        .arg("-r")
        .arg("requirements.txt")
        .current_dir(rl_plugin.source_path());
    run_logged_command(command, logger).await?;

    let line = "dependencies installed successfully";
    logger.log(line, LogLevel::INFO).await?;

    let wrapper = rl_plugin.manifest().entry_filename()?;
    let wrapper_path = rl_plugin.get_entrypath()?;
    let venv_dir = rl_plugin.source_path().join(".venv");

    let wrapper = create_wrapper(rl_plugin, wrapper, &venv_dir).await?;
    fs::write(&wrapper_path, wrapper).await?;

    set_executable(&wrapper_path).await?;

    Ok(wrapper_path)
}

pub async fn install_python_plugin(
    rl_plugin: &RecklessPlugin,
    logger: &mut RecklessLogger<'_>,
) -> Result<PathBuf, anyhow::Error> {
    let line = "using installer PyprojectViaPip/Python";
    logger.log(line, LogLevel::INFO).await?;

    let venv_dir = rl_plugin.source_path().join(".venv");
    create_venv(rl_plugin.source_path(), &venv_dir, logger).await?;

    let pip = pip_bin(&venv_dir);

    let req_txt = rl_plugin.source_path().join("requirements.txt");
    let pyproject = rl_plugin.source_path().join("pyproject.toml");

    let line = "installing dependencies with `pip install`...";
    logger.log(line, LogLevel::INFO).await?;

    let mut command = Command::new(&pip);
    command.arg("install");

    if req_txt.exists() {
        command.arg("-r").arg(&req_txt);
    } else if pyproject.exists() {
        command.arg(".");
    } else {
        return Err(anyhow!("No requirements.txt or pyproject.toml found"));
    }

    command.current_dir(rl_plugin.source_path());
    run_logged_command(command, logger).await?;

    let line = "dependencies installed successfully";
    logger.log(line, LogLevel::INFO).await?;

    let wrapper = rl_plugin.manifest().entry_filename()?;
    let wrapper_path = rl_plugin.get_entrypath()?;

    let wrapper = create_wrapper(rl_plugin, wrapper, &venv_dir).await?;
    fs::write(&wrapper_path, wrapper).await?;

    set_executable(&wrapper_path).await?;

    Ok(wrapper_path)
}

async fn create_venv(
    source: &Path,
    venv_dir: &Path,
    logger: &mut RecklessLogger<'_>,
) -> Result<(), anyhow::Error> {
    let line = format!("creating venv at: {}", venv_dir.display());
    logger.log(&line, LogLevel::INFO).await?;

    let mut command = Command::new("python");
    command
        .arg("-m")
        .arg("venv")
        .arg(venv_dir)
        .current_dir(source);

    run_logged_command(command, logger).await?;

    Ok(())
}

fn python_bin(venv: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        venv.join("bin").join("python")
    }
    #[cfg(windows)]
    {
        venv.join("Scripts").join("python.exe")
    }
}

fn pip_bin(venv: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        venv.join("bin").join("pip")
    }
    #[cfg(windows)]
    {
        venv.join("Scripts").join("pip.exe")
    }
}

async fn create_wrapper(
    rl_plugin: &RecklessPlugin,
    entryfile: &Path,
    venv: &Path,
) -> Result<String, anyhow::Error> {
    let source_str = rl_plugin
        .source_path()
        .to_str()
        .ok_or_else(|| anyhow!("source path contains invalid utf-8"))?
        .to_owned();

    let venv = check_venv(venv).await?;

    let python = python_bin(&venv);

    let python = python.display().to_string();

    let path_str = rl_plugin
        .path()
        .to_str()
        .ok_or_else(|| anyhow!("path contains invalid utf-8"))?;

    let module_name = entryfile
        .file_stem()
        .ok_or_else(|| anyhow!("entryfile has no filename"))?
        .to_str()
        .ok_or_else(|| anyhow!("entryfile has invalid utf-8 characters"))?;

    let wrapper = format!(
        r#"#!{python}
import sys
import runpy

if '{source_str}' not in sys.path:
    sys.path.append('{source_str}')

if '{path_str}' in sys.path:
    sys.path.remove('{path_str}')

runpy.run_module("{module_name}", {{}}, "__main__")
"#
    );
    Ok(wrapper)
}

async fn check_venv(venv: &Path) -> Result<PathBuf, anyhow::Error> {
    if python_bin(venv).exists() {
        return Ok(venv.to_path_buf());
    }

    let mut venv_entries = fs::read_dir(venv).await?;

    while let Ok(Some(entry)) = venv_entries.next_entry().await {
        if entry.file_type().await?.is_file() {
            continue;
        }
        if python_bin(&entry.path()).exists() {
            return Ok(entry.path());
        }
    }

    Err(anyhow!("python not found in venv: {}", venv.display()))
}

#[cfg(unix)]
async fn set_executable(path: &Path) -> Result<(), anyhow::Error> {
    use std::os::unix::fs::PermissionsExt;

    let mut perm = fs::metadata(path).await?.permissions();
    perm.set_mode(0o755);
    fs::set_permissions(path, perm).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}
