use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes};
use cln_plugin::{options, Builder, Plugin};
use cln_rpc::model::responses::CheckruneResponse;
use cln_rpc::notifications::Notification;
use cln_rpc::ClnRpc;
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperBuilder;
use log::{debug, error, warn};
use rustls::ServerConfig;
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;

mod tls;

#[derive(Clone, Debug)]
struct PluginState {
    rpc_path: PathBuf,
    identity: tls::Identity,
    events: broadcast::Sender<cln_rpc::notifications::Notification>,
}

const OPTION_REST_PORT: options::IntegerConfigOption = options::ConfigOption::new_i64_no_default(
    "clnrest-port",
    "Which port should the rest plugin listen for incoming connections?",
);

const OPTION_REST_MSG_BUFFER_SIZE : options::DefaultIntegerConfigOption = options::ConfigOption::new_i64_with_default(
    "clnrest-msg-buffer-size",
    1024,
    "Number of notifications which can be stored in the rest message buffer. Notifications can be skipped if this buffer is full");

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    debug!("Starting rest plugin");

    let directory = std::env::current_dir()?;

    let plugin = match Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(OPTION_REST_PORT)
        .option(OPTION_REST_MSG_BUFFER_SIZE)
        // TODO: Use the catch-all subscribe method
        // However, doing this breaks the plugin at the time begin
        // We should fix this
        // .subscribe("*", handle_notification)
        .subscribe("block_added", handle_notification)
        .subscribe("channel_open_failed", handle_notification)
        .subscribe("channel_opened", handle_notification)
        .subscribe("channel_state_changed", handle_notification)
        .subscribe("connect", handle_notification)
        .subscribe("custommsg", handle_notification)
        .configure()
        .await?
    {
        Some(p) => p,
        None => return Ok(()),
    };

    let bind_port = match plugin.option(&OPTION_REST_PORT)? {
        Some(port) => port,
        None => {
            log::info!("'rest-port' options i not configured. exiting.");
            plugin.disable("Missing 'rest-port' option").await?;
            return Ok(());
        }
    };

    let buffer_size: i64 = plugin.option(&OPTION_REST_MSG_BUFFER_SIZE)?;
    let buffer_size = match usize::try_from(buffer_size) {
        Ok(b) => b,
        Err(_) => {
            plugin
                .disable("'rest-msg-buffer-size' should be strictly positive")
                .await?;
            return Ok(());
        }
    };

    let (sender, _) = broadcast::channel(buffer_size);

    let (identity, _ca_cert) = tls::init(&directory)?;

    let state = PluginState {
        rpc_path: PathBuf::from(plugin.configuration().rpc_file.as_str()),
        identity,
        events: sender,
    };

    let plugin = plugin.start(state.clone()).await?;
    let state = Arc::new(state);

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", bind_port).parse()?;

    tokio::select! {
        _ = plugin.join() => {
        // This will likely never be shown, if we got here our
        // parent process is exiting and not processing out log
        // messages anymore.
            debug!("Plugin loop terminated")
        }
        e = run_interface(bind_addr, state) => {
            warn!("Error running REST interface: {:?}", e)
        }
    }
    Ok(())
}

async fn run_interface(bind_addr: SocketAddr, state: Arc<PluginState>) -> Result<()> {
    debug!(
        "Connecting to {:?} and serving REST on {:?}",
        &state.rpc_path, &bind_addr
    );
    let cert = rustls_pemfile::certs(&mut state.identity.certificate.reader())
        .last()
        .ok_or_else(|| anyhow!("Missing certificate"))??;
    let key = rustls_pemfile::private_key(&mut state.identity.key.reader())?
        .ok_or_else(|| anyhow!("Missing key"))?;
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind(bind_addr).await?;
    loop {
        let (tcp_stream, _) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let rpc_path = state.rpc_path.clone();
        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => tls_stream,
                Err(err) => {
                    debug!("Failed to perform tls handshake: {err:#}");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let svc =
                hyper::service::service_fn(move |req| handle_request(req, rpc_path.to_path_buf()));
            if let Err(err) = HyperBuilder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await
            {
                error!("REST server error: {}", err);
            }
        });
    }
}

async fn handle_request(
    request: Request<impl Body>,
    rpc_path: PathBuf,
) -> Result<Response<Full<Bytes>>> {
    let rune = match request.headers().get("rune") {
        Some(rune) => match rune.to_str() {
            Ok(rune) => rune.to_string(),
            Err(_) => {
                return respond(
                    StatusCode::UNAUTHORIZED,
                    "Rune should only contain ASCII chars",
                )
            }
        },
        None => return respond(StatusCode::UNAUTHORIZED, "Missing rune"),
    };

    let method = request
        .uri()
        .path()
        .to_string()
        .trim_start_matches("/v1/")
        .to_string();

    let json_body: serde_json::Value = if request.size_hint().lower() > 0 {
        let whole_body = match request.collect().await {
            Ok(parts) => parts.aggregate(),
            Err(_) => return respond(StatusCode::BAD_REQUEST, "Bad Request"),
        };
        match serde_json::from_reader(whole_body.reader()) {
            Ok(value) => value,
            Err(_) => return respond(StatusCode::BAD_REQUEST, "Invalid JSON body"),
        }
    } else {
        json!({})
    };
    let request = json!({
        "method": method,
        "params": json_body.clone(),
        "rune": rune,
    });

    let mut rpc_client = match ClnRpc::new(rpc_path).await {
        Ok(client) => client,
        Err(e) => {
            error!("REST server could not connect to rpc socket: {}", e);
            return respond(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error");
        }
    };
    match rpc_client
        .call_raw::<CheckruneResponse, serde_json::Value>("checkrune", &request)
        .await
    {
        Ok(check_rune) => {
            if !check_rune.valid {
                return respond(StatusCode::UNAUTHORIZED, "Unauthorized rune");
            }
        }
        Err(e) => {
            error!("REST server received error from rpc socket: {}", e);
            return respond(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error");
        }
    };
    let bytes = match rpc_client.call_raw(&method, &json_body).await {
        Ok(result) => match serde_json::to_vec::<serde_json::Value>(&result) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(
                    "REST server received invalid response from rpc socket: {}",
                    e
                );
                return respond(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error");
            }
        },
        Err(e) => {
            error!("REST server received error from rpc socket: {}", e);
            return respond(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error");
        }
    };
    Ok(Response::new(Full::<Bytes>::from(bytes)))
}

fn respond(code: StatusCode, body: &'static str) -> Result<Response<Full<Bytes>>> {
    match Response::builder()
        .status(code)
        .body(Full::<Bytes>::from(body))
    {
        Ok(r) => Ok(r),
        Err(_) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::<Bytes>::default())?),
    }
}

async fn handle_notification(plugin: Plugin<PluginState>, value: serde_json::Value) -> Result<()> {
    let notification: Result<Notification, _> = serde_json::from_value(value);
    match notification {
        Err(err) => {
            debug!("Failed to parse notification from lightningd {:?}", err);
        }
        Ok(notification) => {
            if let Err(e) = plugin.state().events.send(notification) {
                warn!("Failed to broadcast notification {:?}", e)
            }
        }
    };
    Ok(())
}
