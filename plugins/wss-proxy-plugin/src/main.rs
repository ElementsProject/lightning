use std::{net::SocketAddr, process, sync::Arc, time::Duration};

use anyhow::anyhow;
use certs::get_tls_config;
use cln_plugin::{Builder, options::ConfigOption};

use futures_util::{SinkExt, StreamExt};
use options::{OPT_WSS_BIND_ADDR, OPT_WSS_CERTS_DIR, WssproxyOptions, parse_options};
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_tungstenite::{
    WebSocketStream, accept_async_with_config, tungstenite::protocol::WebSocketConfig,
};

mod certs;
mod options;

const MAX_WS_MESSAGE_SIZE: usize = 65569;

const MAX_CONNECTIONS: usize = 1024;

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
        .max_frame_size(Some(MAX_WS_MESSAGE_SIZE))
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    unsafe {
        // SAFETY:
        // `std::env::set_var` is unsafe in Rust 2024 because environment variables
        // are process-global and unsynchronized. Concurrent reads/writes from
        // multiple threads can cause undefined behavior.
        //
        // This call happens at process startup, before any threads are spawned and
        // before any code that may read environment variables is executed.
        // Therefore, no concurrent access is possible.
        std::env::set_var(
            "CLN_PLUGIN_LOG",
            "cln_plugin=info,cln_rpc=info,wss_proxy=debug,warn",
        )
    };

    log_panics::init();

    let opt_wss_proxy_bind_addr = ConfigOption::new_str_arr_no_default(
        OPT_WSS_BIND_ADDR,
        "WSS proxy address to connect with WS",
    );

    let default_certs_dir = std::env::current_dir()?;
    let default_certs_dir_str = default_certs_dir
        .to_str()
        .ok_or_else(|| anyhow!("Invalid working directory: {:?}", default_certs_dir))?;

    let opt_wss_proxy_certs = ConfigOption::new_str_with_default(
        OPT_WSS_CERTS_DIR,
        default_certs_dir_str,
        "Certificate location for WSS proxy",
    );

    let conf_plugin = match Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(opt_wss_proxy_bind_addr)
        .option(opt_wss_proxy_certs)
        .dynamic()
        .configure()
        .await?
    {
        Some(p) => p,
        None => return Ok(()),
    };

    let wss_proxy_options = match parse_options(&conf_plugin).await {
        Ok(opts) => opts,
        Err(e) => return conf_plugin.disable(&e.to_string()).await,
    };

    let plugin = conf_plugin.start(()).await?;

    let tls_config = match get_tls_config(&wss_proxy_options).await {
        Ok(tls) => tls,
        Err(err) => {
            log_error(err.to_string());
            process::exit(1)
        }
    };

    for wss_address in wss_proxy_options.wss_addresses.clone().into_iter() {
        let options_clone = wss_proxy_options.clone();
        let tls_clone = tls_config.clone();
        tokio::spawn(async move {
            match start_proxy(options_clone, wss_address, tls_clone).await {
                Ok(_) => (),
                Err(err) => {
                    log_error(err.to_string());
                    process::exit(1)
                }
            }
        });
    }

    plugin.join().await
}

async fn start_proxy(
    wss_proxy_options: WssproxyOptions,
    wss_address: SocketAddr,
    tls_config: ServerConfig,
) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(wss_address).await?;
    let connection_slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    log::info!("Websocket Secure Server Started at {wss_address}");

    let handshake_timeout = Duration::from_secs(10);

    loop {
        let permit = connection_slots.clone().acquire_owned().await?;
        if let Ok((stream, _)) = listener.accept().await {
            let tls_config_clone = tls_config.clone();
            let ws_address = wss_proxy_options.ws_address;
            tokio::spawn(async move {
                let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config_clone));
                let tls_stream = match tokio::time::timeout(
                    handshake_timeout,
                    tls_acceptor.accept(stream),
                )
                .await
                {
                    Ok(Ok(o)) => o,
                    Ok(Err(e)) => {
                        log::debug!("Error upgrading to tls: {e}");
                        return;
                    }
                    Err(_) => {
                        log::debug!("Timed out upgrading to tls");
                        return;
                    }
                };
                let wss_stream = match tokio::time::timeout(
                    handshake_timeout,
                    accept_async_with_config(tls_stream, Some(ws_config())),
                )
                .await
                {
                    Ok(Ok(o)) => o,
                    Ok(Err(e)) => {
                        log::debug!("Error upgrading to websocket: {e}");
                        return;
                    }
                    Err(_) => {
                        log::debug!("Timed out upgrading to websocket");
                        return;
                    }
                };
                if let Err(e) = relay_messages(wss_stream, ws_address, permit).await {
                    log::info!("Error relaying messages: {e}");
                }
            });
        } else {
            return Err(anyhow!("TCP Listener closed!"));
        }
    }
}

async fn relay_messages(
    wss_stream: WebSocketStream<TlsStream<TcpStream>>,
    ws_address: SocketAddr,
    _permit: OwnedSemaphorePermit,
) -> Result<(), anyhow::Error> {
    let (ws_stream, _ws_response) = tokio_tungstenite::connect_async_with_config(
        format!("ws://{}", ws_address),
        Some(ws_config()),
        false,
    )
    .await?;
    let (mut wss_sender, mut wss_receiver) = wss_stream.split();
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    /* Relay from WSS to WS */
    let mut relays = tokio::task::JoinSet::new();
    relays.spawn(async move {
        while let Some(writer) = wss_receiver.next().await {
            if let Ok(msg) = writer {
                if let Err(e) = ws_sender.send(msg.clone()).await {
                    log::debug!("Error sending message to WS server: {}", e);
                    break;
                }
            }
        }
    });

    /* Relay from WS to WSS */
    relays.spawn(async move {
        while let Some(msg) = ws_receiver.next().await {
            if let Ok(msg) = msg {
                if let Err(e) = wss_sender.send(msg.clone()).await {
                    log::debug!("Error sending message to WSS client: {}", e);
                    break;
                }
            }
        }
    });

    let _ = relays.join_next().await;
    Ok(())
}

/* Workaround: Using log crate right before plugin exit will not print */
fn log_error(error: String) {
    println!(
        "{}",
        serde_json::json!({"jsonrpc": "2.0",
                          "method": "log",
                          "params": {"level":"info", "message":error}})
    );
}
