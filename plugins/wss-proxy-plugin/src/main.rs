use std::{net::SocketAddr, process, sync::Arc};

use anyhow::anyhow;
use certs::get_tls_config;
use cln_plugin::{options::ConfigOption, Builder};

use futures_util::{SinkExt, StreamExt};
use options::{parse_options, WssproxyOptions, OPT_WSS_BIND_ADDR, OPT_WSS_CERTS_DIR};
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_tungstenite::{accept_async, WebSocketStream};

mod certs;
mod options;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    log_panics::init();
    std::env::set_var(
        "CLN_PLUGIN_LOG",
        "cln_plugin=info,cln_rpc=info,wss_proxy=debug,warn",
    );

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
    log::info!("Websocket Secure Server Started at {}", wss_address);

    loop {
        if let Ok((stream, _)) = listener.accept().await {
            let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config.clone()));
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(o) => o,
                Err(e) => {
                    log::debug!("Error upgrading to tls: {}", e);
                    continue;
                }
            };
            let wss_stream = match accept_async(tls_stream).await {
                Ok(o) => o,
                Err(e) => {
                    log::debug!("Error upgrading to websocket: {}", e);
                    continue;
                }
            };
            tokio::spawn(async move {
                match relay_messages(wss_stream, wss_proxy_options.ws_address).await {
                    Ok(_) => (),
                    Err(e) => log::info!("Error relaying messages: {}", e),
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
) -> Result<(), anyhow::Error> {
    let (ws_stream, _ws_response) =
        tokio_tungstenite::connect_async(format!("ws://{}", ws_address)).await?;
    let (mut wss_sender, mut wss_receiver) = wss_stream.split();
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    /* Relay from WSS to WS */
    tokio::spawn(async move {
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
    tokio::spawn(async move {
        while let Some(msg) = ws_receiver.next().await {
            if let Ok(msg) = msg {
                if let Err(e) = wss_sender.send(msg.clone()).await {
                    log::debug!("Error sending message to WSS client: {}", e);
                    break;
                }
            }
        }
    });
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
