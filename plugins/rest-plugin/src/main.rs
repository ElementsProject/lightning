use std::{
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::anyhow;
use axum::{
    http::{HeaderName, HeaderValue},
    middleware,
    routing::{any, get},
    Extension, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use certs::{do_certificates_exist, generate_certificates};
use cln_plugin::{Builder, Plugin, RpcMethodBuilder};
use handlers::{
    call_rpc_method, handle_notification, list_methods, socketio_on_connect,
    swagger_redirect_middleware,
};
use options::*;
use serde_json::json;
use socketioxide::{handler::ConnectHandler, SocketIo, SocketIoBuilder};
use tokio::{
    sync::mpsc::{self, Receiver},
    time,
};
use tower::ServiceBuilder;
use tower_http::set_header::SetResponseHeaderLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    handlers::auth_socket_io_middleware,
    shared::filter_json,
    structs::{ApiDoc, CheckRuneParams, ClnrestMap, ClnrestOptions, ClnrestProtocol, PluginState},
};

mod certs;
mod handlers;
mod options;
mod shared;
mod structs;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    log_panics::init();
    std::env::set_var(
        "CLN_PLUGIN_LOG",
        "cln_plugin=info,cln_rpc=info,clnrest=debug,warn",
    );

    let plugin = match Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(OPT_CLNREST_PORT)
        .option(OPT_CLNREST_CERTS)
        .option(OPT_CLNREST_PROTOCOL)
        .option(OPT_CLNREST_HOST)
        .option(OPT_CLNREST_CORS)
        .option(OPT_CLNREST_CSP)
        .option(OPT_CLNREST_SWAGGER)
        .rpcmethod_from_builder(
            RpcMethodBuilder::new("clnrest-register-path", register_path)
                .description("Register a dynamic REST path for clnrest")
                .usage("path rpc_method [rune]"),
        )
        .subscribe("*", handle_notification)
        .dynamic()
        .configure()
        .await?
    {
        Some(p) => p,
        None => return Ok(()),
    };

    let clnrest_options = match parse_options(&plugin) {
        Ok(opts) => opts,
        Err(e) => return plugin.disable(&e.to_string()).await,
    };

    let (notify_tx, notify_rx) = mpsc::channel(100);

    let state = PluginState {
        notification_sender: notify_tx,
        dyn_router: Arc::new(Mutex::new(matchit::Router::new())),
    };

    let plugin = plugin.start(state.clone()).await?;

    tokio::select! {
        _ = plugin.join() => {
        /* This will likely never be shown, if we got here our
         * parent process is exiting and not processing out log
         * messages anymore.
         */
            log::debug!("Plugin loop terminated")
        }
        e = run_rest_server(plugin.clone(), clnrest_options, notify_rx) => {
            log_error(format!("Error running rest interface: {:?}", e));
        }
    }
    Ok(())
}

async fn run_rest_server(
    plugin: Plugin<PluginState>,
    clnrest_options: ClnrestOptions,
    notify_rx: Receiver<serde_json::Value>,
) -> Result<(), anyhow::Error> {
    let (socket_layer, socket_io) = SocketIoBuilder::new()
        .with_state(plugin.clone())
        .build_layer();

    socket_io.ns("/", socketio_on_connect.with(auth_socket_io_middleware));

    tokio::spawn(notification_background_task(socket_io.clone(), notify_rx));

    let swagger_path = if clnrest_options.swagger.eq("/") {
        SWAGGER_FALLBACK.to_string()
    } else {
        clnrest_options.swagger.clone()
    };

    let swagger_router =
        Router::new().merge(SwaggerUi::new(swagger_path).url("/swagger.json", ApiDoc::openapi()));

    let root_router = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .layer(ServiceBuilder::new().layer(middleware::from_fn(swagger_redirect_middleware)))
        .layer(Extension(clnrest_options.swagger));

    let rpc_router = Router::new()
        .route("/v1/list-methods", get(list_methods))
        .route("/{*path}", any(call_rpc_method))
        .layer(clnrest_options.cors)
        .layer(Extension(plugin.clone()))
        .layer(
            ServiceBuilder::new().layer(SetResponseHeaderLayer::if_not_present(
                HeaderName::from_str("Content-Security-Policy")?,
                HeaderValue::from_str(&clnrest_options.csp)?,
            )),
        );

    let app = swagger_router
        .merge(root_router)
        .merge(rpc_router)
        .layer(socket_layer);

    match clnrest_options.protocol {
        ClnrestProtocol::Https => {
            let max_retries = 10;
            let mut retries = 0;
            while retries < max_retries && !do_certificates_exist(&clnrest_options.certs) {
                log::debug!("Certificates incomplete. Retrying...");
                time::sleep(Duration::from_millis(500)).await;
                retries += 1;
            }

            if !do_certificates_exist(&clnrest_options.certs) {
                log::debug!("Certificates still not existing after retries. Generating...");
                generate_certificates(&clnrest_options.certs, &plugin.option(&OPT_CLNREST_HOST)?)?;
                log::debug!("Certificates generated.");
            }

            let config = RustlsConfig::from_pem_file(
                clnrest_options.certs.join("server.pem"),
                clnrest_options.certs.join("server-key.pem"),
            )
            .await?;
            log::info!(
                "REST server running at https://{}",
                clnrest_options.address_str
            );

            axum_server::bind_rustls(clnrest_options.address, config)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .map_err(anyhow::Error::from)
        }
        ClnrestProtocol::Http => {
            log::info!(
                "REST server running at http://{}",
                clnrest_options.address_str
            );

            axum_server::bind(clnrest_options.address)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .map_err(anyhow::Error::from)
        }
    }
}

async fn register_path(
    plugin: Plugin<PluginState>,
    mut args: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    filter_json(&mut args);

    let (path_input, rpc_method, rune_params) = match args {
        serde_json::Value::Array(args_arr) => {
            let path_input = args_arr
                .first()
                .ok_or_else(|| anyhow!("path is required"))?
                .as_str()
                .ok_or_else(|| anyhow!("path must be a string"))?
                .to_owned();
            let rpc_method = args_arr
                .get(1)
                .ok_or_else(|| anyhow!("rpc_method is required"))?
                .as_str()
                .ok_or_else(|| anyhow!("rpc_method must be a string"))?
                .to_owned();
            let rune_val = args_arr.get(2);
            let rune_params: Option<CheckRuneParams> = if let Some(r) = rune_val {
                Some(serde_json::from_value(r.clone())?)
            } else {
                None
            };
            (path_input, rpc_method, rune_params)
        }
        serde_json::Value::Object(map) => {
            let path_input = map
                .get("path")
                .ok_or_else(|| anyhow!("path is required"))?
                .as_str()
                .ok_or_else(|| anyhow!("path must be a string"))?
                .to_owned();
            let rpc_method = map
                .get("rpc_method")
                .ok_or_else(|| anyhow!("rpc_method is required"))?
                .as_str()
                .ok_or_else(|| anyhow!("rpc_method must be a string"))?
                .to_owned();
            let rune_val = map.get("rune");
            let rune_params: Option<CheckRuneParams> = if let Some(r) = rune_val {
                Some(serde_json::from_value(r.clone())?)
            } else {
                None
            };
            (path_input, rpc_method, rune_params)
        }
        _ => return Err(anyhow!("Input arguments must be an array or object")),
    };

    let clnrest_map = ClnrestMap {
        rpc_method,
        rune: rune_params,
    };

    if path_input.eq("/") {
        return Err(anyhow!("Path must not be root"));
    }

    let path = path_input.trim_matches('/');

    if path.is_empty() {
        return Err(anyhow!("Path must not be empty"));
    }
    if path.contains("{*") {
        return Err(anyhow!("Wildcards not supported"));
    }

    let mut dyn_router = plugin.state().dyn_router.lock().unwrap();
    if dyn_router.at(path).is_ok() {
        return Err(anyhow!(
            "Path '{}' already exists or conflicts with an existing route",
            path
        ));
    }
    dyn_router.insert(path, clnrest_map)?;

    Ok(json!({}))
}

async fn notification_background_task(io: SocketIo, mut receiver: Receiver<serde_json::Value>) {
    log::debug!("Background task spawned");
    while let Some(notification) = receiver.recv().await {
        match io.emit("message", &notification).await {
            Ok(_) => (),
            Err(e) => log::info!("Could not emit notification from background task: {}", e),
        }
    }
}

fn log_error(error: String) {
    println!(
        "{}",
        serde_json::json!({"jsonrpc": "2.0",
                          "method": "log",
                          "params": {"level":"warn", "message":error}})
    );
}
