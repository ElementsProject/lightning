use std::{
    collections::{hash_map::Entry, HashMap},
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    http::{HeaderName, HeaderValue},
    middleware,
    routing::get,
    Extension, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use certs::{do_certificates_exist, generate_certificates};
use cln_plugin::{Builder, Plugin};
use handlers::{
    get_rpc_method, handle_notification, header_inspection_middleware, list_methods,
    post_rpc_method, socketio_on_connect,
};
use options::*;
use shared::get_clnrest_manifests;
use socketioxide::SocketIo;
use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    time,
};
use tower::ServiceBuilder;
use tower_http::set_header::SetResponseHeaderLayer;
use utoipa::{
    openapi::{
        security::{ApiKey, ApiKeyValue, SecurityScheme},
        Components,
    },
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

mod certs;
mod handlers;
mod options;
mod shared;

#[derive(Clone, Debug)]
struct PluginState {
    notification_sender: Sender<serde_json::Value>,
    rest_paths: Arc<Mutex<HashMap<String, ClnrestMap>>>,
}

#[derive(Debug, Clone)]
pub struct ClnrestMap {
    pub content_type: String,
    pub http_method: String,
    pub rpc_method: String,
    pub rune: bool,
}

#[derive(OpenApi)]
#[openapi(
        paths(
            handlers::list_methods,
            handlers::post_rpc_method,
            handlers::get_rpc_method
        ),
        modifiers(&SecurityAddon),
    )]
struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Components::new);
        components.add_security_scheme(
            "api_key",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("rune"))),
        );
        openapi.components = Some(components.clone())
    }
}

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
        .subscribe("*", handle_notification)
        .dynamic()
        .configure()
        .await?
    {
        Some(p) => p,
        None => return Ok(()),
    };

    let clnrest_options = match parse_options(&plugin).await {
        Ok(opts) => opts,
        Err(e) => return plugin.disable(&e.to_string()).await,
    };

    let (notify_tx, notify_rx) = mpsc::channel(100);

    let rest_paths = match rest_manifests_init(&plugin.configuration().rpc_file).await {
        Ok(rest) => rest,
        Err(e) => return plugin.disable(&e.to_string()).await,
    };

    let state = PluginState {
        notification_sender: notify_tx,
        rest_paths: Arc::new(Mutex::new(rest_paths)),
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
    let (socket_layer, socket_io) = SocketIo::new_layer();

    socket_io.ns("/", socketio_on_connect);

    tokio::spawn(notification_background_task(socket_io.clone(), notify_rx));

    let swagger_path = if clnrest_options.swagger.eq("/") {
        SWAGGER_FALLBACK.to_string()
    } else {
        clnrest_options.swagger.clone()
    };
    let swagger_router =
        Router::new().merge(SwaggerUi::new(swagger_path).url("/swagger.json", ApiDoc::openapi()));

    let rpc_router = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(
                    plugin.clone(),
                    header_inspection_middleware,
                ))
                .layer(socket_layer),
        )
        .layer(Extension(clnrest_options.swagger))
        .nest(
            "/v1",
            Router::new()
                .route("/list-methods", get(list_methods))
                .route("/{*route}", get(get_rpc_method).post(post_rpc_method))
                .layer(clnrest_options.cors)
                .layer(Extension(plugin.clone()))
                .layer(
                    ServiceBuilder::new().layer(SetResponseHeaderLayer::if_not_present(
                        HeaderName::from_str("Content-Security-Policy")?,
                        HeaderValue::from_str(&clnrest_options.csp)?,
                    )),
                ),
        );

    let app = swagger_router.merge(rpc_router);

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

async fn notification_background_task(io: SocketIo, mut receiver: Receiver<serde_json::Value>) {
    log::debug!("Background task spawned");
    while let Some(notification) = receiver.recv().await {
        match io.emit("message", &notification) {
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
async fn rest_manifests_init(
    rpc_file: &String,
) -> Result<HashMap<String, ClnrestMap>, anyhow::Error> {
    let manifests = get_clnrest_manifests(rpc_file).await?;
    let mut rest_paths: HashMap<String, ClnrestMap> = HashMap::new();
    for (rpc_method, clnrest_data) in manifests.into_iter() {
        if let Entry::Vacant(entry) = rest_paths.entry(clnrest_data.path.clone()) {
            log::info!(
                "Registered custom path `{}` for `{}` via `{}`",
                clnrest_data.path,
                rpc_method,
                clnrest_data.method
            );
            entry.insert(ClnrestMap {
                content_type: clnrest_data.content_type,
                http_method: clnrest_data.method,
                rpc_method,
                rune: clnrest_data.rune,
            });
        }
    }

    Ok(rest_paths)
}
