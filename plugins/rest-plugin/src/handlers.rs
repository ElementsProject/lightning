use std::{collections::hash_map::Entry, process};

use anyhow::anyhow;
use axum::{
    body::Body,
    extract::{Extension, Json, Path, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
};
use cln_plugin::Plugin;
use cln_rpc::{
    model::{requests::HelpRequest, responses::HelpResponse},
    RpcError,
};
use serde_json::json;
use socketioxide::extract::{Data, SocketRef};

use crate::{
    shared::{
        call_rpc, filter_json, generate_response, get_clnrest_manifests, get_content_type,
        get_plugin_methods, handle_custom_paths, merge_params, parse_request_body, verify_rune,
    },
    ClnrestMap, PluginState, SWAGGER_FALLBACK,
};

#[derive(Debug)]
pub enum AppError {
    Unauthorized(RpcError),
    Forbidden(RpcError),
    NotFound(RpcError),
    InternalServerError(RpcError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Unauthorized(err) => (StatusCode::UNAUTHORIZED, err),
            AppError::Forbidden(err) => (StatusCode::FORBIDDEN, err),
            AppError::NotFound(err) => (StatusCode::NOT_FOUND, err),
            AppError::InternalServerError(err) => (StatusCode::INTERNAL_SERVER_ERROR, err),
        };

        let body = Json(json!(error_message));
        (status, body).into_response()
    }
}

/* Handler for list-methods */
#[utoipa::path(
    get,
    path = "/v1/list-methods",
    responses(
        (status = 200, description = "Success", body = String, content_type = "text/html"),
        (status = 500, description = "Server Error", body = serde_json::Value)
    )
)]
pub async fn list_methods(
    Extension(plugin): Extension<Plugin<PluginState>>,
) -> Result<Html<String>, AppError> {
    match call_rpc(
        &plugin.configuration().rpc_file,
        "help",
        Some(json!(HelpRequest { command: None })),
    )
    .await
    {
        Ok(help_response) => {
            let html_content = process_help_response(help_response);
            Ok(Html(html_content))
        }
        Err(err) => Err(AppError::InternalServerError(RpcError {
            code: None,
            data: None,
            message: format!("Error calling help rpc: {}", err),
        })),
    }
}

fn process_help_response(help_response: serde_json::Value) -> String {
    /* Parse the "help" field as an array of HelpCommand */
    let processed_res: HelpResponse = serde_json::from_value(help_response).unwrap();

    let line = "\n---------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n\n";
    let mut processed_html_res = String::new();

    for row in processed_res.help {
        processed_html_res.push_str(&format!("Command: {}<br>", row.command));
        if let Some(clnrest) = row.clnrest {
            processed_html_res.push_str(&format!("Clnrest path:: {}\n", clnrest.path));
            processed_html_res.push_str(&format!("Clnrest method: {}\n", clnrest.method));
            processed_html_res
                .push_str(&format!("Clnrest content-type: {}\n", clnrest.content_type));
            processed_html_res.push_str(&format!("Clnrest rune: {}\n", clnrest.rune));
        }
        processed_html_res.push_str(line);
    }

    processed_html_res
}

/* Handler for calling RPC methods */
#[utoipa::path(
    post,
    path = "/v1/{rpc_method_or_path}",
    responses(
        (status = 201, description = "Call rpc method by name or custom path", body = serde_json::Value),
        (status = 401, description = "Unauthorized", body = serde_json::Value),
        (status = 403, description = "Forbidden", body = serde_json::Value),
        (status = 404, description = "Not Found", body = serde_json::Value),
        (status = 500, description = "Server Error", body = serde_json::Value)
    ),
    request_body(content = serde_json::Value, content_type = "application/json",
     example = json!({}) ),
    security(("api_key" = []))
)]
pub async fn post_rpc_method(
    Path(path): Path<String>,
    headers: axum::http::HeaderMap,
    Extension(plugin): Extension<Plugin<PluginState>>,
    body: Request<Body>,
) -> Result<Response, AppError> {
    let (rpc_method, path_params, rest_map) = handle_custom_paths(&plugin, &path, "POST").await?;

    let mut rpc_params = parse_request_body(body).await?;

    filter_json(&mut rpc_params);

    merge_params(&mut rpc_params, path_params)?;

    if rest_map.as_ref().map_or_else(|| true, |map| map.rune) {
        let rune = headers
            .get("rune")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        verify_rune(
            &plugin.configuration().rpc_file,
            rune,
            &rpc_method,
            Some(rpc_params.clone()),
        )
        .await?;
    }

    let content_type = get_content_type(rest_map)?;

    match call_rpc(
        &plugin.configuration().rpc_file,
        &rpc_method,
        Some(rpc_params),
    )
    .await
    {
        Ok(result) => Ok(generate_response(result, content_type)),
        Err(err) => {
            if let Some(code) = err.code {
                if code == -32601 {
                    return Err(AppError::NotFound(err));
                }
            }
            Err(AppError::InternalServerError(err))
        }
    }
}

// Handler for calling RPC methods
#[utoipa::path(
    get,
    path = "/v1/{rpc_method_or_path}",
    responses(
        (status = 201, description = "Call rpc method by name or custom path", body = serde_json::Value),
        (status = 401, description = "Unauthorized", body = serde_json::Value),
        (status = 403, description = "Forbidden", body = serde_json::Value),
        (status = 404, description = "Not Found", body = serde_json::Value),
        (status = 500, description = "Server Error", body = serde_json::Value)
    ),
    security(("api_key" = []))
)]
pub async fn get_rpc_method(
    Path(path): Path<String>,
    headers: axum::http::HeaderMap,
    Extension(plugin): Extension<Plugin<PluginState>>,
) -> Result<Response, AppError> {
    let (rpc_method, path_params, rest_map) = handle_custom_paths(&plugin, &path, "GET").await?;

    if rest_map.as_ref().map_or_else(|| true, |map| map.rune) {
        let rune = headers
            .get("rune")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        verify_rune(
            &plugin.configuration().rpc_file,
            rune,
            &rpc_method,
            path_params.clone(),
        )
        .await?;
    }

    let content_type = get_content_type(rest_map)?;

    match call_rpc(&plugin.configuration().rpc_file, &rpc_method, path_params).await {
        Ok(result) => Ok(generate_response(result, content_type)),
        Err(err) => {
            if let Some(code) = err.code {
                if code == -32601 {
                    return Err(AppError::NotFound(err));
                }
            }
            Err(AppError::InternalServerError(err))
        }
    }
}

pub fn socketio_on_connect(socket: SocketRef, Data(_data): Data<serde_json::Value>) {
    log::info!("Socket.IO connected: {} {}", socket.ns(), socket.id);
}

pub async fn handle_notification(
    plugin: Plugin<PluginState>,
    value: serde_json::Value,
) -> Result<(), anyhow::Error> {
    log::debug!("notification: {}", value.to_string());
    if let Some(sht) = value.get("shutdown") {
        log::info!("Got shutdown notification: {}", sht);
        /* This seems to error when subscribing to "*" notifications */
        _ = plugin.shutdown();
        process::exit(0);
    } else if let Some(p_started) = value.get("plugin_started") {
        let rpc_methods = get_plugin_methods(p_started);

        let manifests = get_clnrest_manifests(&plugin.configuration().rpc_file).await?;
        let mut rest_paths = plugin.state().rest_paths.lock().unwrap();
        for rpc_method in rpc_methods.into_iter() {
            let clnrest_data = match manifests.get(&rpc_method) {
                Some(c) => c.clone(),
                None => continue,
            };
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
    } else if let Some(p_stopped) = value.get("plugin_stopped") {
        let rpc_methods = get_plugin_methods(p_stopped);

        let mut rest_paths = plugin.state().rest_paths.lock().unwrap();
        rest_paths.retain(|_, v| !rpc_methods.contains(&v.rpc_method))
    }
    match plugin.state().notification_sender.send(value).await {
        Ok(()) => Ok(()),
        Err(e) => Err(anyhow!("Error sending notification: {}", e)),
    }
}

pub async fn header_inspection_middleware(
    State(plugin): State<Plugin<PluginState>>,
    Extension(swagger_path): Extension<String>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let root_path = req.uri().path();
    if !root_path.eq("/") && !root_path.eq("/socket.io/") {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let rune = req
        .headers()
        .get("rune")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let upgrade = req
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if upgrade.is_some() {
        match verify_rune(
            &plugin.configuration().rpc_file,
            rune,
            "listclnrest-notifications",
            None,
        )
        .await
        {
            Ok(()) => Ok(next.run(req).await),
            Err(e) => Err(e),
        }
    } else if swagger_path.eq("/") {
        Ok(Redirect::permanent(SWAGGER_FALLBACK).into_response())
    } else {
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}
