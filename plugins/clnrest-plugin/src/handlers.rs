use std::{collections::HashMap, process};

use anyhow::anyhow;
use axum::{
    body::{to_bytes, Body},
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
    shared::{call_rpc, filter_json, verify_rune},
    PluginState, SWAGGER_FALLBACK,
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
    match call_rpc(plugin, "help", json!(HelpRequest { command: None })).await {
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
        processed_html_res.push_str(&format!("Command: {}\n", row.command));
        processed_html_res.push_str(line);
    }

    processed_html_res
}

/* Handler for calling RPC methods */
#[utoipa::path(
    post,
    path = "/v1/{rpc_method}",
    responses(
        (status = 201, description = "Call rpc method", body = serde_json::Value),
        (status = 401, description = "Unauthorized", body = serde_json::Value),
        (status = 403, description = "Forbidden", body = serde_json::Value),
        (status = 404, description = "Not Found", body = serde_json::Value),
        (status = 500, description = "Server Error", body = serde_json::Value)
    ),
    request_body(content = serde_json::Value, content_type = "application/json",
     example = json!({}) ),
    security(("api_key" = []))
)]
pub async fn call_rpc_method(
    Path(rpc_method): Path<String>,
    headers: axum::http::HeaderMap,
    Extension(plugin): Extension<Plugin<PluginState>>,
    body: Request<Body>,
) -> Result<Response, AppError> {
    let rune = headers
        .get("rune")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let bytes = match to_bytes(body.into_body(), usize::MAX).await {
        Ok(o) => o,
        Err(e) => {
            return Err(AppError::InternalServerError(RpcError {
                code: None,
                data: None,
                message: format!("Could not read request body: {}", e),
            }))
        }
    };

    let mut rpc_params = match serde_json::from_slice(&bytes) {
        Ok(o) => o,
        Err(e1) => {
            /* it's not json but a form instead */
            let form_str = String::from_utf8(bytes.to_vec()).unwrap();
            let mut form_data = HashMap::new();
            for pair in form_str.split('&') {
                let mut kv = pair.split('=');
                if let (Some(key), Some(value)) = (kv.next(), kv.next()) {
                    form_data.insert(key.to_string(), value.to_string());
                }
            }
            match serde_json::to_value(form_data) {
                Ok(o) => o,
                Err(e2) => {
                    return Err(AppError::InternalServerError(RpcError {
                        code: None,
                        data: None,
                        message: format!(
                            "Could not parse json from form data: {}\
                        Original serde_json error: {}",
                            e2, e1
                        ),
                    }))
                }
            }
        }
    };

    filter_json(&mut rpc_params);

    verify_rune(plugin.clone(), rune, &rpc_method, &rpc_params).await?;

    match call_rpc(plugin, &rpc_method, rpc_params).await {
        Ok(result) => {
            let response_body = Json(result);
            let response = (StatusCode::CREATED, response_body).into_response();
            Ok(response)
        }
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
    if let Some(sht) = value.get("shutdown") {
        log::info!("Got shutdown notification: {}", sht);
        /* This seems to error when subscribing to "*" notifications */
        _ = plugin.shutdown();
        process::exit(0);
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
        match verify_rune(plugin, rune, "listclnrest-notifications", &json!({})).await {
            Ok(()) => Ok(next.run(req).await),
            Err(e) => Err(e),
        }
    } else if swagger_path.eq("/") {
        Ok(Redirect::permanent(SWAGGER_FALLBACK).into_response())
    } else {
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}
