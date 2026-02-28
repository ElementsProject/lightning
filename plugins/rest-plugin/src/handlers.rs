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
    NotAcceptable(RpcError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Unauthorized(err) => (StatusCode::UNAUTHORIZED, err),
            AppError::Forbidden(err) => (StatusCode::FORBIDDEN, err),
            AppError::NotFound(err) => (StatusCode::NOT_FOUND, err),
            AppError::InternalServerError(err) => (StatusCode::INTERNAL_SERVER_ERROR, err),
            AppError::NotAcceptable(err) => (StatusCode::NOT_ACCEPTABLE, err),
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

/* Example for swagger ui */
#[derive(utoipa::ToSchema)]
#[allow(non_camel_case_types)]
struct newaddr {
    #[schema(example = "p2tr")]
    #[allow(dead_code)]
    addresstype: String,
}

/* Example for swagger ui */
#[derive(utoipa::ToSchema)]
#[allow(dead_code)]
struct DynamicForm(HashMap<String, String>);

/* Handler for calling RPC methods */
#[utoipa::path(
    post,
    path = "/v1/{rpc_method}",
    responses(
        (status = 201, description = "Call rpc method", body = serde_json::Value,
         content(("application/json"),("application/yaml"),("application/xml"),
         ("application/x-www-form-urlencoded"))),
        (status = 401, description = "Unauthorized", body = serde_json::Value),
        (status = 403, description = "Forbidden", body = serde_json::Value),
        (status = 404, description = "Not Found", body = serde_json::Value),
        (status = 500, description = "Server Error", body = serde_json::Value)
    ),
    request_body(description = "RPC params",
        content((newaddr = "application/json"),
                (newaddr = "application/yaml"),
                (DynamicForm = "application/x-www-form-urlencoded"),
                (newaddr = "application/xml"))),
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

    let request_bytes = match to_bytes(body.into_body(), usize::MAX).await {
        Ok(o) => o,
        Err(e) => {
            return Err(AppError::InternalServerError(RpcError {
                code: None,
                data: None,
                message: format!("Could not read request body: {}", e),
            }))
        }
    };

    let mut rpc_params = convert_request_to_json(&headers, &rpc_method, request_bytes)?;

    filter_json(&mut rpc_params);

    verify_rune(plugin.clone(), rune, &rpc_method, &rpc_params).await?;

    let cln_result = match call_rpc(plugin, &rpc_method, rpc_params).await {
        Ok(result) => result,
        Err(err) => {
            if let Some(code) = err.code {
                if code == -32601 {
                    return Err(AppError::NotFound(err));
                }
            }
            return Err(AppError::InternalServerError(err));
        }
    };

    convert_json_to_response(headers, &rpc_method, cln_result)
}

fn convert_request_to_json(
    headers: &axum::http::HeaderMap,
    rpc_method: &str,
    request_bytes: axum::body::Bytes,
) -> Result<serde_json::Value, AppError> {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    let format = match content_type {
        a if a.contains("*/*") => "json",
        a if a.contains("application/json") => "json",
        a if a.contains("application/yaml") => "yaml",
        a if a.contains("application/xml") => "xml",
        a if a.contains("application/x-www-form-urlencoded") => "form",
        _ => {
            return Err(AppError::NotAcceptable(RpcError {
                code: None,
                data: None,
                message: format!("Unsupported content-type header: {}", content_type),
            }));
        }
    };

    if request_bytes.is_empty() {
        return Ok(json!({}));
    }

    match format {
        "yaml" => serde_yml::from_slice(&request_bytes).map_err(|e| {
            AppError::InternalServerError(RpcError {
                code: None,
                data: None,
                message: format!(
                    "Could not parse `{}` as YAML request: {}",
                    String::from_utf8_lossy(&request_bytes),
                    e
                ),
            })
        }),
        "xml" => {
            let req_str = std::str::from_utf8(&request_bytes).map_err(|e| {
                AppError::InternalServerError(RpcError {
                    code: None,
                    data: None,
                    message: format!(
                        "Could not read `{}` as valid utf8: {}",
                        String::from_utf8_lossy(&request_bytes),
                        e
                    ),
                })
            })?;
            let json_with_root = roxmltree_to_serde::xml_str_to_json(
                req_str,
                &roxmltree_to_serde::Config::new_with_defaults(),
            )
            .map_err(|e| {
                AppError::InternalServerError(RpcError {
                    code: None,
                    data: None,
                    message: format!(
                        "Could not parse `{}` as XML request: {}",
                        String::from_utf8_lossy(&request_bytes),
                        e
                    ),
                })
            })?;
            let json_without_root = json_with_root.get(rpc_method).ok_or_else(|| {
                AppError::InternalServerError(RpcError {
                    code: None,
                    data: None,
                    message: format!("Use rpc method name as root element: `{}`", rpc_method),
                })
            })?;
            Ok(json!(json_without_root))
        }
        "form" => {
            let form_map: HashMap<String, serde_json::Value> = serde_qs::from_bytes(&request_bytes)
                .map_err(|e| {
                    AppError::InternalServerError(RpcError {
                        code: None,
                        data: None,
                        message: format!(
                            "Could not parse `{}` FORM-URLENCODED request: {}",
                            String::from_utf8_lossy(&request_bytes),
                            e
                        ),
                    })
                })?;
            Ok(json!(form_map))
        }
        _ => serde_json::from_slice(&request_bytes).map_err(|e| {
            AppError::InternalServerError(RpcError {
                code: None,
                data: None,
                message: format!(
                    "Could not parse `{}` JSON request: {}",
                    String::from_utf8_lossy(&request_bytes),
                    e
                ),
            })
        }),
    }
}

fn convert_json_to_response(
    headers: axum::http::HeaderMap,
    rpc_method: &str,
    cln_result: serde_json::Value,
) -> Result<Response, AppError> {
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    let format = match accept {
        a if a.contains("*/*") => "json",
        a if a.contains("application/json") => "json",
        a if a.contains("application/yaml") => "yaml",
        a if a.contains("application/xml") => "xml",
        a if a.contains("application/x-www-form-urlencoded") => "form",
        _ => {
            return Err(AppError::NotAcceptable(RpcError {
                code: None,
                data: None,
                message: format!("Unsupported accept header: {}", accept),
            }));
        }
    };

    match format {
        "yaml" => match serde_yml::to_string(&cln_result) {
            Ok(yaml) => Ok((
                StatusCode::CREATED,
                [("Content-Type", "application/yaml")],
                yaml,
            )
                .into_response()),
            Err(e) => Err(AppError::InternalServerError(RpcError {
                code: None,
                data: None,
                message: format!("Could not serialize to YAML: {}", e),
            })),
        },
        "xml" => match quick_xml::se::to_string_with_root(rpc_method, &cln_result) {
            Ok(xml) => Ok((
                StatusCode::CREATED,
                [("Content-Type", "application/xml")],
                xml,
            )
                .into_response()),
            Err(e) => Err(AppError::InternalServerError(RpcError {
                code: None,
                data: None,
                message: format!("Could not serialize to XML: {}", e),
            })),
        },
        "form" => match serde_qs::to_string(&cln_result) {
            Ok(form) => Ok((
                StatusCode::CREATED,
                [("Content-Type", "application/x-www-form-urlencoded")],
                form,
            )
                .into_response()),
            Err(e) => Err(AppError::InternalServerError(RpcError {
                code: None,
                data: None,
                message: format!("Could not serialize to FORM-URLENCODED: {}", e),
            })),
        },
        _ => {
            let response_body = Json(cln_result);
            let response = (
                StatusCode::CREATED,
                [("Content-Type", "application/json")],
                response_body,
            )
                .into_response();
            Ok(response)
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
