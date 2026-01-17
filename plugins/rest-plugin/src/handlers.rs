use std::{collections::HashMap, process};

use anyhow::anyhow;
use axum::{
    body::{to_bytes, Body},
    extract::{Extension, Json, Path},
    http::{self, Request, StatusCode},
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
use std::fmt::Write;

use crate::{
    shared::{call_rpc, filter_json, path_to_rest_map_and_params, verify_rune},
    structs::{AppError, CheckRuneParams, ClnrestMap, PluginState},
    SWAGGER_FALLBACK,
};

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
    match call_rpc(&plugin, "help", json!(HelpRequest { command: None })).await {
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
    let processed_res: HelpResponse = match serde_json::from_value(help_response) {
        Ok(res) => res,
        Err(e) => {
            log::error!("Failed to parse help response: {e}");
            return format!("Failed to parse help response: {e}");
        }
    };

    let line = "\n---------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n";
    let mut processed_html_res = String::new();

    for row in processed_res.help {
        writeln!(processed_html_res, "Command: {}", row.command).unwrap();
        writeln!(processed_html_res, "{line}").unwrap();
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
    http_method: http::Method,
    Path(path): Path<String>,
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

    let (mut rest_map, mut rpc_params) = path_to_rest_map_and_params(&plugin, &path, &http_method)?;

    request_body_to_rpc_params(
        &mut rpc_params,
        &headers,
        &rest_map.rpc_method,
        request_bytes,
    )?;

    fill_rune_restrictions(&mut rest_map, &rpc_params);

    let mut rpc_params_value = json!(rpc_params);

    filter_json(&mut rpc_params_value);

    if rest_map.rune_required || http_method != http::Method::GET {
        verify_rune(&plugin, rune, &rest_map.rune_restrictions.unwrap()).await?;
    }

    let cln_result = match call_rpc(&plugin, &rest_map.rpc_method, rpc_params_value).await {
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

    convert_json_to_response(headers, &rest_map.rpc_method, cln_result)
}

fn fill_rune_restrictions(
    rest_map: &mut ClnrestMap,
    rpc_params: &serde_json::Map<String, serde_json::Value>,
) {
    if let Some(r) = &mut rest_map.rune_restrictions {
        if r.params.is_none() {
            r.params = Some(rpc_params.clone());
        }
        if r.method.is_none() {
            r.method = Some(rest_map.rpc_method.clone());
        }
    } else {
        rest_map.rune_restrictions = Some(CheckRuneParams {
            nodeid: None,
            method: Some(rest_map.rpc_method.clone()),
            params: Some(rpc_params.clone()),
        });
    }
}

fn request_body_to_rpc_params(
    rpc_params: &mut serde_json::Map<String, serde_json::Value>,
    headers: &axum::http::HeaderMap,
    rpc_method: &str,
    request_bytes: axum::body::Bytes,
) -> Result<(), AppError> {
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
        return Ok(());
    }

    let body_rpc_params: serde_json::Map<String, serde_json::Value> = match format {
        "yaml" => serde_yaml_ng::from_slice(&request_bytes).map_err(|e| {
            AppError::InternalServerError(RpcError {
                code: None,
                data: None,
                message: format!(
                    "Could not parse `{}` as YAML request: {}",
                    String::from_utf8_lossy(&request_bytes),
                    e
                ),
            })
        })?,
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
            serde_json::from_value(json_without_root.to_owned()).unwrap()
        }
        "form" => serde_qs::from_bytes(&request_bytes).map_err(|e| {
            AppError::InternalServerError(RpcError {
                code: None,
                data: None,
                message: format!(
                    "Could not parse `{}` FORM-URLENCODED request: {}",
                    String::from_utf8_lossy(&request_bytes),
                    e
                ),
            })
        })?,
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
        })?,
    };

    merge_maps_disjoint(rpc_params, body_rpc_params)?;

    Ok(())
}

fn merge_maps_disjoint(
    base: &mut serde_json::Map<String, serde_json::Value>,
    other: serde_json::Map<String, serde_json::Value>,
) -> Result<(), AppError> {
    for (key, value) in other {
        if base.contains_key(&key) {
            return Err(AppError::NotAcceptable(RpcError {
                code: None,
                message: format!("Duplicate key: {key}"),
                data: None,
            }));
        }
        base.insert(key, value);
    }
    Ok(())
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
        "yaml" => match serde_yaml_ng::to_string(&cln_result) {
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

pub async fn swagger_redirect_middleware(
    Extension(swagger_path): Extension<String>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let root_path = req.uri().path();

    if root_path.eq("/") && swagger_path.eq("/") {
        return Ok(Redirect::permanent(SWAGGER_FALLBACK).into_response());
    }

    Ok(next.run(req).await)
}

pub async fn auth_socket_io_middleware(
    socket: SocketRef,
    socketioxide::extract::State(plugin): socketioxide::extract::State<Plugin<PluginState>>,
) -> Result<(), AppError> {
    let rune = socket
        .req_parts()
        .headers
        .get("rune")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let checkrune_params = CheckRuneParams {
        nodeid: None,
        method: Some("listclnrest-notifications".to_owned()),
        params: None,
    };
    verify_rune(&plugin, rune, &checkrune_params).await
}
