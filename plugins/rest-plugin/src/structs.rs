use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    extract::Json,
    http::{self, StatusCode},
    response::{IntoResponse, Response},
};
use cln_rpc::RpcError;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::mpsc::Sender;
use tower_http::cors::CorsLayer;
use utoipa::{
    openapi::{
        security::{ApiKey, ApiKeyValue, SecurityScheme},
        Components,
    },
    Modify, OpenApi,
};

#[derive(Debug)]
pub enum AppError {
    Unauthorized(RpcError),
    Forbidden(RpcError),
    NotFound(RpcError),
    MethodNotAllowed(RpcError),
    InternalServerError(RpcError),
    NotAcceptable(RpcError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Unauthorized(err) => (StatusCode::UNAUTHORIZED, err),
            AppError::Forbidden(err) => (StatusCode::FORBIDDEN, err),
            AppError::NotFound(err) => (StatusCode::NOT_FOUND, err),
            AppError::MethodNotAllowed(err) => (StatusCode::METHOD_NOT_ALLOWED, err),
            AppError::InternalServerError(err) => (StatusCode::INTERNAL_SERVER_ERROR, err),
            AppError::NotAcceptable(err) => (StatusCode::NOT_ACCEPTABLE, err),
        };

        let body = Json(json!(error_message));
        (status, body).into_response()
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Unauthorized(err) => write!(f, "Unauthorized: {err}"),
            AppError::Forbidden(err) => write!(f, "Forbidden: {err}"),
            AppError::NotFound(err) => write!(f, "Not Found: {err}"),
            AppError::MethodNotAllowed(err) => write!(f, "Method not allowed: {err}"),
            AppError::InternalServerError(err) => write!(f, "Internal Server Error: {err}"),
            AppError::NotAcceptable(err) => write!(f, "Not Acceptable: {err}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PluginState {
    pub notification_sender: Sender<serde_json::Value>,
    pub dyn_router: Arc<Mutex<matchit::Router<HashMap<http::Method, ClnrestMap>>>>,
}

#[derive(Debug, Clone)]
pub struct ClnrestMap {
    pub rpc_method: String,
    pub rune_required: bool,
    pub rune_restrictions: Option<CheckRuneParams>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CheckRuneParams {
    pub nodeid: Option<String>,
    pub method: Option<String>,
    pub params: Option<serde_json::Map<String, serde_json::Value>>,
}

impl std::fmt::Display for CheckRuneParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();

        if let Some(nodeid) = &self.nodeid {
            parts.push(format!("nodeid: `{nodeid}`"));
        }

        if let Some(method) = &self.method {
            parts.push(format!("method: `{method}`"));
        }

        if let Some(params) = &self.params {
            parts.push(format!(
                "params: `{}`",
                serde_json::to_string(params).unwrap_or_else(|_| "{}".to_string())
            ));
        }

        if parts.is_empty() {
            write!(f, "{{}}")
        } else {
            write!(f, "{}", parts.join(", "))
        }
    }
}

#[derive(OpenApi)]
#[openapi(
        paths(
            crate::handlers::list_methods,
            crate::handlers::call_rpc_method,
        ),
        modifiers(&SecurityAddon),
    )]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Components::new);
        components.add_security_scheme(
            "api_key",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("rune"))),
        );
        openapi.components = Some(components.clone());
    }
}

pub enum ClnrestProtocol {
    Https,
    Http,
}
pub struct ClnrestOptions {
    pub certs: PathBuf,
    pub protocol: ClnrestProtocol,
    pub address_str: String,
    pub address: SocketAddr,
    pub cors: CorsLayer,
    pub csp: String,
    pub swagger: String,
}
