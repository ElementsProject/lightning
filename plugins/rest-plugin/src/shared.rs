use axum::http;
use cln_plugin::Plugin;
use cln_rpc::{
    model::responses::{CheckruneResponse, ShowrunesResponse},
    ClnRpc, RpcError,
};
use serde_json::json;

use crate::{structs::AppError, CheckRuneParams, ClnrestMap, PluginState};

pub async fn verify_rune(
    plugin: &Plugin<PluginState>,
    rune_header: Option<String>,
    checkrune_params: &CheckRuneParams,
) -> Result<(), AppError> {
    let rune = match rune_header {
        Some(rune) => rune,
        None => {
            let err = RpcError {
                code: Some(1501),
                data: None,
                message: "Not authorized: Missing rune".to_string(),
            };
            log::info!("verify_rune failed: {checkrune_params} {err}");
            return Err(AppError::Forbidden(err));
        }
    };

    let mut rpc_params = serde_json::Map::new();
    rpc_params.insert("rune".to_owned(), json!(rune));
    if let Some(nodeid) = &checkrune_params.nodeid {
        rpc_params.insert("nodeid".to_owned(), json!(nodeid));
    }
    if let Some(method) = &checkrune_params.method {
        rpc_params.insert("method".to_owned(), json!(method));
    }
    if let Some(params) = &checkrune_params.params {
        rpc_params.insert("params".to_owned(), json!(params));
    }
    let rpc_params_value = serde_json::Value::Object(rpc_params);

    let checkrune_result = match call_rpc(plugin, "checkrune", rpc_params_value).await {
        Ok(o) => serde_json::from_value::<CheckruneResponse>(o).unwrap(),
        Err(e) => {
            log::info!("verify_rune failed: {checkrune_params} {e}");
            return Err(AppError::Unauthorized(e));
        }
    };

    if !checkrune_result.valid {
        let err = RpcError {
            code: Some(1502),
            message: "Rune is not valid".to_string(),
            data: None,
        };
        log::info!("verify_rune failed: {checkrune_params} {err}");
        return Err(AppError::Unauthorized(err));
    }

    let showrunes_result = match call_rpc(plugin, "showrunes", json!({"rune": rune})).await {
        Ok(r) => serde_json::from_value::<ShowrunesResponse>(r).unwrap(),
        Err(e) => return Err(AppError::InternalServerError(e)),
    };

    log::info!(
        "Authorized rune_id:`{}` access to {}",
        showrunes_result.runes.first().unwrap().unique_id,
        checkrune_params,
    );

    Ok(())
}

pub async fn call_rpc(
    plugin: &Plugin<PluginState>,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, RpcError> {
    let rpc_path = plugin.configuration().rpc_file;
    let mut rpc = ClnRpc::new(rpc_path).await.map_err(|e| RpcError {
        code: None,
        data: None,
        message: e.to_string(),
    })?;
    rpc.call_raw(method, &params).await
}

pub fn path_to_rest_map_and_params(
    plugin: &Plugin<PluginState>,
    path: &str,
    http_method: &http::Method,
) -> Result<(ClnrestMap, serde_json::Map<String, serde_json::Value>), AppError> {
    let mut rpc_params = serde_json::Map::new();
    let dynamic_paths = plugin.state().dyn_router.lock().unwrap();
    if let Ok(dyn_path) = dynamic_paths.at(path) {
        for (name, value) in dyn_path.params.iter() {
            rpc_params.insert(name.to_owned(), serde_json::Value::String(value.to_owned()));
        }
        if let Some(clnrest_map) = dyn_path.value.get(http_method) {
            return Ok((clnrest_map.to_owned(), rpc_params));
        }
        return Err(AppError::MethodNotAllowed(RpcError {
            code: Some(-32601),
            message: format!("Dynamic path: {path} has no http_method:{http_method} registered"),
            data: None,
        }));
    }
    if let Some((prefix, suffix)) = path.split_once("v1/") {
        if !prefix.is_empty() {
            return Err(AppError::NotFound(RpcError {
                code: Some(-32601),
                message: "Path invalid, version missing for CLN methods".to_owned(),
                data: None,
            }));
        }
        if http_method != http::Method::POST {
            return Err(AppError::MethodNotAllowed(RpcError {
                code: Some(-32601),
                message: "Path invalid, http_method must be POST for CLN methods".to_owned(),
                data: None,
            }));
        }
        let clnrest_map = ClnrestMap {
            rpc_method: suffix.to_owned(),
            rune_required: true,
            rune_restrictions: None,
        };
        return Ok((clnrest_map, rpc_params));
    }
    Err(AppError::NotFound(RpcError {
        code: Some(-32601),
        message: "Path not found".to_owned(),
        data: None,
    }))
}

pub fn filter_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(arr) => {
            for v in arr {
                filter_json(v);
            }
        }
        serde_json::Value::Object(obj) => {
            obj.retain(|k, v| !is_unwanted(k, v));
            for v in obj.values_mut() {
                filter_json(v);
            }
        }
        _ => (),
    }
}

fn is_unwanted(key: &String, value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => {
            log::debug!("is_unwanted: key:{} value:{} (null)", key, value);
            true
        }
        _ => false,
    }
}
