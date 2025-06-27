use std::collections::HashMap;

use anyhow::anyhow;
use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::HeaderValue,
    response::{IntoResponse, Response},
};
use cln_plugin::Plugin;
use cln_rpc::{
    model::responses::{CheckruneResponse, HelpHelpClnrest, HelpResponse, ShowrunesResponse},
    ClnRpc, RpcError,
};
use hyper::{header, StatusCode};
use serde_json::{json, Map};

use crate::{handlers::AppError, ClnrestMap, PluginState};

pub async fn verify_rune(
    rpc_file: &String,
    rune_header: Option<String>,
    rpc_method: &str,
    rpc_params: Option<serde_json::Value>,
) -> Result<(), AppError> {
    let rpc_params = rpc_params.unwrap_or_else(|| json!({}));
    let rune = match rune_header {
        Some(rune) => rune,
        None => {
            let err = RpcError {
                code: Some(1501),
                data: None,
                message: "Not authorized: Missing rune".to_string(),
            };
            log::info!(
                "verify_rune failed: method:`{}` params:`{}` {}",
                rpc_method,
                rpc_params,
                err
            );
            return Err(AppError::Forbidden(err));
        }
    };

    let checkrune_result = match call_rpc(
        rpc_file,
        "checkrune",
        Some(json!({"rune": rune, "method": rpc_method, "params": rpc_params})),
    )
    .await
    {
        Ok(o) => serde_json::from_value::<CheckruneResponse>(o).unwrap(),
        Err(e) => {
            log::info!(
                "verify_rune failed: method:`{}` params:`{}` {}",
                rpc_method,
                rpc_params,
                e
            );
            return Err(AppError::Unauthorized(e));
        }
    };

    if !checkrune_result.valid {
        let err = RpcError {
            code: Some(1502),
            message: "Rune is not valid".to_string(),
            data: None,
        };
        log::info!(
            "verify_rune failed: method:`{}` params:`{}` {}",
            rpc_method,
            rpc_params,
            err
        );
        return Err(AppError::Unauthorized(err));
    }

    let showrunes_result = match call_rpc(rpc_file, "showrunes", Some(json!({"rune": rune}))).await
    {
        Ok(r) => serde_json::from_value::<ShowrunesResponse>(r).unwrap(),
        Err(e) => return Err(AppError::InternalServerError(e)),
    };

    log::info!(
        "Authorized rune_id:`{}` access to method:`{}` with params:`{}`",
        showrunes_result.runes.first().unwrap().unique_id,
        rpc_method,
        rpc_params
    );

    Ok(())
}

pub async fn call_rpc(
    rpc_file: &String,
    method: &str,
    params: Option<serde_json::Value>,
) -> Result<serde_json::Value, RpcError> {
    let params = params.unwrap_or_else(|| json!({}));
    let mut rpc = ClnRpc::new(rpc_file).await.map_err(|e| RpcError {
        code: None,
        data: None,
        message: e.to_string(),
    })?;
    rpc.call_raw(method, &params).await
}

pub async fn parse_request_body(body: Request) -> Result<serde_json::Value, AppError> {
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
    serde_json::from_slice(&bytes).or_else(|_| {
        let form_str = String::from_utf8(bytes.to_vec()).unwrap();
        let mut form_data = serde_json::Map::new();
        for pair in form_str.split('&') {
            let mut kv = pair.split('=');
            if let (Some(key), Some(value)) = (kv.next(), kv.next()) {
                form_data.insert(
                    key.to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            }
        }
        Ok(serde_json::Value::Object(form_data))
    })
}

pub fn merge_params(
    rpc_params: &mut serde_json::Value,
    path_params: Option<serde_json::Value>,
) -> Result<(), AppError> {
    if let Some(serde_json::Value::Object(extr_p)) = path_params {
        match rpc_params {
            serde_json::Value::Object(a_map) => {
                for (k, v) in extr_p {
                    a_map.insert(k, v);
                }
            }
            a => {
                return Err(AppError::InternalServerError(RpcError {
                    code: None,
                    data: None,
                    message: format!("Could not parse params as object: {}", a),
                }))
            }
        }
    }
    Ok(())
}

pub async fn handle_custom_paths(
    plugin: &Plugin<PluginState>,
    path: &str,
    method: &str,
) -> Result<(String, Option<serde_json::Value>, Option<ClnrestMap>), AppError> {
    let custom_paths = plugin.state().rest_paths.lock().unwrap().clone();
    let mut rest_map = None;
    let mut extra_params = None;
    let most_specific_match = match match_path(&("/".to_string() + path), method, &custom_paths) {
        Ok(m) => m.into_iter().min_by_key(|(_, params)| params.len()),
        Err(e) => {
            return Err(AppError::InternalServerError(RpcError {
                code: Some(-1),
                message: e.to_string(),
                data: None,
            }))
        }
    };
    if let Some((custom_path, custom_params)) = most_specific_match {
        rest_map = Some(custom_paths.get(&custom_path).unwrap().clone());
        extra_params = Some(serde_json::Value::Object(custom_params));
    }

    if let Some(rm) = &rest_map {
        if !rm.http_method.eq_ignore_ascii_case(method) {
            return Err(AppError::NotFound(RpcError {
                code: Some(-32601),
                data: None,
                message: "Wrong http method".to_string(),
            }));
        }
    }

    let rpc_method = if let Some(rp) = &rest_map {
        rp.rpc_method.clone()
    } else if path.contains('/') {
        return Err(AppError::NotFound(RpcError {
            code: Some(-32601),
            message: "Path not registered".to_string(),
            data: None,
        }));
    } else {
        path.to_string()
    };

    Ok((rpc_method, extra_params, rest_map))
}

pub fn generate_response(result: serde_json::Value, content_type: HeaderValue) -> Response<Body> {
    let body = Body::new(result.to_string());
    let mut response = (StatusCode::CREATED, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
}

pub fn get_content_type(rest_map: Option<ClnrestMap>) -> Result<HeaderValue, AppError> {
    if let Some(rm) = rest_map {
        Ok(HeaderValue::from_str(&rm.content_type).map_err(|_| {
            AppError::InternalServerError(RpcError {
                code: Some(-1),
                message: format!("Invalid content-type: `{}`", rm.content_type),
                data: None,
            })
        })?)
    } else {
        Ok(HeaderValue::from_static("application/json"))
    }
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

pub async fn get_clnrest_manifests(
    rpc_file: &String,
) -> Result<HashMap<String, HelpHelpClnrest>, anyhow::Error> {
    let help: HelpResponse = serde_json::from_value(call_rpc(rpc_file, "help", None).await?)?;
    let mut help_map = HashMap::new();
    for help in help.help {
        if let Some(clnrest_help) = help.clnrest {
            let command_name = if let Some((name, _args)) = help.command.split_once(' ') {
                name.to_string()
            } else {
                help.command
            };
            help_map.insert(command_name, clnrest_help);
        }
    }
    Ok(help_map)
}

pub fn get_plugin_methods(input: &serde_json::Value) -> Vec<String> {
    input
        .get("methods")
        .and_then(|m| m.as_array())
        .map_or_else(Vec::new, |array| {
            array
                .iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
}

pub fn match_path(
    path: &str,
    http_method: &str,
    rest_map: &HashMap<String, ClnrestMap>,
) -> Result<HashMap<String, serde_json::Map<String, serde_json::Value>>, anyhow::Error> {
    let path_parts: Vec<&str> = path.split('/').collect();

    let mut matches = HashMap::new();

    'outer: for (pattern, map) in rest_map.iter() {
        let pattern_parts: Vec<&str> = pattern.split('/').collect();
        if path_parts.len() != pattern_parts.len() {
            continue;
        }
        if !map.http_method.eq_ignore_ascii_case(http_method) {
            continue;
        }
        let mut params = Map::new();
        if path.eq(pattern) && !pattern.contains('<') {
            matches.insert(pattern.clone(), params);
            continue;
        }
        let mut unambiguous_match = false;
        for (path_part, pattern_part) in path_parts.iter().zip(pattern_parts.iter()) {
            if pattern_part.starts_with('<') && pattern_part.ends_with('>') {
                unambiguous_match = unambiguous_match || !path_part.starts_with('<');

                let key = &pattern_part[1..pattern_part.len() - 1];
                params.insert(
                    key.to_string(),
                    serde_json::Value::String(path_part.to_string()),
                );
            } else if path_part.starts_with('<') && path_part.ends_with('>') {
                unambiguous_match = true;
            } else if path_part != pattern_part {
                continue 'outer;
            }
        }
        if !unambiguous_match {
            return Err(anyhow!("Ambiguous path: {}", path));
        }
        matches.insert(pattern.clone(), params);
    }
    Ok(matches)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_match_path() {
        let http_get1 = "GET";
        let http_get2 = "get";
        let http_post1 = "POST";

        let mut rest_map = HashMap::new();

        let path1 = "/test/me/now";
        let path2 = "/<test>/me/now";
        let path3 = "/<test>/<me>/now";
        let path4 = "/<test>/me/<now>";
        let path_map_get = ClnrestMap {
            content_type: "N/A".to_string(),
            http_method: "GET".to_string(),
            rpc_method: "N/A".to_string(),
            rune: false,
        };
        let path_map_post = ClnrestMap {
            content_type: "N/A".to_string(),
            http_method: "POST".to_string(),
            rpc_method: "N/A".to_string(),
            rune: false,
        };

        assert!(match_path(path1, http_get1, &rest_map).unwrap().is_empty());
        assert!(match_path(path1, http_get2, &rest_map).unwrap().is_empty());
        rest_map.insert(path1.to_string(), path_map_get.clone());
        assert!(match_path(path1, http_get1, &rest_map).unwrap().len() == 1);
        assert!(match_path(path1, http_get2, &rest_map).unwrap().len() == 1);
        assert!(match_path(path1, http_post1, &rest_map).unwrap().is_empty());
        assert!(match_path(path2, http_get1, &rest_map).unwrap().len() == 1);
        rest_map.insert(path2.to_string(), path_map_get.clone());
        assert!(match_path(path2, http_get1, &rest_map).is_err());
        assert!(match_path(path3, http_get1, &rest_map).unwrap().len() == 2);
        rest_map.insert(path3.to_string(), path_map_get.clone());
        assert!(match_path(path3, http_get1, &rest_map).is_err());
        assert!(match_path(path4, http_get1, &rest_map).unwrap().len() == 3);
        rest_map.insert(path4.to_string(), path_map_get.clone());
        assert!(match_path(path4, http_get1, &rest_map).is_err());
        assert!(match_path(path1, http_get1, &rest_map)
            .unwrap()
            .into_iter()
            .min_by_key(|(_, y)| y.len())
            .unwrap()
            .1
            .is_empty());
        assert!(
            match_path("/path/me/now", http_get1, &rest_map)
                .unwrap()
                .into_iter()
                .min_by_key(|(_, y)| y.len())
                .unwrap()
                .1
                .len()
                == 1
        );
        assert!(
            match_path("/path/to/now", http_get1, &rest_map)
                .unwrap()
                .into_iter()
                .min_by_key(|(_, y)| y.len())
                .unwrap()
                .1
                .len()
                == 2
        );
        assert!(
            match_path("/path/me/to", http_get1, &rest_map)
                .unwrap()
                .into_iter()
                .min_by_key(|(_, y)| y.len())
                .unwrap()
                .1
                .len()
                == 2
        );
        assert!(match_path("/path/to/me", http_get1, &rest_map)
            .unwrap()
            .is_empty());
        assert!(match_path(path1, http_post1, &rest_map).unwrap().is_empty());
        rest_map.insert(path1.to_string(), path_map_post.clone());
        assert!(match_path("/test", http_post1, &rest_map)
            .unwrap()
            .is_empty());
    }
}
