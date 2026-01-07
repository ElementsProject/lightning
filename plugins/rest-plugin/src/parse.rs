use std::str::FromStr;

use anyhow::anyhow;
use axum::http;

use crate::structs::{CheckRuneParams, ClnrestMap};

pub fn parse_register_path_args(
    args: serde_json::Value,
) -> Result<(String, http::Method, ClnrestMap), anyhow::Error> {
    let (path_input, http_method, clnrest_map) = match args {
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
            let http_method = if let Some(h) = args_arr.get(2) {
                http::Method::from_str(
                    &h.as_str()
                        .ok_or_else(|| anyhow!("http_method must be a string"))?
                        .to_ascii_uppercase(),
                )?
            } else {
                http::Method::POST
            };
            let rune_required = if let Some(r) = args_arr.get(3) {
                r.as_bool()
                    .ok_or_else(|| anyhow!("rune_required must be a boolean"))?
            } else {
                true
            };
            let rune_restrictions: Option<CheckRuneParams> = if let Some(r) = args_arr.get(4) {
                Some(serde_json::from_value(r.clone())?)
            } else {
                None
            };
            let clnrest_map = ClnrestMap {
                rpc_method,
                rune_required,
                rune_restrictions,
            };
            (path_input, http_method, clnrest_map)
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
            let http_method = if let Some(h) = map.get("http_method") {
                http::Method::from_str(
                    &h.as_str()
                        .ok_or_else(|| anyhow!("http_method must be a string"))?
                        .to_ascii_uppercase(),
                )?
            } else {
                http::Method::POST
            };
            let rune_required = if let Some(r) = map.get("rune_required") {
                r.as_bool()
                    .ok_or_else(|| anyhow!("rune_required must be a boolean"))?
            } else {
                true
            };
            let rune_restrictions: Option<CheckRuneParams> =
                if let Some(r) = map.get("rune_restrictions") {
                    Some(serde_json::from_value(r.clone())?)
                } else {
                    None
                };
            let clnrest_map = ClnrestMap {
                rpc_method,
                rune_required,
                rune_restrictions,
            };
            (path_input, http_method, clnrest_map)
        }
        _ => return Err(anyhow!("Input arguments must be an array or object")),
    };

    if !matches!(
        http_method,
        http::Method::GET
            | http::Method::POST
            | http::Method::PUT
            | http::Method::PATCH
            | http::Method::DELETE
    ) {
        return Err(anyhow!("{} is not a supported http method!", http_method));
    }

    if http_method != http::Method::GET && !clnrest_map.rune_required {
        return Err(anyhow!(
            "rune_required must be true for anything but GET requests"
        ));
    }

    Ok((path_input, http_method, clnrest_map))
}
