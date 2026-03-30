use cln_plugin::{Plugin, messages::ProxyInfo};

pub fn get_proxy(plugin: Plugin<()>) -> Option<ProxyInfo> {
    match plugin.configuration().always_use_proxy {
        Some(use_proxy) => {
            if !use_proxy {
                return None;
            }
        }
        None => return None,
    };
    plugin.configuration().proxy
}
