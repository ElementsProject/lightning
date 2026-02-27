use anyhow::anyhow;
use cln_plugin::options::StringArrayConfigOption;
use cln_plugin::{Builder, ConfiguredPlugin, Plugin, RpcMethodBuilder};
use cln_rpc::ClnRpc;
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::vec;
use tokio::sync::Mutex;

use crate::oracle::{BtcPriceOracle, Source};

mod oracle;

const DEFAULT_PROXY_PORT: u16 = 9050;

#[derive(Debug, Clone)]
pub struct SourceResult {
    pub name: String,
    pub price: f64,
}

#[derive(Clone)]
struct PluginState {
    oracle: Arc<Mutex<BtcPriceOracle>>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    log_panics::init();
    std::env::set_var(
        "CLN_PLUGIN_LOG",
        "cln_plugin=info,cln_rpc=info,cln_currencyrate=debug,warn",
    );

    let _ = rustls::crypto::ring::default_provider().install_default();

    let add_source_opt = StringArrayConfigOption::new_str_arr_no_default(
        "currencyrate-add-source",
        "A source for cln-currencyrate to fetch price data from in the format of `NAME,URL,MEMBERS`",
    );
    let disable_source_opt = StringArrayConfigOption::new_str_arr_no_default(
        "currencyrate-disable-source",
        "The name of the cln-currencyrate source to disable",
    );

    let Some(plugin) = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(add_source_opt)
        .option(disable_source_opt)
        .rpcmethod_from_builder(
            RpcMethodBuilder::new("currencyconvert", currencyconvert)
                .description(
                    "Converts the given amount and currency into msats, using the
median from currencyrates results",
                )
                .usage("amount currency"),
        )
        .rpcmethod_from_builder(
            RpcMethodBuilder::new("currencyrates", currencyrates)
                .description("Returns the number of msats per unit from every source")
                .usage("currency"),
        )
        .dynamic()
        .configure()
        .await?
    else {
        return Ok(());
    };

    let proxy = match check_proxy_config(&plugin).await {
        Ok(o) => o,
        Err(e) => return plugin.disable(&e.to_string()).await,
    };

    let sources = match gather_sources(&plugin, proxy.is_some()) {
        Ok(o) => o,
        Err(e) => return plugin.disable(&e.to_string()).await,
    };

    let price_oracle = match BtcPriceOracle::new(proxy, sources) {
        Ok(o) => o,
        Err(e) => return plugin.disable(&e.to_string()).await,
    };

    let plugin_state = PluginState {
        oracle: Arc::new(Mutex::new(price_oracle)),
    };

    let plugin = plugin.start(plugin_state).await?;

    plugin.join().await
}

async fn currencyconvert(plugin: Plugin<PluginState>, args: Value) -> Result<Value, anyhow::Error> {
    let (amount, currency) = match args {
        Value::Array(values) => {
            let amount = values
                .first()
                .ok_or_else(|| anyhow!("Missing amount"))?
                .as_f64()
                .ok_or_else(|| anyhow!("amount must be a number"))?;
            let currency = values
                .get(1)
                .ok_or_else(|| anyhow!("Missing currency"))?
                .as_str()
                .ok_or_else(|| anyhow!("currency must be a string"))?
                .to_owned();
            (amount, currency.to_uppercase())
        }
        Value::Object(map) => {
            let amount = map
                .get("amount")
                .ok_or_else(|| anyhow!("Missing amount"))?
                .as_f64()
                .ok_or_else(|| anyhow!("amount must be a number"))?;
            let currency = map
                .get("currency")
                .ok_or_else(|| anyhow!("Missing currency"))?
                .as_str()
                .ok_or_else(|| anyhow!("currency must be a string"))?
                .to_owned();
            (amount, currency.to_uppercase())
        }
        _ => return Err(anyhow!("Arguments must be an array or dictionary")),
    };

    let oracle = plugin.state().oracle.lock().await;
    oracle.currency_requested(&currency).await;

    match oracle.convert(amount, &currency).await {
        Ok(result) => Ok(json!({
            "msat": result,
        })),
        Err(e) => Err(anyhow!("Error converting currency: {e}")),
    }
}

async fn currencyrates(plugin: Plugin<PluginState>, args: Value) -> Result<Value, anyhow::Error> {
    let currency = match args {
        Value::Array(values) => {
            let currency = values
                .first()
                .ok_or_else(|| anyhow!("Missing currency"))?
                .as_str()
                .ok_or_else(|| anyhow!("currency must be a string"))?
                .to_owned();
            currency.to_uppercase()
        }
        Value::Object(map) => {
            let currency = map
                .get("currency")
                .ok_or_else(|| anyhow!("Missing currency"))?
                .as_str()
                .ok_or_else(|| anyhow!("currency must be a string"))?
                .to_owned();
            currency.to_uppercase()
        }
        _ => return Err(anyhow!("Arguments must be an array or dictionary")),
    };

    let oracle = plugin.state().oracle.lock().await;
    oracle.currency_requested(&currency).await;

    match oracle.get_all_rates(&currency).await {
        Ok(result) => {
            let mut map = serde_json::Map::new();
            for source_result in result {
                let msat = source_result.price.round() as u64;
                map.insert(source_result.name.clone(), json!(msat));
            }
            Ok(json!(map))
        }
        Err(e) => Err(anyhow!("Error converting currency: {e}")),
    }
}

async fn check_proxy_config(
    plugin: &ConfiguredPlugin<PluginState, tokio::io::Stdin, tokio::io::Stdout>,
) -> Result<Option<SocketAddr>, anyhow::Error> {
    let rpc_path =
        Path::new(&plugin.configuration().lightning_dir).join(plugin.configuration().rpc_file);
    let mut rpc = ClnRpc::new(rpc_path).await?;

    let listconfigs_val: Value = rpc.call_raw("listconfigs", &json!(["proxy"])).await?;
    let configs_val = listconfigs_val
        .get("configs")
        .ok_or(anyhow!("Missing configs"))?;
    let Some(proxy_val) = configs_val.get("proxy") else {
        return Ok(None);
    };
    let proxy_str = proxy_val
        .get("value_str")
        .ok_or(anyhow!("proxy missing value_str"))?
        .as_str()
        .ok_or(anyhow!("proxy value is not a string"))?;

    if let Ok(addr) = SocketAddr::from_str(proxy_str) {
        return Ok(Some(addr));
    }

    if let Ok(ip) = IpAddr::from_str(proxy_str) {
        return Ok(Some(SocketAddr::new(ip, DEFAULT_PROXY_PORT)));
    }

    Err(anyhow!("Could not parse proxy value: {proxy_str}"))
}
fn gather_sources(
    plugin: &ConfiguredPlugin<PluginState, tokio::io::Stdin, tokio::io::Stdout>,
    has_proxy: bool,
) -> Result<Vec<Source>, anyhow::Error> {
    let mut result = Vec::new();

    let source_opts = plugin.option_str("currencyrate-add-source").unwrap();
    if let Some(sources) = source_opts {
        let sources_arr = sources
            .as_str_arr()
            .ok_or(anyhow!("currencyrate-add-source is not a string array"))?;
        for source in sources_arr {
            let parts: Vec<&str> = source.splitn(3, ',').collect();
            if parts.len() != 3 {
                return Err(anyhow!("Invalid source format: {source}"));
            }
            let source = Source::new(parts[0], parts[1], parts[2].split(',').collect());
            result.push(source);
        }
    }

    add_default_sources(&mut result, has_proxy);

    let disable_sources = plugin.option_str("currencyrate-disable-source").unwrap();
    if let Some(dis_sorc) = disable_sources {
        let disable_sources_arr = dis_sorc
            .as_str_arr()
            .ok_or(anyhow!("currencyrate-disable-source is not a string array"))?;
        for source in disable_sources_arr {
            result.retain(|s| s.name() != source);
        }
    }

    if result.is_empty() {
        return Err(anyhow!("No sources configured"));
    }

    Ok(result)
}

fn add_default_sources(result: &mut Vec<Source>, has_proxy: bool) {
    let coingecko = Source::new(
        "coingecko",
        "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies={currency_lc}",
        vec!["bitcoin", "{currency_lc}"],
    );
    result.push(coingecko);

    let kraken = Source::new(
        "kraken",
        "https://api.kraken.com/0/public/Ticker?pair=XXBTZ{currency}",
        vec!["result", "XXBTZ{currency}", "c", "0"],
    );
    result.push(kraken);

    let blockchain_info = Source::new(
        "blockchain.info",
        "https://blockchain.info/ticker",
        vec!["{currency}", "last"],
    );
    result.push(blockchain_info);

    if !has_proxy {
        let bitstamp = Source::new(
            "bitstamp",
            "https://www.bitstamp.net/api/v2/ticker/btc{currency_lc}",
            vec!["last"],
        );
        result.push(bitstamp);
    }

    let coindesk = Source::new(
        "coindesk",
        "https://data-api.coindesk.com/index/cc/v1/latest/tick\
        ?market=cadli&instruments=BTC-{currency}&apply_mapping=true",
        vec!["Data", "BTC-{currency}", "VALUE"],
    );
    result.push(coindesk);

    let coinbase = Source::new(
        "coinbase",
        "https://api.coinbase.com/v2/prices/BTC-{currency}/spot",
        vec!["data", "amount"],
    );
    result.push(coinbase);

    let binance = Source::new(
        "binance",
        "https://data-api.binance.vision/api/v3/ticker/price?symbol=BTC{currency}",
        vec!["price"],
    );
    result.push(binance);
}
