use std::time::Duration;

use anyhow::anyhow;
use bitcoin::hex::DisplayHex;
use bitcoin_payment_instructions::{
    hrn_resolution::HumanReadableName, http_resolver::HTTPHrnResolver, PaymentInstructions,
    PaymentMethod, PossiblyResolvedPaymentMethod,
};
use cln_plugin::{Builder, Plugin, RpcMethodBuilder};
use serde::Serialize;

use crate::config::get_proxy;

mod config;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    log_panics::init();
    std::env::set_var(
        "CLN_PLUGIN_LOG",
        "cln_plugin=info,cln_rpc=info,cln_bip353=trace,warn",
    );

    let plugin = match Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .rpcmethod_from_builder(
            RpcMethodBuilder::new("fetchbip353", fetch_bip353)
                .description("Fetch bip353 data and proofs")
                .usage("[address]"),
        )
        .dynamic()
        .configure()
        .await?
    {
        Some(p) => p,
        None => return Ok(()),
    };

    let plugin = plugin.start(()).await?;

    plugin.join().await
}

#[derive(Debug, Serialize)]
struct ProcessedBIP353 {
    proof: String,
    instructions: Vec<ProcessedPaymentInstruction>,
}
impl ProcessedBIP353 {
    fn new(proof: String) -> ProcessedBIP353 {
        ProcessedBIP353 {
            proof,
            instructions: Vec::new(),
        }
    }
}
#[derive(Debug, Serialize)]
struct ProcessedPaymentInstruction {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onchain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offchain_amount_msat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onchain_amount_sat: Option<u64>,
}
impl ProcessedPaymentInstruction {
    fn new() -> ProcessedPaymentInstruction {
        ProcessedPaymentInstruction {
            description: None,
            offer: None,
            onchain: None,
            offchain_amount_msat: None,
            onchain_amount_sat: None,
        }
    }
}

async fn fetch_bip353(
    plugin: Plugin<()>,
    args: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let hrn = parse_hrn(args)?;

    let payment_instructions = fetch_payment_instructions(plugin.clone(), &hrn).await?;

    let processed_payment_instructions = parse_payment_instructions(&payment_instructions)?;

    Ok(serde_json::to_value(processed_payment_instructions)?)
}

fn parse_hrn(args: serde_json::Value) -> Result<HumanReadableName, anyhow::Error> {
    match args {
        serde_json::Value::String(s) => {
            HumanReadableName::from_encoded(&s).map_err(|_e| anyhow!("invalid address"))
        }
        serde_json::Value::Array(values) => {
            if values.len() > 1 {
                return Err(anyhow!("too many arguments"));
            }
            if values.is_empty() {
                return Err(anyhow!("no address given"));
            }
            let address = values
                .first()
                .unwrap()
                .as_str()
                .ok_or_else(|| anyhow!("address is not a string"))?;
            HumanReadableName::from_encoded(address).map_err(|_e| anyhow!("invalid address"))
        }
        serde_json::Value::Object(map) => {
            let address = map
                .get("address")
                .ok_or_else(|| anyhow!("no address given"))?
                .as_str()
                .ok_or_else(|| anyhow!("address is not a string"))?;
            HumanReadableName::from_encoded(address).map_err(|_e| anyhow!("invalid address"))
        }
        _ => Err(anyhow!("invalid json type for address")),
    }
}

async fn fetch_payment_instructions(
    plugin: Plugin<()>,
    hrn: &HumanReadableName,
) -> Result<PaymentInstructions, anyhow::Error> {
    let hrn_resolver = match get_proxy(plugin) {
        Some(proxy_info) => {
            let proxy = reqwest::Proxy::all(format!(
                "socks5h://{}:{}",
                proxy_info.address, proxy_info.port
            ))?;
            let client = reqwest::Client::builder()
                .proxy(proxy)
                .timeout(Duration::from_secs(30))
                .build()?;
            HTTPHrnResolver::with_client(client)
        }
        None => HTTPHrnResolver::new(),
    };

    log::debug!(
        "Trying to fetch payment instructions for `{}@{}`",
        hrn.user(),
        hrn.domain(),
    );
    PaymentInstructions::parse(
        &format!("{}@{}", hrn.user(), hrn.domain()),
        bitcoin::Network::Bitcoin,
        &hrn_resolver,
        false,
    )
    .await
    .map_err(|e| anyhow!("failed to fetch payment instructions: {:?}", e))
}

fn parse_payment_instructions(
    payment_instructions: &PaymentInstructions,
) -> Result<ProcessedBIP353, anyhow::Error> {
    let proof = payment_instructions
        .bip_353_dnssec_proof()
        .as_ref()
        .ok_or_else(|| anyhow!("bip353 dnssec proof not found"))?
        .to_lower_hex_string();

    let mut processed_bip353 = ProcessedBIP353::new(proof);

    match payment_instructions {
        PaymentInstructions::ConfigurableAmount(configurable_instructions) => {
            for method in configurable_instructions.methods() {
                let resolved_method = if let PossiblyResolvedPaymentMethod::Resolved(m) = method {
                    m
                } else {
                    continue;
                };
                let mut processed_instruction = ProcessedPaymentInstruction::new();
                if let Some(desc) = configurable_instructions.recipient_description() {
                    processed_instruction.description = Some(desc.to_owned());
                }
                match resolved_method {
                    PaymentMethod::LightningBolt12(offer) => {
                        processed_instruction.offer = Some(offer.to_string());
                        processed_bip353.instructions.push(processed_instruction);
                        log::debug!("Found offer for configurable amount: {}", offer);
                    }
                    PaymentMethod::OnChain(address) => {
                        processed_instruction.onchain = Some(address.to_string());
                        processed_bip353.instructions.push(processed_instruction);
                        log::debug!("Found onchain address for configurable amount: {}", address);
                    }
                    _ => continue,
                }
            }
        }
        PaymentInstructions::FixedAmount(fixed_instructions) => {
            for method in fixed_instructions.methods() {
                let mut processed_instruction = ProcessedPaymentInstruction::new();
                if let Some(desc) = fixed_instructions.recipient_description() {
                    processed_instruction.description = Some(desc.to_owned());
                }
                match method {
                    PaymentMethod::LightningBolt12(offer) => {
                        processed_instruction.offer = Some(offer.to_string());
                        let offchain_amount_msat = fixed_instructions
                            .ln_payment_amount()
                            .ok_or_else(|| {
                                anyhow!("Not supported: amount is for non-Bitcoin currency")
                            })?
                            .milli_sats();
                        processed_instruction.offchain_amount_msat = Some(offchain_amount_msat);
                        processed_bip353.instructions.push(processed_instruction);

                        log::debug!(
                            "Found offer:{} for fixed amount: {}msat",
                            offer,
                            offchain_amount_msat
                        );
                    }
                    PaymentMethod::OnChain(address) => {
                        processed_instruction.onchain = Some(address.to_string());
                        let onchain_amount_sat = fixed_instructions
                            .onchain_payment_amount()
                            .ok_or_else(|| anyhow!("Internal error: amount should be available"))?
                            .sats()
                            .map_err(|_| anyhow!("Onchain amount is in sub-sat precision"))?;
                        processed_instruction.onchain_amount_sat = Some(onchain_amount_sat);
                        processed_bip353.instructions.push(processed_instruction);

                        log::debug!(
                            "Found onchain address: {} for fixed amount: {}",
                            address,
                            onchain_amount_sat
                        );
                    }
                    _ => continue,
                }
            }
        }
    }

    if processed_bip353.instructions.is_empty() {
        Err(anyhow!(
            "payment instructions did not contain valid methods"
        ))
    } else {
        Ok(processed_bip353)
    }
}
