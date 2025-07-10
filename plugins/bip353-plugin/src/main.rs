use std::{net::SocketAddr, str::FromStr};

use anyhow::anyhow;
use bitcoin::hex::DisplayHex;
use bitcoin_payment_instructions::{
    dns_resolver::DNSHrnResolver, hrn::HumanReadableName, PaymentInstructions, PaymentMethod,
    PossiblyResolvedPaymentMethod,
};
use cln_plugin::{Builder, Plugin, RpcMethodBuilder};
use serde::Serialize;

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
struct ProcessedPaymentInstructions {
    offer: String,
    proof: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount_msat: Option<u64>,
}

async fn fetch_bip353(
    _plugin: Plugin<()>,
    args: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let hrn = parse_hrn(args)?;

    let payment_instructions = fetch_payment_instructions(&hrn).await?;

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
                .ok_or_else(|| anyhow!("invalid type for address"))?;
            HumanReadableName::from_encoded(address).map_err(|_e| anyhow!("invalid address"))
        }
        serde_json::Value::Object(map) => {
            let address = map
                .get("address")
                .ok_or_else(|| anyhow!("no address given"))?
                .as_str()
                .ok_or_else(|| anyhow!("invalid type for address"))?;
            HumanReadableName::from_encoded(address).map_err(|_e| anyhow!("invalid address"))
        }
        _ => Err(anyhow!("invalid address")),
    }
}

async fn fetch_payment_instructions(
    hrn: &HumanReadableName,
) -> Result<PaymentInstructions, anyhow::Error> {
    let cloudflare_resolver = DNSHrnResolver(SocketAddr::from_str("1.1.1.1:53")?);
    let google_resolver = DNSHrnResolver(SocketAddr::from_str("8.8.8.8:53")?);
    let quad9_resolver = DNSHrnResolver(SocketAddr::from_str("9.9.9.9:53")?);
    let dns_resolvers = vec![cloudflare_resolver, google_resolver, quad9_resolver];

    let mut last_err = String::new();

    for resolver in dns_resolvers {
        log::debug!(
            "Trying to fetch payment instructions for `{}@{}` using DNS resolver `{}`",
            hrn.user(),
            hrn.domain(),
            resolver.0
        );
        match PaymentInstructions::parse(
            &format!("{}@{}", hrn.user(), hrn.domain()),
            bitcoin::Network::Bitcoin,
            &resolver,
            false,
        )
        .await
        {
            Ok(pi) => return Ok(pi),
            Err(e) => {
                log::info!(
                    "failed to fetch payment instructions: {:?} using DNS resolver `{}`",
                    e,
                    resolver.0
                );
                last_err = format!("failed to fetch payment instructions: {:?}", e)
            }
        }
    }
    Err(anyhow!("{}", last_err))
}

fn parse_payment_instructions(
    payment_instructions: &PaymentInstructions,
) -> Result<ProcessedPaymentInstructions, anyhow::Error> {
    let proof = payment_instructions
        .bip_353_dnssec_proof()
        .as_ref()
        .ok_or_else(|| anyhow!("bip353 dnssec proof not found"))?
        .to_lower_hex_string();

    match payment_instructions {
        PaymentInstructions::ConfigurableAmount(configurable_instructions) => {
            for method in configurable_instructions.methods() {
                if let PossiblyResolvedPaymentMethod::Resolved(PaymentMethod::LightningBolt12(
                    offer,
                )) = method
                {
                    let description = configurable_instructions
                        .recipient_description()
                        .map(str::to_owned);
                    return Ok(ProcessedPaymentInstructions {
                        offer: offer.to_string(),
                        proof,
                        description,
                        amount_msat: None,
                    });
                }
            }
        }
        PaymentInstructions::FixedAmount(fixed_instructions) => {
            for method in fixed_instructions.methods() {
                if let PaymentMethod::LightningBolt12(offer) = method {
                    let amount_msat = fixed_instructions
                        .ln_payment_amount()
                        .ok_or_else(|| anyhow!("Not supported: offer is for non-Bitcoin currency"))?
                        .milli_sats();
                    let description = fixed_instructions
                        .recipient_description()
                        .map(str::to_owned);
                    return Ok(ProcessedPaymentInstructions {
                        offer: offer.to_string(),
                        proof,
                        description,
                        amount_msat: Some(amount_msat),
                    });
                }
            }
        }
    }
    Err(anyhow!("payment instructions did contain valid methods"))
}
