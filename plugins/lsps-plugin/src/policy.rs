use anyhow::{anyhow, bail};
use chrono::{Duration, Utc};
use cln_lsps::proto::lsps0::{Msat, Ppm};
use cln_lsps::proto::lsps2::{
    Lsps2PolicyGetChannelCapacityRequest, Lsps2PolicyGetChannelCapacityResponse,
    Lsps2PolicyGetInfoRequest, Lsps2PolicyGetInfoResponse, PolicyOpeningFeeParams,
};
use cln_plugin::options::{self, DefaultIntegerConfigOption};

const OPTION_MIN_FEE_MSAT: DefaultIntegerConfigOption = options::ConfigOption::new_i64_with_default(
    "lsps2-policy-min-fee-msat",
    1_000,
    "Minimum opening fee in millisatoshis charged by the LSP",
);

const OPTION_PROPORTIONAL_PPM: DefaultIntegerConfigOption =
    options::ConfigOption::new_i64_with_default(
        "lsps2-policy-proportional-ppm",
        0,
        "Proportional opening fee in parts-per-million of the payment size",
    );

const OPTION_VALID_UNTIL_HOURS: DefaultIntegerConfigOption =
    options::ConfigOption::new_i64_with_default(
        "lsps2-policy-valid-until-hours",
        1,
        "Number of hours for which the offered fee parameters are valid",
    );

const OPTION_MIN_LIFETIME: DefaultIntegerConfigOption = options::ConfigOption::new_i64_with_default(
    "lsps2-policy-min-lifetime",
    144,
    "Minimum channel lifetime in blocks that the LSP guarantees",
);

const OPTION_MAX_CLIENT_TO_SELF_DELAY: DefaultIntegerConfigOption =
    options::ConfigOption::new_i64_with_default(
        "lsps2-policy-max-client-to-self-delay",
        2016,
        "Maximum to_self_delay (in blocks) accepted from the client",
    );

const OPTION_MIN_PAYMENT_SIZE_MSAT: DefaultIntegerConfigOption =
    options::ConfigOption::new_i64_with_default(
        "lsps2-policy-min-payment-size-msat",
        1_000,
        "Minimum payment size in millisatoshis that will trigger a JIT channel opening",
    );

const OPTION_MAX_PAYMENT_SIZE_MSAT: DefaultIntegerConfigOption =
    options::ConfigOption::new_i64_with_default(
        "lsps2-policy-max-payment-size-msat",
        10_000_000_000,
        "Maximum payment size in millisatoshis that will trigger a JIT channel opening",
    );

const OPTION_CHANNEL_CAPACITY_MSAT: DefaultIntegerConfigOption =
    options::ConfigOption::new_i64_with_default(
        "lsps2-policy-channel-capacity-msat",
        10_000_000_000,
        "Channel capacity in millisatoshis to open for JIT channel requests",
    );

#[derive(Clone)]
struct State {
    min_fee_msat: Msat,
    proportional: Ppm,
    valid_until_hours: i64,
    min_lifetime: u32,
    max_client_to_self_delay: u32,
    min_payment_size_msat: Msat,
    max_payment_size_msat: Msat,
    channel_capacity_msat: u64,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    if let Some(plugin) = cln_plugin::Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(OPTION_MIN_FEE_MSAT)
        .option(OPTION_PROPORTIONAL_PPM)
        .option(OPTION_VALID_UNTIL_HOURS)
        .option(OPTION_MIN_LIFETIME)
        .option(OPTION_MAX_CLIENT_TO_SELF_DELAY)
        .option(OPTION_MIN_PAYMENT_SIZE_MSAT)
        .option(OPTION_MAX_PAYMENT_SIZE_MSAT)
        .option(OPTION_CHANNEL_CAPACITY_MSAT)
        .rpcmethod(
            "lsps2-policy-getpolicy",
            "Returns the LSP fee policy used for LSPS2 JIT channel requests",
            on_getpolicy,
        )
        .rpcmethod(
            "lsps2-policy-getchannelcapacity",
            "Returns the channel capacity the LSP will open for a given JIT channel request",
            on_getchannelcapacity,
        )
        .configure()
        .await?
    {
        let min_fee_msat = plugin.option(&OPTION_MIN_FEE_MSAT)?;
        let proportional = plugin.option(&OPTION_PROPORTIONAL_PPM)?;
        let valid_until_hours = plugin.option(&OPTION_VALID_UNTIL_HOURS)?;
        let min_lifetime = plugin.option(&OPTION_MIN_LIFETIME)?;
        let max_client_to_self_delay = plugin.option(&OPTION_MAX_CLIENT_TO_SELF_DELAY)?;
        let min_payment_size_msat = plugin.option(&OPTION_MIN_PAYMENT_SIZE_MSAT)?;
        let max_payment_size_msat = plugin.option(&OPTION_MAX_PAYMENT_SIZE_MSAT)?;
        let channel_capacity_msat = plugin.option(&OPTION_CHANNEL_CAPACITY_MSAT)?;

        if min_fee_msat < 0 {
            bail!(
                "`{}` must be non-negative, got {}",
                OPTION_MIN_FEE_MSAT.name,
                min_fee_msat
            );
        }
        if proportional < 0 || proportional > 1_000_000 {
            bail!(
                "`{}` must be between 0 and 1000000, got {}",
                OPTION_PROPORTIONAL_PPM.name,
                proportional
            );
        }
        if valid_until_hours <= 0 {
            bail!(
                "`{}` must be positive, got {}",
                OPTION_VALID_UNTIL_HOURS.name,
                valid_until_hours
            );
        }
        if min_lifetime < 0 || min_lifetime > i64::from(u32::MAX) {
            bail!(
                "`{}` must be between 0 and {}, got {}",
                OPTION_MIN_LIFETIME.name,
                u32::MAX,
                min_lifetime
            );
        }
        if max_client_to_self_delay < 0 || max_client_to_self_delay > i64::from(u32::MAX) {
            bail!(
                "`{}` must be between 0 and {}, got {}",
                OPTION_MAX_CLIENT_TO_SELF_DELAY.name,
                u32::MAX,
                max_client_to_self_delay
            );
        }
        if min_payment_size_msat < 0 {
            bail!(
                "`{}` must be non-negative, got {}",
                OPTION_MIN_PAYMENT_SIZE_MSAT.name,
                min_payment_size_msat
            );
        }
        if max_payment_size_msat <= min_payment_size_msat {
            bail!(
                "`{}` must be greater than `{}`, got {} <= {}",
                OPTION_MAX_PAYMENT_SIZE_MSAT.name,
                OPTION_MIN_PAYMENT_SIZE_MSAT.name,
                max_payment_size_msat,
                min_payment_size_msat
            );
        }
        if channel_capacity_msat <= 0 {
            bail!(
                "`{}` must be positive, got {}",
                OPTION_CHANNEL_CAPACITY_MSAT.name,
                channel_capacity_msat
            );
        }
        if channel_capacity_msat % 1_000 != 0 {
            bail!(
                "`{}` must be divisible by 1000 (whole satoshis), got {}",
                OPTION_CHANNEL_CAPACITY_MSAT.name,
                channel_capacity_msat
            );
        }

        let state = State {
            min_fee_msat: Msat::from_msat(min_fee_msat as u64),
            proportional: Ppm::from_ppm(proportional as u32),
            valid_until_hours,
            min_lifetime: min_lifetime as u32,
            max_client_to_self_delay: max_client_to_self_delay as u32,
            min_payment_size_msat: Msat::from_msat(min_payment_size_msat as u64),
            max_payment_size_msat: Msat::from_msat(max_payment_size_msat as u64),
            channel_capacity_msat: channel_capacity_msat as u64,
        };

        let plugin = plugin.start(state).await?;
        plugin.join().await
    } else {
        Ok(())
    }
}

async fn on_getpolicy(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let _req: Lsps2PolicyGetInfoRequest =
        serde_json::from_value(v).unwrap_or(Lsps2PolicyGetInfoRequest { token: None });

    let s = p.state();
    let offset = Duration::try_hours(s.valid_until_hours)
        .ok_or_else(|| anyhow!("`{}` is out of range", OPTION_VALID_UNTIL_HOURS.name))?;
    let valid_until = Utc::now()
        .checked_add_signed(offset)
        .ok_or_else(|| anyhow!("`{}` is out of range", OPTION_VALID_UNTIL_HOURS.name))?;

    let params = PolicyOpeningFeeParams {
        min_fee_msat: s.min_fee_msat,
        proportional: s.proportional,
        valid_until,
        min_lifetime: s.min_lifetime,
        max_client_to_self_delay: s.max_client_to_self_delay,
        min_payment_size_msat: s.min_payment_size_msat,
        max_payment_size_msat: s.max_payment_size_msat,
    };

    let res = Lsps2PolicyGetInfoResponse {
        policy_opening_fee_params_menu: vec![params],
        client_rejected: false,
    };
    Ok(serde_json::to_value(res)?)
}

async fn on_getchannelcapacity(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let _req: Lsps2PolicyGetChannelCapacityRequest = serde_json::from_value(v)?;

    let res = Lsps2PolicyGetChannelCapacityResponse {
        channel_capacity_msat: Some(p.state().channel_capacity_msat),
    };
    Ok(serde_json::to_value(res)?)
}
