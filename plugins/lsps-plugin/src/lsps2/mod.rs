use cln_plugin::options;

pub mod cln;
pub mod handler;
pub mod model;

pub const OPTION_ENABLED: options::FlagConfigOption = options::ConfigOption::new_flag(
    "experimental-lsps2-service",
    "Enables lsps2 for the LSP service",
);

pub const OPTION_PROMISE_SECRET: options::StringConfigOption =
    options::ConfigOption::new_str_no_default(
        "experimental-lsps2-promise-secret",
        "A 64-character hex string that is the secret for promises",
    );

pub const DS_MAIN_KEY: &'static str = "lsps";
pub const DS_SUB_KEY: &'static str = "lsps2";
