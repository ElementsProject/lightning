//! This module contains all logic related to `ConfigOption`'s that can be
//! set in Core Lightning. The [Core Lightning documentation](https://docs.corelightning.org/reference/lightningd-config)
//! describes how the user can specify configuration. This can be done using
//! a command-line argument or by specifying the value in the `config`-file.
//!
//! ## A simple example
//!
//! A config option can either be specified using helper-methods or explicitly.
//!
//! ```no_run
//! use anyhow::Result;
//!
//! use cln_plugin::ConfiguredPlugin;
//! use cln_plugin::Builder;
//! use cln_plugin::options::{StringConfigOption, DefaultStringConfigOption};
//!
//! const STRING_OPTION : StringConfigOption =
//!     StringConfigOption::new_str_no_default(
//!         "string-option",
//!         "A config option of type string with no default"
//! );
//!
//! const DEFAULT_STRING_OPTION : DefaultStringConfigOption =
//!     DefaultStringConfigOption::new_str_with_default(
//!         "string-option",
//!         "bitcoin",
//!         "A config option which uses 'bitcoin when as a default"
//! );
//!
//! #[tokio::main]
//! async fn main() -> Result<()>{
//!     let configured_plugin = Builder::new(tokio::io::stdin(), tokio::io::stdout())
//!         .option(STRING_OPTION)
//!         .option(DEFAULT_STRING_OPTION)
//!         .configure()
//!         .await?;
//!     
//!     let configured_plugin :ConfiguredPlugin<(),_,_> = match configured_plugin {
//!         Some(plugin) => plugin,
//!         None => return Ok(())       // Core Lightning was started with --help
//!     };
//!
//!     // Note the types here.
//!     // In `string_option` the developer did not specify a default and `None`
//!     // will be returned if the user doesn't specify a configuration.
//!     //
//!     // In `default_string_option` the developer set a default-value.
//!     // If the user doesn't specify a configuration the `String` `"bitcoin"`
//!     // will be returned.
//!     let string_option : Option<String> = configured_plugin
//!         .option(&STRING_OPTION)
//!         .expect("Failed to configure option");
//!     let default_string_option : String = configured_plugin
//!         .option(&DEFAULT_STRING_OPTION)
//!         .expect("Failed to configure option");
//!
//!     // You can start the plugin here
//!     // ...
//!
//!     Ok(())
//! }
//!
//! ```
//!
//! ## Explicit initialization
//!
//! A `ConfigOption` can be initialized explicitly or using one of the helper methods.
//! The two code-samples below are equivalent. The explicit version is more verbose
//! but allows specifying additional information.
//!
//! ```
//! use cln_plugin::options::{StringConfigOption};
//!
//! const STRING_OPTION : StringConfigOption = StringConfigOption {
//!     name : "string-option",
//!     default : (), // We provide no default here
//!     description : "A config option of type string that takes no default",
//!     deprecated : false,     // Option is not deprecated
//! };
//! ```
//!
//! ```
//! use cln_plugin::options::{StringConfigOption};
//! // This code is equivalent
//! const STRING_OPTION_EQ : StringConfigOption = StringConfigOption::new_str_no_default(
//!     "string-option-eq",
//!     "A config option of type string that takes no default"
//! );
//! ```
//!
//! ## Required options
//!
//! In some cases you want to require the user to specify a value.
//! This can be achieved using [`crate::ConfiguredPlugin::disable`].
//!
//! ```no_run
//! use anyhow::Result;
//!
//! use cln_plugin::ConfiguredPlugin;
//! use cln_plugin::Builder;
//! use cln_plugin::options::{IntegerConfigOption};
//!
//! const WEBPORTAL_PORT : IntegerConfigOption = IntegerConfigOption::new_i64_no_default(
//!     "webportal-port",
//!     "The port on which the web-portal will be exposed"
//! );
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let configured_plugin = Builder::new(tokio::io::stdin(), tokio::io::stdout())
//!         .option(WEBPORTAL_PORT)
//!         .configure()
//!         .await?;
//!
//!     let configured_plugin :ConfiguredPlugin<(),_,_> = match configured_plugin {
//!         Some(plugin) => plugin,
//!         None => return Ok(())       // Core Lightning was started with --help
//!     };
//!
//!     let webportal_port : i64 = match(configured_plugin.option(&WEBPORTAL_PORT)?) {
//!         Some(port) => port,
//!         None => {
//!             return configured_plugin.disable("No value specified for webportal-port").await
//!         }
//!     };
//!
//!     // Start the plugin here
//!     //..
//!
//!     Ok(())
//! }
//! ```
use serde::ser::Serializer;
use serde::Serialize;

pub mod config_type {
    #[derive(Clone, Debug)]
    pub struct Integer;
    #[derive(Clone, Debug)]
    pub struct DefaultInteger;
    #[derive(Clone, Debug)]
    pub struct String;
    #[derive(Clone, Debug)]
    pub struct DefaultString;
    #[derive(Clone, Debug)]
    pub struct Boolean;
    #[derive(Clone, Debug)]
    pub struct DefaultBoolean;
    #[derive(Clone, Debug)]
    pub struct Flag;
}

/// Config values are represented as an i64. No default is used
pub type IntegerConfigOption<'a> = ConfigOption<'a, config_type::Integer>;
/// Config values are represented as a String. No default is used.
pub type StringConfigOption<'a> = ConfigOption<'a, config_type::String>;
/// Config values are represented as a boolean. No default is used.
pub type BooleanConfigOption<'a> = ConfigOption<'a, config_type::Boolean>;
/// Config values are repsentedas an i64. A default is used
pub type DefaultIntegerConfigOption<'a> = ConfigOption<'a, config_type::DefaultInteger>;
/// Config values are repsentedas an String. A default is used
pub type DefaultStringConfigOption<'a> = ConfigOption<'a, config_type::DefaultString>;
/// Config values are repsentedas an bool. A default is used
pub type DefaultBooleanConfigOption<'a> = ConfigOption<'a, config_type::DefaultBoolean>;
/// Config value is represented as a flag
pub type FlagConfigOption<'a> = ConfigOption<'a, config_type::Flag>;

pub trait OptionType<'a> {
    type OutputValue;
    type DefaultValue;

    fn convert_default(value: &Self::DefaultValue) -> Option<Value>;

    fn from_value(value: &Option<Value>) -> Self::OutputValue;

    fn get_value_type() -> ValueType;
}

impl<'a> OptionType<'a> for config_type::DefaultString {
    type OutputValue = String;
    type DefaultValue = &'a str;

    fn convert_default(value: &Self::DefaultValue) -> Option<Value> {
        Some(Value::String(value.to_string()))
    }

    fn from_value(value: &Option<Value>) -> Self::OutputValue {
        match value {
            Some(Value::String(s)) => s.to_string(),
            _ => panic!("Type mismatch. Expected string but found {:?}", value),
        }
    }

    fn get_value_type() -> ValueType {
        ValueType::String
    }
}

impl<'a> OptionType<'a> for config_type::DefaultInteger {
    type OutputValue = i64;
    type DefaultValue = i64;

    fn convert_default(value: &Self::DefaultValue) -> Option<Value> {
        Some(Value::Integer(*value))
    }

    fn from_value(value: &Option<Value>) -> i64 {
        match value {
            Some(Value::Integer(i)) => *i,
            _ => panic!("Type mismatch. Expected Integer but found {:?}", value),
        }
    }

    fn get_value_type() -> ValueType {
        ValueType::Integer
    }
}

impl<'a> OptionType<'a> for config_type::DefaultBoolean {
    type OutputValue = bool;
    type DefaultValue = bool;

    fn convert_default(value: &bool) -> Option<Value> {
        Some(Value::Boolean(*value))
    }
    fn from_value(value: &Option<Value>) -> bool {
        match value {
            Some(Value::Boolean(b)) => *b,
            _ => panic!("Type mismatch. Expected Boolean but found {:?}", value),
        }
    }

    fn get_value_type() -> ValueType {
        ValueType::Boolean
    }
}

impl<'a> OptionType<'a> for config_type::Flag {
    type OutputValue = bool;
    type DefaultValue = ();

    fn convert_default(_value: &()) -> Option<Value> {
        Some(Value::Boolean(false))
    }

    fn from_value(value: &Option<Value>) -> bool {
        match value {
            Some(Value::Boolean(b)) => *b,
            _ => panic!("Type mismatch. Expected Boolean but found {:?}", value),
        }
    }

    fn get_value_type() -> ValueType {
        ValueType::Flag
    }
}

impl<'a> OptionType<'a> for config_type::String {
    type OutputValue = Option<String>;
    type DefaultValue = ();

    fn convert_default(_value: &()) -> Option<Value> {
        None
    }

    fn from_value(value: &Option<Value>) -> Option<String> {
        match value {
            Some(Value::String(s)) => Some(s.to_string()),
            None => None,
            _ => panic!(
                "Type mismatch. Expected Option<string> but found {:?}",
                value
            ),
        }
    }

    fn get_value_type() -> ValueType {
        ValueType::String
    }
}

impl<'a> OptionType<'a> for config_type::Integer {
    type OutputValue = Option<i64>;
    type DefaultValue = ();

    fn convert_default(_value: &()) -> Option<Value> {
        None
    }

    fn from_value(value: &Option<Value>) -> Self::OutputValue {
        match value {
            Some(Value::Integer(i)) => Some(*i),
            None => None,
            _ => panic!(
                "Type mismatch. Expected Option<Integer> but found {:?}",
                value
            ),
        }
    }

    fn get_value_type() -> ValueType {
        ValueType::Integer
    }
}
impl<'a> OptionType<'a> for config_type::Boolean {
    type OutputValue = Option<bool>;
    type DefaultValue = ();

    fn convert_default(_value: &()) -> Option<Value> {
        None
    }
    fn from_value(value: &Option<Value>) -> Self::OutputValue {
        match value {
            Some(Value::Boolean(b)) => Some(*b),
            None => None,
            _ => panic!(
                "Type mismatch. Expected Option<Boolean> but found {:?}",
                value
            ),
        }
    }

    fn get_value_type() -> ValueType {
        ValueType::Boolean
    }
}

#[derive(Clone, Debug, Serialize)]
pub enum ValueType {
    #[serde(rename = "string")]
    String,
    #[serde(rename = "int")]
    Integer,
    #[serde(rename = "bool")]
    Boolean,
    #[serde(rename = "flag")]
    Flag,
}

#[derive(Clone, Debug)]
pub enum Value {
    String(String),
    Integer(i64),
    Boolean(bool),
}

impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Value::String(s) => serializer.serialize_str(s),
            Value::Integer(i) => serializer.serialize_i64(*i),
            Value::Boolean(b) => serializer.serialize_bool(*b),
        }
    }
}

impl Value {
    /// Returns true if the `Value` is a String. Returns false otherwise.
    ///
    /// For any Value on which `is_string` returns true, `as_str` is guaranteed
    /// to return the string slice.
    pub fn is_string(&self) -> bool {
        self.as_str().is_some()
    }

    /// If the `Value` is a String, returns the associated str. Returns None
    /// otherwise.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(&s),
            Value::Integer(_) => None,
            Value::Boolean(_) => None,
        }
    }

    /// Returns true if the `Value` is an integer between `i64::MIN` and
    /// `i64::MAX`.
    ///
    /// For any Value on which `is_i64` returns true, `as_i64` is guaranteed to
    /// return the integer value.
    pub fn is_i64(&self) -> bool {
        self.as_i64().is_some()
    }

    /// If the `Value` is an integer, represent it as i64. Returns
    /// None otherwise.
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Value::Integer(n) => Some(n),
            _ => None,
        }
    }

    /// Returns true if the `Value` is a Boolean. Returns false otherwise.
    ///
    /// For any Value on which `is_boolean` returns true, `as_bool` is
    /// guaranteed to return the boolean value.
    pub fn is_boolean(&self) -> bool {
        self.as_bool().is_some()
    }

    /// If the `Value` is a Boolean, returns the associated bool. Returns None
    /// otherwise.
    pub fn as_bool(&self) -> Option<bool> {
        match *self {
            Value::Boolean(b) => Some(b),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConfigOption<'a, V: OptionType<'a>> {
    /// The name of the `ConfigOption`.
    pub name: &'a str,
    /// The default value of the `ConfigOption`
    pub default: V::DefaultValue,
    pub description: &'a str,
    pub deprecated: bool,
}

impl<'a, V: OptionType<'a>> ConfigOption<'a, V> {
    pub fn build(&self) -> UntypedConfigOption {
        UntypedConfigOption {
            name: self.name.to_string(),
            value_type: V::get_value_type(),
            default: <V as OptionType>::convert_default(&self.default),
            description: self.description.to_string(),
            deprecated: self.deprecated,
        }
    }
}

impl<'a> DefaultStringConfigOption<'a> {
    pub const fn new_str_with_default(
        name: &'a str,
        default: &'a str,
        description: &'a str,
    ) -> Self {
        Self {
            name: name,
            default: default,
            description: description,
            deprecated: false,
        }
    }
}

impl<'a> StringConfigOption<'a> {
    pub const fn new_str_no_default(name: &'a str, description: &'a str) -> Self {
        Self {
            name,
            default: (),
            description: description,
            deprecated: false,
        }
    }
}

impl<'a> DefaultIntegerConfigOption<'a> {
    pub const fn new_i64_with_default(name: &'a str, default: i64, description: &'a str) -> Self {
        Self {
            name: name,
            default: default,
            description: description,
            deprecated: false,
        }
    }
}

impl<'a> IntegerConfigOption<'a> {
    pub const fn new_i64_no_default(name: &'a str, description: &'a str) -> Self {
        Self {
            name: name,
            default: (),
            description: description,
            deprecated: false,
        }
    }
}

impl<'a> BooleanConfigOption<'a> {
    pub const fn new_bool_no_default(name: &'a str, description: &'a str) -> Self {
        Self {
            name,
            description,
            default: (),
            deprecated: false,
        }
    }
}

impl<'a> DefaultBooleanConfigOption<'a> {
    pub const fn new_bool_with_default(name: &'a str, default: bool, description: &'a str) -> Self {
        Self {
            name,
            description,
            default: default,
            deprecated: false,
        }
    }
}

impl<'a> FlagConfigOption<'a> {
    pub const fn new_flag(name: &'a str, description: &'a str) -> Self {
        Self {
            name,
            description,
            default: (),
            deprecated: false,
        }
    }
}

fn is_false(b: &bool) -> bool {
    *b == false
}

/// An stringly typed option that is passed to
#[derive(Clone, Debug, Serialize)]
pub struct UntypedConfigOption {
    name: String,
    #[serde(rename = "type")]
    pub(crate) value_type: ValueType,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<Value>,
    description: String,
    #[serde(skip_serializing_if = "is_false")]
    deprecated: bool,
}

impl UntypedConfigOption {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn default(&self) -> &Option<Value> {
        &self.default
    }
}

impl<'a, V> ConfigOption<'a, V>
where
    V: OptionType<'a>,
{
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_option_serialize() {
        let tests = vec![
            (
                ConfigOption::new_str_with_default("name", "default", "description").build(),
                json!({
                "name": "name",
                        "description":"description",
                        "default": "default",
                        "type": "string",
                    }),
            ),
            (
                ConfigOption::new_i64_with_default("name", 42, "description").build(),
                json!({
                "name": "name",
                        "description":"description",
                        "default": 42,
                        "type": "int",
                    }),
            ),
            (
                ConfigOption::new_bool_with_default("name", true, "description").build(),
                json!({
                "name": "name",
                        "description":"description",
                        "default": true,
                        "type": "bool",
                    }),
            ),
            (
                ConfigOption::new_flag("name", "description").build(),
                json!({
                    "name" : "name",
                    "description": "description",
                    "type" : "flag",
                    "default" : false
                }),
            ),
        ];

        for (input, expected) in tests.iter() {
            let res = serde_json::to_value(input).unwrap();
            assert_eq!(&res, expected);
        }
    }

    #[test]
    fn const_config_option() {
        // The main goal of this test is to test compilation

        // Initiate every type as a const
        const _: FlagConfigOption = ConfigOption::new_flag("flag-option", "A flag option");
        const _: DefaultBooleanConfigOption =
            ConfigOption::new_bool_with_default("bool-option", false, "A boolean option");
        const _: BooleanConfigOption =
            ConfigOption::new_bool_no_default("bool-option", "A boolean option");

        const _: IntegerConfigOption =
            ConfigOption::new_i64_no_default("integer-option", "A flag option");
        const _: DefaultIntegerConfigOption =
            ConfigOption::new_i64_with_default("integer-option", 12, "A flag option");

        const _: StringConfigOption =
            ConfigOption::new_str_no_default("integer-option", "A flag option");
        const _: DefaultStringConfigOption =
            ConfigOption::new_str_with_default("integer-option", "erik", "A flag option");
    }

    #[test]
    fn test_type_serialize() {
        assert_eq!(json!(ValueType::Integer), json!("int"));
        assert_eq!(json!(ValueType::Flag), json!("flag"));
    }
}
