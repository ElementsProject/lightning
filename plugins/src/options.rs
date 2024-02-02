use serde::ser::Serializer;
use serde::Serialize;

pub mod config_type {
    pub struct Integer;
    pub struct DefaultInteger;
    pub struct String;
    pub struct DefaultString;
    pub struct Boolean;
    pub struct DefaultBoolean;
    pub struct Flag;
}

pub type IntegerConfigOption<'a> = ConfigOption<'a, config_type::Integer>;
pub type StringConfigOption<'a> = ConfigOption<'a, config_type::String>;
pub type BooleanConfigOption<'a> = ConfigOption<'a, config_type::Boolean>;

pub type DefaultIntegerConfigOption<'a> = ConfigOption<'a, config_type::DefaultInteger>;
pub type DefaultStringConfigOption<'a> = ConfigOption<'a, config_type::DefaultString>;
pub type DefaultBooleanConfigOption<'a> = ConfigOption<'a, config_type::DefaultBoolean>;
/// Config value is represented as a flag
pub type FlagConfigOption<'a> = ConfigOption<'a, config_type::Flag>;


pub trait OptionType {
    type OutputValue;
    type DefaultValue;

    fn convert_default(value: &Self::DefaultValue) -> Option<Value>;

    fn from_value(value: &Option<Value>) -> Self::OutputValue;

    fn get_value_type() -> ValueType;
}

impl OptionType for config_type::DefaultString {
    type OutputValue = String;
    type DefaultValue = &'static str;

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

impl OptionType for config_type::DefaultInteger {
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

impl OptionType for config_type::DefaultBoolean {
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

impl OptionType for config_type::Flag {
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

impl OptionType for config_type::String {
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

impl OptionType for config_type::Integer {
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
impl OptionType for config_type::Boolean {
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
pub struct ConfigOption<'a, V: OptionType> {
    /// The name of the `ConfigOption`.
    pub name: &'a str,
    /// The default value of the `ConfigOption`
    pub default: V::DefaultValue,
    pub description: &'a str,
    pub deprecated: bool,
}

impl<V: OptionType> ConfigOption<'_, V> {
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

impl DefaultStringConfigOption<'_> {
    pub const fn new_str_with_default(
        name: &'static str,
        default: &'static str,
        description: &'static str,
    ) -> Self {
        Self {
            name: name,
            default: default,
            description: description,
            deprecated: false,
        }
    }
}

impl StringConfigOption<'_> {
    pub const fn new_str_no_default(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            default: (),
            description : description,
            deprecated: false,
        }
    }
}

impl DefaultIntegerConfigOption<'_> {
    pub const fn new_i64_with_default(
        name: &'static str,
        default: i64,
        description: &'static str,
    ) -> Self {
        Self {
            name: name,
            default: default,
            description: description,
            deprecated: false,
        }
    }
}

impl IntegerConfigOption<'_> {
    pub const fn new_i64_no_default(name: &'static str, description: &'static str) -> Self {
        Self {
            name: name,
            default: (),
            description: description,
            deprecated: false,
        }
    }
}

impl BooleanConfigOption<'_> {
    pub const fn new_bool_no_default(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            description,
            default: (),
            deprecated: false,
        }
    }
}

impl DefaultBooleanConfigOption<'_> {
    pub const fn new_bool_with_default(
        name: &'static str,
        default: bool,
        description: &'static str,
    ) -> Self {
        Self {
            name,
            description,
            default: default,
            deprecated: false,
        }
    }
}

impl FlagConfigOption<'_> {
    pub const fn new_flag(name: &'static str, description: &'static str) -> Self {
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

impl<V> ConfigOption<'_, V>
where
    V: OptionType,
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
        const _: FlagConfigOption =
            ConfigOption::new_flag("flag-option", "A flag option");
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
