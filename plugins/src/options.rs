use anyhow::Result;
use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;

// Marker trait for possible values of options
pub trait OptionType {
    fn convert_default(value: Option<&Self>) -> Option<Value>;
}

impl OptionType for &str {
    fn convert_default(value: Option<&Self>) -> Option<Value> {
        value.map(|s| Value::String(s.to_string()))
    }
}

impl OptionType for String {
    fn convert_default(value: Option<&Self>) -> Option<Value> {
        value.map(|s| Value::String(s.clone()))
    }
}
impl OptionType for i64 {
    fn convert_default(value: Option<&Self>) -> Option<Value> {
        value.map(|i| Value::Integer(*i))
    }
}
impl OptionType for bool {
    fn convert_default(value: Option<&Self>) -> Option<Value> {
        value.map(|b| Value::Boolean(*b))
    }
}

impl OptionType for Option<String> {
    fn convert_default(_value: Option<&Self>) -> Option<Value> {
        None
    }
}

impl OptionType for Option<&str> {
    fn convert_default(_value: Option<&Self>) -> Option<Value> {
        None
    }
}
impl OptionType for Option<i64> {
    fn convert_default(_value: Option<&Self>) -> Option<Value> {
        None
    }
}
impl OptionType for Option<bool> {
    fn convert_default(_value: Option<&Self>) -> Option<Value> {
        None
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
    name: &'a str,
    default: Option<V>,
    value_type: ValueType,
    description: &'a str,
}

impl<V: OptionType> ConfigOption<'_, V> {
    pub fn build(&self) -> UntypedConfigOption {
        UntypedConfigOption {
            name: self.name.to_string(),
            value_type: self.value_type.clone(),
            default: OptionType::convert_default(self.default.as_ref()),
            value: None,
            description: self.description.to_string(),
        }
    }
}

impl ConfigOption<'_, &'static str> {
    pub const fn new_str_with_default(
        name: &'static str,
        default: &'static str,
        description: &'static str,
    ) -> Self {
        Self {
            name: name,
            default: Some(default),
            value_type: ValueType::String,
            description: description,
        }
    }
}

impl ConfigOption<'_, Option<&str>> {
    pub const fn new_str_no_default(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            default: None,
            value_type: ValueType::String,
            description,
        }
    }
}

impl ConfigOption<'_, i64> {
    pub const fn new_i64_with_default(
        name: &'static str,
        default: i64,
        description: &'static str,
    ) -> Self {
        Self {
            name: name,
            default: Some(default),
            value_type: ValueType::Integer,
            description: description,
        }
    }
}

impl ConfigOption<'_, Option<i64>> {
    pub const fn new_i64_no_default(name: &'static str, description: &'static str) -> Self {
        Self {
            name: name,
            default: None,
            value_type: ValueType::Integer,
            description: description,
        }
    }
}

impl ConfigOption<'_, Option<bool>> {
    pub const fn new_bool_no_default(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            description,
            default: None,
            value_type: ValueType::Boolean,
        }
    }
}

impl ConfigOption<'_, bool> {
    pub const fn new_bool_with_default(
        name: &'static str,
        default: bool,
        description: &'static str,
    ) -> Self {
        Self {
            name,
            description,
            default: Some(default),
            value_type: ValueType::Boolean,
        }
    }

    pub const fn new_flag(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            description,
            default: Some(false),
            value_type: ValueType::Flag,
        }
    }
}

/// An stringly typed option that is passed to
#[derive(Clone, Debug)]
pub struct UntypedConfigOption {
    name: String,
    pub(crate) value_type: ValueType,
    pub(crate) value: Option<Value>,
    default: Option<Value>,
    description: String,
}

impl UntypedConfigOption {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn default(&self) -> &Option<Value> {
        &self.default
    }
}

// When we serialize we don't add the value. This is because we only
// ever serialize when we pass the option back to lightningd during
// the getmanifest call.
impl Serialize for UntypedConfigOption {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("ConfigOption", 4)?;
        s.serialize_field("name", &self.name)?;
        match &self.default {
            Some(Value::String(ss)) => {
                s.serialize_field("default", ss)?;
            }
            Some(Value::Integer(i)) => {
                s.serialize_field("default", i)?;
            }
            Some(Value::Boolean(b)) => {
                match self.value_type {
                    ValueType::Boolean => s.serialize_field("default", b)?,
                    ValueType::Flag => {}
                    _ => {} // This should never happen
                }
            }
            _ => {}
        }
        s.serialize_field("type", &self.value_type)?;
        s.serialize_field("description", &self.description)?;
        s.end()
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
                    "type" : "flag"
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
        const _: ConfigOption<bool> = ConfigOption::new_flag("flag-option", "A flag option");
        const _: ConfigOption<bool> =
            ConfigOption::new_bool_with_default("bool-option", false, "A boolean option");
        const _: ConfigOption<Option<bool>> =
            ConfigOption::new_bool_no_default("bool-option", "A boolean option");

        const _: ConfigOption<Option<i64>> =
            ConfigOption::new_i64_no_default("integer-option", "A flag option");
        const _: ConfigOption<i64> =
            ConfigOption::new_i64_with_default("integer-option", 12, "A flag option");

        const _: ConfigOption<Option<&str>> =
            ConfigOption::new_str_no_default("integer-option", "A flag option");
        const _: ConfigOption<&str> =
            ConfigOption::new_str_with_default("integer-option", "erik", "A flag option");
    }

    #[test]
    fn test_type_serialize() {
        assert_eq!(json!(ValueType::Integer), json!("int"));
        assert_eq!(json!(ValueType::Flag), json!("flag"));
    }
}
