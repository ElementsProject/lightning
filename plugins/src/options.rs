use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;

#[derive(Clone, Debug)]
pub enum Value {
    String(String),
    Integer(i64),
    Boolean(bool),
    OptString,
    OptInteger,
    OptBoolean,
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
            Value::String(s) => Some(s),
            _ => None,
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

    /// Return `true` if the option is not None and `false` otherwise.
    pub fn is_some(&self) -> bool {
        match self {
            Value::String(_) => false,
            Value::Integer(_) => false,
            Value::Boolean(_) => false,
            Value::OptString => true,
            Value::OptInteger => true,
            Value::OptBoolean => true,
        }
    }
}

/// An stringly typed option that is passed to
#[derive(Clone, Debug)]
pub struct ConfigOption {
    name: String,
    pub(crate) value: Option<Value>,
    default: Value,
    description: String,
}

impl ConfigOption {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn default(&self) -> &Value {
        &self.default
    }
}

// When we serialize we don't add the value. This is because we only
// ever serialize when we pass the option back to lightningd during
// the getmanifest call.
impl Serialize for ConfigOption {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("ConfigOption", 4)?;
        s.serialize_field("name", &self.name)?;
        match &self.default {
            Value::String(ss) => {
                s.serialize_field("type", "string")?;
                s.serialize_field("default", ss)?;
            }
            Value::Integer(i) => {
                s.serialize_field("type", "int")?;
                s.serialize_field("default", i)?;
            }
            Value::Boolean(b) => {
                s.serialize_field("type", "bool")?;
                s.serialize_field("default", b)?;
            }
            Value::OptString => {
                s.serialize_field("type", "string")?;
            }
            Value::OptInteger => {
                s.serialize_field("type", "int")?;
            }
            Value::OptBoolean => {
                s.serialize_field("type", "bool")?;
            }
        }

        s.serialize_field("description", &self.description)?;
        s.end()
    }
}
impl ConfigOption {
    pub fn new(name: &str, default: Value, description: &str) -> Self {
        Self {
            name: name.to_string(),
            default,
            description: description.to_string(),
            value: None,
        }
    }

    pub fn value(&self) -> Value {
        match &self.value {
            None => self.default.clone(),
            Some(v) => v.clone(),
        }
    }

    pub fn description(&self) -> String {
        self.description.clone()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_option_serialize() {
        let tests = vec![
            (
                ConfigOption::new("name", Value::String("default".to_string()), "description"),
                json!({
                "name": "name",
                        "description":"description",
                        "default": "default",
                        "type": "string",
                    }),
            ),
            (
                ConfigOption::new("name", Value::Integer(42), "description"),
                json!({
                "name": "name",
                        "description":"description",
                        "default": 42,
                        "type": "int",
                    }),
            ),
            (
                ConfigOption::new("name", Value::Boolean(true), "description"),
                json!({
                "name": "name",
                        "description":"description",
                        "default": true,
                        "type": "bool",
                    }),
            ),
        ];

        for (input, expected) in tests.iter() {
            let res = serde_json::to_value(input).unwrap();
            assert_eq!(&res, expected);
        }
    }
}
