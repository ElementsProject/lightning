use serde::ser::{SerializeStruct, Serializer};
use serde::{Serialize};

#[derive(Clone, Debug)]
pub enum Value {
    String(String),
    Integer(i64),
    Boolean(bool),
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
                        "type": "booltes",
                    }),
            ),
        ];

        for (input, expected) in tests.iter() {
            let res = serde_json::to_value(input).unwrap();
            assert_eq!(&res, expected);
        }
    }
}
