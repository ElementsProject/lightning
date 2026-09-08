use std::cell::Cell;
use std::fmt;

use serde::de::{self, DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// Maximum number of JSON nodes a YAML request body may deserialize to.
const MAX_YAML_NODES: usize = 100_000;

/// Maximum total size (in bytes) of the strings materialized from a YAML
/// request body.
///
/// Bounding the node count alone is not enough: a single large anchored
/// scalar can be aliased many times and each reference allocates a fresh
/// copy, so the materialized size grows with the number of aliases rather
/// than with the number of nodes.
const MAX_YAML_BYTES: usize = 8 * 1024 * 1024;

/* Deserialize YAML into a `serde_json::Map`, bounding both the number of
 * nodes and the total size of materialized strings so that anchor/alias
 * expansion cannot exhaust memory. */
pub fn from_slice(bytes: &[u8]) -> Result<Map<String, Value>, serde_yaml_ng::Error> {
    let nodes = Cell::new(0);
    let byte_count = Cell::new(0);
    let budget = Budget {
        nodes: &nodes,
        bytes: &byte_count,
    };
    let value = BoundedValue { budget }
        .deserialize(serde_yaml_ng::Deserializer::from_slice(bytes))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(serde_yaml_ng::Error::custom(
            "expected a mapping at the top level",
        )),
    }
}

#[derive(Clone, Copy)]
struct Budget<'a> {
    nodes: &'a Cell<usize>,
    bytes: &'a Cell<usize>,
}

impl<'a> Budget<'a> {
    fn bump_node<E>(&self) -> Result<(), E>
    where
        E: de::Error,
    {
        self.nodes.set(self.nodes.get() + 1);
        if self.nodes.get() > MAX_YAML_NODES {
            return Err(E::custom(format!(
                "YAML body expands to more than {MAX_YAML_NODES} nodes"
            )));
        }
        Ok(())
    }

    fn add_bytes<E>(&self, n: usize) -> Result<(), E>
    where
        E: de::Error,
    {
        self.bytes.set(self.bytes.get() + n);
        if self.bytes.get() > MAX_YAML_BYTES {
            return Err(E::custom(format!(
                "YAML body expands to more than {MAX_YAML_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

struct BoundedVisitor<'a> {
    budget: Budget<'a>,
}

struct BoundedValue<'a> {
    budget: Budget<'a>,
}

impl<'de, 'a> DeserializeSeed<'de> for BoundedValue<'a> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(BoundedVisitor {
            budget: self.budget,
        })
    }
}

impl<'de, 'a> Visitor<'de> for BoundedVisitor<'a> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a bounded JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E>
    where
        E: de::Error,
    {
        self.budget.bump_node::<E>()?;
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E>
    where
        E: de::Error,
    {
        self.budget.bump_node::<E>()?;
        Ok(Value::Number(Number::from(v)))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E>
    where
        E: de::Error,
    {
        self.budget.bump_node::<E>()?;
        Ok(Value::Number(Number::from(v)))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E>
    where
        E: de::Error,
    {
        self.budget.bump_node::<E>()?;
        Ok(Number::from_f64(v).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E>
    where
        E: de::Error,
    {
        self.budget.add_bytes::<E>(v.len())?;
        self.budget.bump_node::<E>()?;
        Ok(Value::String(v.to_owned()))
    }

    fn visit_none<E>(self) -> Result<Value, E>
    where
        E: de::Error,
    {
        self.budget.bump_node::<E>()?;
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.budget.bump_node::<D::Error>()?;
        BoundedValue {
            budget: self.budget,
        }
        .deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Value, E>
    where
        E: de::Error,
    {
        self.budget.bump_node::<E>()?;
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        self.budget.bump_node::<A::Error>()?;
        let mut vec = Vec::new();
        while let Some(elem) = access.next_element_seed(BoundedValue {
            budget: self.budget,
        })? {
            vec.push(elem);
        }
        Ok(Value::Array(vec))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        self.budget.bump_node::<A::Error>()?;
        let mut map = Map::new();
        while let Some((key, value)) = access.next_entry_seed(
            BoundedKey {
                budget: self.budget,
            },
            BoundedValue {
                budget: self.budget,
            },
        )? {
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }
}

struct KeyVisitor<'a> {
    budget: Budget<'a>,
}

struct BoundedKey<'a> {
    budget: Budget<'a>,
}

impl<'de, 'a> DeserializeSeed<'de> for BoundedKey<'a> {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<String, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(KeyVisitor {
            budget: self.budget,
        })
    }
}

impl<'de, 'a> Visitor<'de> for KeyVisitor<'a> {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string key")
    }

    fn visit_str<E>(self, v: &str) -> Result<String, E>
    where
        E: de::Error,
    {
        self.budget.add_bytes::<E>(v.len())?;
        self.budget.bump_node::<E>()?;
        Ok(v.to_owned())
    }
}
