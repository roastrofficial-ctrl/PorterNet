//! PORTER-CANONICAL-JSON/1: strict decoding followed by RFC 8785 serialization.
use std::collections::HashSet;
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Number, Value, value::RawValue};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

fn number(value: f64) -> Result<Value> {
    if !value.is_finite() {
        return Err(Error::Invalid("non-finite JSON number".into()));
    }
    // Retain small integral values as integers for typed protocol envelopes.
    // All numbers have already entered the same binary64 numeric model.
    if value.abs() <= 9_007_199_254_740_991.0 && value.fract() == 0.0 {
        return Ok(Value::from(value as i64));
    }
    Ok(Value::Number(
        Number::from_f64(value).expect("finite number"),
    ))
}

pub fn bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    // serde_json::to_value and nested serde_jcs serialization can replace a
    // non-finite float with null. Preserve its type until validation (D-007).
    let tree = serde_value::to_value(value).map_err(|e| Error::Invalid(e.to_string()))?;
    validate_tree(&tree)?;
    Ok(serde_jcs::to_vec(&tree)?)
}

fn validate_tree(value: &serde_value::Value) -> Result<()> {
    use serde_value::Value as V;
    match value {
        V::F32(n) if !n.is_finite() => return Err(Error::Invalid("non-finite JSON number".into())),
        V::F64(n) if !n.is_finite() => return Err(Error::Invalid("non-finite JSON number".into())),
        V::Seq(values) => {
            for value in values {
                validate_tree(value)?;
            }
        }
        V::Map(values) => {
            for (key, value) in values {
                if !matches!(key, V::String(_)) {
                    return Err(Error::Invalid("JSON object names must be strings".into()));
                }
                validate_tree(value)?;
            }
        }
        V::Option(Some(value)) | V::Newtype(value) => validate_tree(value)?,
        _ => {}
    }
    Ok(())
}

/// Reject duplicate decoded keys before any mapping can discard them.
struct Members(Vec<(String, Box<RawValue>)>);
impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct MemberVisitor;
        impl<'de> Visitor<'de> for MemberVisitor {
            type Value = Members;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Members, A::Error> {
                let mut seen = HashSet::new();
                let mut members = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, Box<RawValue>>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate JSON object name"));
                    }
                    members.push((key, value));
                }
                Ok(Members(members))
            }
        }
        deserializer.deserialize_map(MemberVisitor)
    }
}

fn decode(raw: &RawValue, depth: usize) -> Result<Value> {
    if depth > 128 {
        return Err(Error::Invalid("JSON nesting exceeds bound".into()));
    }
    let text = raw.get();
    match text.as_bytes().first() {
        Some(b'{') => {
            let Members(members) = serde_json::from_str(text)?;
            members
                .into_iter()
                .map(|(key, raw)| Ok((key, decode(&raw, depth + 1)?)))
                .collect::<Result<serde_json::Map<_, _>>>()
                .map(Value::Object)
        }
        Some(b'[') => {
            let values: Vec<Box<RawValue>> = serde_json::from_str(text)?;
            values
                .iter()
                .map(|raw| decode(raw, depth + 1))
                .collect::<Result<Vec<_>>>()
                .map(Value::Array)
        }
        Some(b'-' | b'0'..=b'9') => number(
            text.parse::<f64>()
                .map_err(|_| Error::Invalid("JSON number".into()))?,
        ),
        _ => Ok(serde_json::from_str(text)?),
    }
}

pub fn parse(input: &[u8]) -> Result<Value> {
    // RawValue validates JSON grammar while retaining numeric tokens for a
    // correctly rounded binary64 parse, including integers larger than u64.
    let raw: Box<RawValue> = serde_json::from_slice(input)?;
    decode(&raw, 0)
}

pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    let digest = Sha256::digest(bytes(value)?);
    Ok(format!("sha256:{digest:x}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    #[test]
    fn canonical_objects_are_recursively_key_sorted() {
        assert_eq!(
            super::bytes(&json!({"z":{"b":2,"a":1},"a":0})).unwrap(),
            br#"{"a":0,"z":{"a":1,"b":2}}"#
        );
    }
}
