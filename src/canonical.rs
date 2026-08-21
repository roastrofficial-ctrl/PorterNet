use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::Result;

pub fn bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    Ok(serde_json::to_vec(&sorted(value))?)
}

fn sorted(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sorted).collect()),
        Value::Object(values) => {
            let mut entries: Vec<_> = values.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect(),
            )
        }
        scalar => scalar,
    }
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
        let value = json!({"z":{"b":2,"a":1},"a":0});
        assert_eq!(
            String::from_utf8(super::bytes(&value).unwrap()).unwrap(),
            r#"{"a":0,"z":{"a":1,"b":2}}"#
        );
    }
}
