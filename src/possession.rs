//! Normative PACKAGE-POSSESSION-1 binding. No legacy proof representation.
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{Package, Result, canonical};

type HmacSha256 = Hmac<Sha256>;
pub const VOCABULARY: &str = "PORTER-INTRODUCTION/1";

pub fn proof(capability: &[u8], package: &Package) -> Result<Value> {
    let digest = canonical::digest(package)?;
    let mut mac = HmacSha256::new_from_slice(capability).expect("HMAC accepts any key length");
    mac.update(
        digest
            .strip_prefix("sha256:")
            .expect("digest prefix")
            .as_bytes(),
    );
    let hex: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(json!({"vocabulary": VOCABULARY, "package_digest": digest,
        "proof": format!("hmac-sha256:{hex}")}))
}

pub fn verify(capability: &[u8], package: &Package, evidence: &Value) -> Result<bool> {
    let Some(object) = evidence.as_object() else {
        return Ok(false);
    };
    let digest = canonical::digest(package)?;
    if object.get("vocabulary").and_then(Value::as_str) != Some(VOCABULARY)
        || object.get("package_digest").and_then(Value::as_str) != Some(digest.as_str())
    {
        return Ok(false);
    }
    let Some(hex) = object
        .get("proof")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("hmac-sha256:"))
    else {
        return Ok(false);
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Ok(false);
    }
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("validated hex"))
        .collect();
    let mut mac = HmacSha256::new_from_slice(capability).expect("HMAC accepts any key length");
    mac.update(
        digest
            .strip_prefix("sha256:")
            .expect("digest prefix")
            .as_bytes(),
    );
    Ok(mac.verify_slice(&bytes).is_ok())
}
