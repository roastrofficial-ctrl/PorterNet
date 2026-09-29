#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::env;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use porternet::{NativeFrame, PorterIdentity, PorterNode, UnitClass};
use serde_json::{Value, json};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("establish") if arguments.len() == 4 => establish(&arguments),
        Some("vectors") if arguments.len() == 2 => vectors(&arguments[1]),
        Some("seal") if arguments.len() == 8 => seal(&arguments),
        Some("open") if arguments.len() == 6 => open(&arguments),
        Some("receive") if arguments.len() == 7 => receive(&arguments),
        _ => Err("native-fixture vectors FILE | establish ROOT INTRODUCTION_JSON KEY_HEX | seal FROM PRIVATE TO PUBLIC CLASS UNIT JSON | open TO PRIVATE FROM PUBLIC FRAME | receive TO PRIVATE FROM PUBLIC FRAME ROOT".into()),
    }
}

// Experiment entry point: unlike `open`, this crosses the actual node dispatcher.
// No Host process or Collection operation is reachable from arrival.
fn receive(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let recipient = PorterIdentity::from_private_bytes(&arguments[1], key(&arguments[2])?)?;
    let peers = HashMap::from([(arguments[3].clone(), key(&arguments[4])?)]);
    let roots = HashMap::from([(arguments[3].clone(), "IN-fixture".into())]);
    let node = PorterNode::new(&arguments[6], recipient, peers, roots)?;
    let dispatch = node.receive(&BASE64.decode(&arguments[5])?, 1)?;
    println!("{dispatch:?}");
    Ok(())
}

fn seal(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let sender = PorterIdentity::from_private_bytes(&arguments[1], key(&arguments[2])?)?;
    let class: UnitClass = serde_json::from_value(json!(arguments[5]))?;
    let value: Value = serde_json::from_str(&arguments[7])?;
    let frame = NativeFrame::seal(
        &value,
        &sender,
        &arguments[3],
        key(&arguments[4])?,
        class,
        &arguments[6],
    )?;
    println!("{}", BASE64.encode(frame));
    Ok(())
}

fn open(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let recipient = PorterIdentity::from_private_bytes(&arguments[1], key(&arguments[2])?)?;
    let peers = HashMap::from([(arguments[3].clone(), key(&arguments[4])?)]);
    let frame = BASE64.decode(&arguments[5])?;
    let opened = NativeFrame::open(&frame, &recipient, &peers)?;
    println!("{}", serde_json::to_string(&opened.value)?);
    Ok(())
}

fn key(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(BASE64
        .decode(value)?
        .try_into()
        .map_err(|_| "native key is not 32 bytes")?)
}

fn unhex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if value.len() % 2 != 0 || !value.is_ascii() {
        return Err("invalid hex".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&value[i..i + 2], 16)?))
        .collect()
}

fn vectors(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    use porternet::{Package, canonical, possession};
    let vector: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let package: Package = serde_json::from_value(vector["package"].clone())?;
    let capability = unhex(vector["capability_hex"].as_str().ok_or("key")?)?;
    let encoded = canonical::bytes(&package)?;
    assert_eq!(
        encoded,
        vector["canonical_package_utf8"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
    assert_eq!(
        encoded,
        unhex(vector["canonical_package_hex"].as_str().unwrap())?
    );
    let digest = canonical::digest(&package)?;
    assert_eq!(digest, vector["digest_text"]);
    let hex = digest.strip_prefix("sha256:").unwrap();
    assert_eq!(hex, vector["sha256_hex"]);
    assert_eq!(
        hex.as_bytes(),
        unhex(vector["hmac_input_hex"].as_str().unwrap())?
    );
    assert_eq!(vector["hmac_algorithm"], "HMAC-SHA256");
    let proof = possession::proof(&capability, &package)?;
    assert_eq!(proof, vector["admission"]);
    assert_eq!(
        proof["proof"].as_str().unwrap(),
        format!("hmac-sha256:{}", vector["proof_hex"].as_str().unwrap())
    );
    assert!(possession::verify(&capability, &package, &proof)?);
    let negative = vector["negative"].as_array().unwrap();
    for item in negative {
        let changes = item["change"].as_object().unwrap();
        assert_eq!(changes.len(), 1);
        let mut case = vector.clone();
        for (name, value) in changes {
            case[name] = value.clone();
        }
        let package: Package = serde_json::from_value(case["package"].clone())?;
        let capability = unhex(case["capability_hex"].as_str().unwrap())?;
        assert_eq!(
            possession::verify(&capability, &package, &case["admission"])?,
            item["expected"].as_bool().unwrap(),
            "{}",
            item["name"]
        );
    }
    println!(
        "Rust possession: 1 positive + {} negative vectors PASS",
        negative.len()
    );
    Ok(())
}

fn establish(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Explicit local provisioning, never part of arrival or proof verification.
    let introduction: porternet::Introduction = serde_json::from_str(&arguments[2])?;
    porternet::StandingStore::new(&arguments[1])?
        .establish(&introduction, &unhex(&arguments[3])?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn normative_possession_vectors() {
        super::vectors(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/spec/vectors/package-possession-1.json"
        ))
        .unwrap();
    }
}
