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
        Some("proof") if arguments.len() == 3 => {
            let p: porternet::Package = serde_json::from_value(porternet::canonical::parse(arguments[1].as_bytes())?)?;
            println!("{}", porternet::possession::proof(&unhex(&arguments[2])?, &p)?); Ok(())
        },
        Some("verify-proof") if arguments.len() == 4 => {
            let p: porternet::Package = serde_json::from_value(porternet::canonical::parse(arguments[1].as_bytes())?)?;
            println!("{}", porternet::possession::verify(&unhex(&arguments[2])?, &p, &serde_json::from_str(&arguments[3])?)?); Ok(())
        },
        Some("lodge") if arguments.len() >= 3 => {
            let p = serde_json::from_value(porternet::canonical::parse(arguments[2].as_bytes())?)?;
            let crash = if arguments.len() == 4 { porternet::CrashPoint::AfterLodgement } else { porternet::CrashPoint::None };
            let lg = porternet::PorterStore::new(&arguments[1])?.lodge(&p, 1, crash)?;
            println!("{}", serde_json::to_string(&lg)?); Ok(())
        },
        Some("outgoing") if arguments.len() == 7 => {
            let identity = PorterIdentity::from_private_bytes(&arguments[2], key(&arguments[3])?)?;
            let node = PorterNode::new(&arguments[1], identity, HashMap::from([(arguments[4].clone(), key(&arguments[5])?)]), HashMap::new())?;
            let class: UnitClass = serde_json::from_value(json!(arguments[6]))?;
            let unit = node.spool().pending()?.into_iter().find(|u| u.class == class).ok_or("no pending Unit")?;
            println!("{}", BASE64.encode(node.frame(&unit)?)); Ok(())
        },
        Some("queue") if arguments.len() == 8 => {
            let identity = PorterIdentity::from_private_bytes(&arguments[2], key(&arguments[3])?)?;
            let node = PorterNode::new(&arguments[1], identity, HashMap::from([(arguments[4].clone(), key(&arguments[5])?)]), HashMap::new())?;
            let p = serde_json::from_value(porternet::canonical::parse(arguments[6].as_bytes())?)?;
            node.queue_package(&p, &porternet::possession::proof(&unhex(&arguments[7])?, &p)?, 1)?; Ok(())
        },
        Some("establish") if arguments.len() == 4 => establish(&arguments),
        Some("vectors") if arguments.len() == 2 => vectors(&arguments[1]),
        Some("receipt-vectors") if arguments.len() == 3 => receipt_vectors(&arguments[1], &arguments[2]),
        Some("seal") if arguments.len() == 8 => seal(&arguments),
        Some("open") if arguments.len() == 6 => open(&arguments),
        Some("receive") if arguments.len() == 7 || arguments.len() == 8 => receive(&arguments),
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
    let crash = if arguments.len() == 8 {
        porternet::CrashPoint::AfterAcceptance
    } else {
        porternet::CrashPoint::None
    };
    let dispatch = node.receive_interrupted(&BASE64.decode(&arguments[5])?, 1, crash)?;
    println!("{dispatch:?}");
    Ok(())
}

fn seal(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let sender = PorterIdentity::from_private_bytes(&arguments[1], key(&arguments[2])?)?;
    let class: UnitClass = serde_json::from_value(json!(arguments[5]))?;
    let value = porternet::canonical::parse(arguments[7].as_bytes())?;
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
    let source = canonical::parse(
        vector["package_source_utf8"]
            .as_str()
            .ok_or("source")?
            .as_bytes(),
    )?;
    assert_eq!(source, vector["package"]);
    let package: Package = serde_json::from_value(source)?;
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

fn receipt_vectors(path: &str, root: &str) -> Result<(), Box<dyn std::error::Error>> {
    use porternet::{EvidenceExpectation, NativeUnit, OpenedUnit, UnitSpool};
    let vector: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let mut cases = vec![(vector["receipt"].clone(), true)];
    let mut extended = vector["receipt"].clone();
    extended["future"] = json!(true);
    cases.push((extended, true));
    for item in vector["negative"].as_array().unwrap() {
        let mut receipt = vector["receipt"].clone();
        for (key, value) in item["change"].as_object().unwrap() {
            receipt[key] = value.clone();
        }
        cases.push((receipt, false));
    }
    for (i, (receipt, expected)) in cases.iter().enumerate() {
        let spool = UnitSpool::new(std::path::Path::new(root).join(i.to_string()), "sender")?;
        spool.queue(&NativeUnit {
            protocol: "PORTER-CARRIAGE/1".into(),
            unit: "CU-vector".into(),
            class: UnitClass::Package,
            sender: "sender".into(),
            recipient: "recipient".into(),
            value: json!({"package":vector["package"], "admission":null}),
            awaits: Some(EvidenceExpectation::Package(
                vector["package"]["package"].as_str().unwrap().into(),
            )),
            created_at_ms: 1,
        })?;
        let opened = OpenedUnit {
            unit: "CU-evidence".into(),
            class: UnitClass::AcceptanceEvidence,
            sender: "recipient".into(),
            recipient: "sender".into(),
            value: receipt.clone(),
        };
        assert_eq!(
            spool
                .retain_evidence("CU-vector", &opened, 2, false)
                .is_ok(),
            *expected,
            "receipt case {i}"
        );
        assert_eq!(spool.evidence("CU-vector")?.is_some(), *expected);
    }
    println!(
        "Rust receipt: 2 positive + {} negative vectors PASS",
        cases.len() - 2
    );
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
