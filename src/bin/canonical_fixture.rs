#![forbid(unsafe_code)]
use porternet::{Package, canonical, possession};
use serde_json::Value;
use std::{env, fs};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn unhex(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 || !text.is_ascii() {
        return Err("invalid hex".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}
fn vectors(path: &str) -> Result<()> {
    let suite: Value = serde_json::from_slice(&fs::read(path)?)?;
    let key = unhex(suite["capability_hex"].as_str().unwrap())?;
    let positive = suite["positive"].as_array().unwrap();
    let negative = suite["negative"].as_array().unwrap();
    let mut observed = std::collections::HashMap::new();
    for case in positive {
        let name = case["name"].as_str().unwrap();
        let value = canonical::parse(case["input_utf8"].as_str().unwrap().as_bytes())?;
        let encoded = canonical::bytes(&value)?;
        assert_eq!(
            encoded,
            unhex(case["canonical_hex"].as_str().unwrap())?,
            "{name}"
        );
        assert_eq!(
            encoded,
            case["canonical_utf8"].as_str().unwrap().as_bytes(),
            "{name}"
        );
        assert_eq!(
            canonical::digest(&value)?,
            format!("sha256:{}", case["sha256_hex"].as_str().unwrap()),
            "{name}"
        );
        assert_eq!(
            canonical::bytes(&canonical::parse(&encoded)?)?,
            encoded,
            "idempotence {name}"
        );
        let package: Package = serde_json::from_value(canonical::parse(
            case["package_input_utf8"].as_str().unwrap().as_bytes(),
        )?)?;
        assert_eq!(
            canonical::bytes(&package)?,
            unhex(case["package_canonical_hex"].as_str().unwrap())?,
            "Package {name}"
        );
        assert_eq!(
            canonical::digest(&package)?,
            case["package_digest"],
            "digest {name}"
        );
        assert_eq!(
            possession::proof(&key, &package)?,
            case["admission"],
            "proof {name}"
        );
        assert!(possession::verify(&key, &package, &case["admission"])?);
        observed.insert(name, encoded);
    }
    for case in negative {
        assert!(
            canonical::parse(&unhex(case["input_hex"].as_str().unwrap())?).is_err(),
            "must reject {}",
            case["name"]
        );
    }
    for group in suite["equivalent_groups"].as_array().unwrap() {
        let names = group.as_array().unwrap();
        for name in &names[1..] {
            assert_eq!(
                observed[names[0].as_str().unwrap()],
                observed[name.as_str().unwrap()]
            );
        }
    }
    for pair in suite["distinct_pairs"].as_array().unwrap() {
        assert_ne!(
            observed[pair[0].as_str().unwrap()],
            observed[pair[1].as_str().unwrap()]
        );
    }
    // Direct values must not let a non-finite float become JSON null.
    assert!(canonical::bytes(&f64::NAN).is_err());
    assert!(canonical::bytes(&vec![f64::INFINITY]).is_err());
    println!(
        "Rust canonical: {} positive + {} negative vectors; bytes/digests/proofs/idempotence PASS",
        positive.len(),
        negative.len()
    );
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 1 {
        return Err("canonical_fixture VECTORS_JSON".into());
    }
    vectors(&args[0])
}
#[cfg(test)]
mod tests {
    #[test]
    fn normative_canonical_vectors() {
        super::vectors(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/spec/vectors/canonical-json-1.json"
        ))
        .unwrap();
    }
}
