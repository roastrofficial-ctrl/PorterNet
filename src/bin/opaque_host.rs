#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let input = arguments.next().ok_or("usage: opaque-host INPUT OUTPUT")?;
    let output = arguments.next().ok_or("usage: opaque-host INPUT OUTPUT")?;
    if arguments.next().is_some() {
        return Err("usage: opaque-host INPUT OUTPUT".into());
    }
    let bytes = fs::read(&input)?;
    let package: Value = serde_json::from_slice(&bytes)?;
    let observation = json!({
        "application": "opaque-rust-fixture",
        "observed_package": package.get("package").and_then(Value::as_str),
        "input_sha256": format!("{:x}", Sha256::digest(&bytes)),
    });
    publish(Path::new(&output), &serde_json::to_vec(&observation)?)?;
    Ok(())
}

fn publish(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("tmp");
    let mut stream = fs::File::create(&temporary)?;
    stream.write_all(bytes)?;
    stream.write_all(b"\n")?;
    stream.sync_all()?;
    fs::rename(temporary, path)
}
