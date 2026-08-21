#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::env;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use porternet::{NativeFrame, PorterIdentity, UnitClass};
use serde_json::{Value, json};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("seal") if arguments.len() == 8 => seal(&arguments),
        Some("open") if arguments.len() == 6 => open(&arguments),
        _ => Err("native-fixture seal FROM PRIVATE TO PUBLIC CLASS UNIT JSON | open TO PRIVATE FROM PUBLIC FRAME".into()),
    }
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
