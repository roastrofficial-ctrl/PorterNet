//! One explicitly chosen local attention opportunity. No arrival entry point.
#![forbid(unsafe_code)]
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use porternet::{Acceptance, CrashPoint, PorterStore, canonical};
use serde_json::{Value, json};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const CONTRACT: &str = "PORTER-HOST-ADAPTER/1";

fn control(reader: &mut impl BufRead) -> Result<Value> {
    let mut line = Vec::new();
    std::io::Read::take(reader, 65_537).read_until(b'\n', &mut line)?;
    if line.len() > 65_536 || !line.ends_with(b"\n") {
        return Err("missing or oversized adapter control".into());
    }
    Ok(serde_json::from_slice(&line)?)
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 3 {
        return Err(
            "host_attention ROOT PACKAGE EXECUTABLE [ARG ...] | ROOT PACKAGE --stop-after-cl"
                .into(),
        );
    }
    let id = &args[1];
    if !id.starts_with("PKG-") || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("invalid candidate identity".into());
    }
    let store = PorterStore::new(&args[0])?;
    // A bounded visit of one: canonical AC, never the inbox projection, is authority.
    let ac: Acceptance = serde_json::from_slice(&fs::read(
        store.root().join("acceptances").join(format!("{id}.json")),
    )?)?;
    if ac.package.package != *id
        || ac.kind != "REMOTE_ACCEPTANCE"
        || ac.package_digest != canonical::digest(&ac.package)?
    {
        return Err("invalid canonical acceptance".into());
    }
    let crash = if args[2] == "--crash-after-cl" {
        CrashPoint::AfterCollection
    } else {
        CrashPoint::None
    };
    let cl = store.collect(id, "local-host", 2, crash)?;
    if cl.package != ac.package || cl.acceptance != ac.acceptance || cl.kind != "COLLECTION" {
        return Err("Collection disagrees with acceptance".into());
    }
    if args[2] == "--stop-after-cl" {
        println!("{}", serde_json::to_string(&cl)?);
        return Ok(());
    }
    // Starting this command is independent Host-local attention. CL is already
    // recoverable before the adapter starts and before any Package offer.
    let mut child = Command::new(&args[2])
        .args(&args[3..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let result = (|| -> Result<()> {
        let mut input = child.stdin.take().ok_or("adapter stdin")?;
        let mut output = BufReader::new(child.stdout.take().ok_or("adapter stdout")?);
        let ready = control(&mut output)?;
        if ready["contract"] != CONTRACT || ready["runtime_observation"] != "ADAPTER_READY" {
            return Err("invalid adapter readiness".into());
        }
        let dispatch = Uuid::new_v4().to_string();
        let offer = json!({"contract": CONTRACT, "dispatch": dispatch, "collection": cl});
        serde_json::to_writer(&mut input, &offer)?;
        input.write_all(b"\n")?;
        input.flush()?;
        let returned = control(&mut output)?;
        if returned["contract"] != CONTRACT
            || returned["dispatch"] != dispatch
            || returned["runtime_observation"] != "ADAPTER_RETURNED_CONTROL"
        {
            return Err("invalid adapter control return after CL".into());
        }
        drop(input);
        println!(
            "{}",
            json!({"collection": cl.collection, "runtime_observation": "ADAPTER_RETURNED_CONTROL"})
        );
        Ok(())
    })();
    // Process lifecycle is local policy. An operational error never retracts CL.
    let _ = child.kill();
    let _ = child.wait();
    result
}
