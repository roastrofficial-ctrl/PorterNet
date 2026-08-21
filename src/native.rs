use std::collections::HashMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::canonical;
use crate::{Error, Result};

const MAGIC: &[u8; 4] = b"PRTR";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = 9;
pub const MAX_FRAME_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnitClass {
    Package,
    Ceremony,
    AcceptanceEvidence,
    RefusalEvidence,
    CeremonyResult,
}

#[derive(Clone)]
pub struct PorterIdentity {
    identity: String,
    private: StaticSecret,
}

impl PorterIdentity {
    pub fn generate(identity: impl Into<String>) -> Result<Self> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self::from_private_bytes(identity, bytes)
    }

    pub fn from_private_bytes(identity: impl Into<String>, private: [u8; 32]) -> Result<Self> {
        let identity = identity.into();
        if !safe_identity(&identity) {
            return Err(Error::Invalid("Porter identity".into()));
        }
        Ok(Self {
            identity,
            private: StaticSecret::from(private),
        })
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn private_bytes(&self) -> [u8; 32] {
        self.private.to_bytes()
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        PublicKey::from(&self.private).to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OpenedUnit {
    pub unit: String,
    pub class: UnitClass,
    pub sender: String,
    pub recipient: String,
    pub value: Value,
}

pub struct NativeFrame;

impl NativeFrame {
    pub fn seal<T: Serialize>(
        value: &T,
        sender: &PorterIdentity,
        recipient: &str,
        recipient_public_key: [u8; 32],
        class: UnitClass,
        unit: &str,
    ) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        Self::seal_with_nonce(
            value,
            sender,
            recipient,
            recipient_public_key,
            class,
            unit,
            nonce,
        )
    }

    pub fn open(
        frame: &[u8],
        recipient: &PorterIdentity,
        peer_public_keys: &HashMap<String, [u8; 32]>,
    ) -> Result<OpenedUnit> {
        let body = parse_frame(frame)?;
        let envelope: Envelope =
            serde_json::from_slice(body).map_err(|_| Error::NativeFrameRefused)?;
        if envelope.protocol != "PORTER-CARRIAGE/1"
            || envelope.version != VERSION
            || envelope.recipient != recipient.identity
            || !safe_identity(&envelope.sender)
            || !safe_unit(&envelope.unit)
        {
            return Err(Error::NativeFrameRefused);
        }
        let sender_public = peer_public_keys
            .get(&envelope.sender)
            .ok_or(Error::NativeFrameRefused)?;
        let metadata = Metadata::from_envelope(&envelope);
        let aad = canonical::bytes(&metadata)?;
        let shared = recipient
            .private
            .diffie_hellman(&PublicKey::from(*sender_public));
        let key = derive_key(shared.as_bytes(), &aad)?;
        let nonce = BASE64
            .decode(envelope.nonce.as_bytes())
            .map_err(|_| Error::NativeFrameRefused)?;
        if nonce.len() != 12 {
            return Err(Error::NativeFrameRefused);
        }
        let ciphertext = BASE64
            .decode(envelope.ciphertext.as_bytes())
            .map_err(|_| Error::NativeFrameRefused)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| Error::NativeFrameRefused)?;
        let clear = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::NativeFrameRefused)?;
        let value = serde_json::from_slice(&clear).map_err(|_| Error::NativeFrameRefused)?;
        Ok(OpenedUnit {
            unit: envelope.unit,
            class: envelope.class,
            sender: envelope.sender,
            recipient: envelope.recipient,
            value,
        })
    }

    fn seal_with_nonce<T: Serialize>(
        value: &T,
        sender: &PorterIdentity,
        recipient: &str,
        recipient_public_key: [u8; 32],
        class: UnitClass,
        unit: &str,
        nonce: [u8; 12],
    ) -> Result<Vec<u8>> {
        if !safe_identity(recipient) || !safe_unit(unit) {
            return Err(Error::Invalid("native Unit boundary identity".into()));
        }
        let metadata = Metadata {
            protocol: "PORTER-CARRIAGE/1",
            version: VERSION,
            unit,
            class,
            sender: sender.identity(),
            recipient,
        };
        let aad = canonical::bytes(&metadata)?;
        let shared = sender
            .private
            .diffie_hellman(&PublicKey::from(recipient_public_key));
        let key = derive_key(shared.as_bytes(), &aad)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| Error::NativeFrameRefused)?;
        let clear = canonical::bytes(value)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &clear,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::NativeFrameRefused)?;
        let envelope = Envelope {
            protocol: "PORTER-CARRIAGE/1".into(),
            version: VERSION,
            unit: unit.into(),
            class,
            sender: sender.identity.clone(),
            recipient: recipient.into(),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        };
        let body = canonical::bytes(&envelope)?;
        if body.len() > MAX_FRAME_BYTES {
            return Err(Error::NativeFrameRefused);
        }
        let mut frame = Vec::with_capacity(HEADER_BYTES + body.len());
        frame.extend_from_slice(MAGIC);
        frame.push(VERSION);
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(frame)
    }
}

#[derive(Serialize)]
struct Metadata<'a> {
    protocol: &'static str,
    version: u8,
    unit: &'a str,
    #[serde(rename = "class")]
    class: UnitClass,
    #[serde(rename = "from")]
    sender: &'a str,
    #[serde(rename = "to")]
    recipient: &'a str,
}

impl<'a> Metadata<'a> {
    fn from_envelope(envelope: &'a Envelope) -> Self {
        Self {
            protocol: "PORTER-CARRIAGE/1",
            version: VERSION,
            unit: &envelope.unit,
            class: envelope.class,
            sender: &envelope.sender,
            recipient: &envelope.recipient,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    protocol: String,
    version: u8,
    unit: String,
    #[serde(rename = "class")]
    class: UnitClass,
    #[serde(rename = "from")]
    sender: String,
    #[serde(rename = "to")]
    recipient: String,
    nonce: String,
    ciphertext: String,
}

fn derive_key(shared: &[u8], aad: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut info = b"PORTER-CARRIAGE/1\0".to_vec();
    info.extend_from_slice(aad);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| Error::NativeFrameRefused)?;
    Ok(key)
}

fn parse_frame(frame: &[u8]) -> Result<&[u8]> {
    if frame.len() < HEADER_BYTES || &frame[..4] != MAGIC || frame[4] != VERSION {
        return Err(Error::NativeFrameRefused);
    }
    let length = u32::from_be_bytes(
        frame[5..9]
            .try_into()
            .map_err(|_| Error::NativeFrameRefused)?,
    ) as usize;
    if !(2..=MAX_FRAME_BYTES).contains(&length) || frame.len() != HEADER_BYTES + length {
        return Err(Error::NativeFrameRefused);
    }
    Ok(&frame[HEADER_BYTES..])
}

fn safe_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn safe_unit(value: &str) -> bool {
    value.starts_with("CU-") && value.len() <= 255 && safe_identity(value)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn identities() -> (PorterIdentity, PorterIdentity) {
        (
            PorterIdentity::from_private_bytes("sender", [7; 32]).unwrap(),
            PorterIdentity::from_private_bytes("recipient", [11; 32]).unwrap(),
        )
    }

    #[test]
    fn protected_unit_binds_every_carriage_identity() {
        let (sender, recipient) = identities();
        let value = json!({"replacement_capability":"must-not-be-visible"});
        let frame = NativeFrame::seal_with_nonce(
            &value,
            &sender,
            recipient.identity(),
            recipient.public_bytes(),
            UnitClass::Ceremony,
            "CU-one",
            [3; 12],
        )
        .unwrap();
        assert!(!frame.windows(19).any(|part| part == b"must-not-be-visible"));
        let peers = HashMap::from([(sender.identity().into(), sender.public_bytes())]);
        let opened = NativeFrame::open(&frame, &recipient, &peers).unwrap();
        assert_eq!(opened.value, value);
        assert_eq!(opened.class, UnitClass::Ceremony);

        let wrong_recipient =
            PorterIdentity::from_private_bytes("another-recipient", recipient.private_bytes())
                .unwrap();
        assert!(matches!(
            NativeFrame::open(&frame, &wrong_recipient, &peers),
            Err(Error::NativeFrameRefused)
        ));
        let wrong_sender = HashMap::from([(sender.identity().into(), [19; 32])]);
        assert!(matches!(
            NativeFrame::open(&frame, &recipient, &wrong_sender),
            Err(Error::NativeFrameRefused)
        ));
    }

    #[test]
    fn corruption_reclassification_and_redirection_fail_authentication() {
        let (sender, recipient) = identities();
        let frame = NativeFrame::seal(
            &json!({"opaque":true}),
            &sender,
            recipient.identity(),
            recipient.public_bytes(),
            UnitClass::Package,
            "CU-two",
        )
        .unwrap();
        let peers = HashMap::from([(sender.identity().into(), sender.public_bytes())]);
        for field in ["class", "unit", "from", "to"] {
            let mut envelope: Value = serde_json::from_slice(&frame[HEADER_BYTES..]).unwrap();
            envelope[field] = match field {
                "class" => json!("CEREMONY"),
                "unit" => json!("CU-altered"),
                "from" => json!("stranger"),
                _ => json!("another-recipient"),
            };
            let body = canonical::bytes(&envelope).unwrap();
            let mut altered = frame[..5].to_vec();
            altered.extend_from_slice(&(body.len() as u32).to_be_bytes());
            altered.extend_from_slice(&body);
            assert!(matches!(
                NativeFrame::open(&altered, &recipient, &peers),
                Err(Error::NativeFrameRefused)
            ));
        }
        let mut corrupted = frame;
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(matches!(
            NativeFrame::open(&corrupted, &recipient, &peers),
            Err(Error::NativeFrameRefused)
        ));
    }

    #[test]
    fn hostile_headers_truncation_and_excess_are_rejected_before_decode() {
        let (sender, recipient) = identities();
        let valid = NativeFrame::seal(
            &json!({"x":1}),
            &sender,
            recipient.identity(),
            recipient.public_bytes(),
            UnitClass::Package,
            "CU-three",
        )
        .unwrap();
        let peers = HashMap::from([(sender.identity().into(), sender.public_bytes())]);
        let mut cases = vec![
            b"P".to_vec(),
            [b"NOPE".as_slice(), &[1], &2u32.to_be_bytes(), b"{}"].concat(),
            [MAGIC.as_slice(), &[9], &2u32.to_be_bytes(), b"{}"].concat(),
            [MAGIC.as_slice(), &[1], &999_999u32.to_be_bytes()].concat(),
            valid[..valid.len() - 1].to_vec(),
        ];
        let mut excess = valid;
        excess.push(0);
        cases.push(excess);
        for case in cases {
            assert!(matches!(
                NativeFrame::open(&case, &recipient, &peers),
                Err(Error::NativeFrameRefused)
            ));
        }
    }
}
