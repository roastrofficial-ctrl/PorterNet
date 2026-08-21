use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::publication::atomic_json;
use crate::{Error, Result};

const MAX_EVIDENCE_BYTES: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RendezvousCrashPoint {
    None,
    AfterFact,
    AfterProjection,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RendezvousTransition {
    pub vocabulary: String,
    pub kind: String,
    pub rendezvous: String,
    pub porter: String,
    pub generation: u64,
    pub predecessor: String,
    pub location: Location,
    pub carriage_public_key: String,
    pub issued_at_ms: i64,
    pub activates_at_ms: i64,
    pub expires_at_ms: i64,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionDraft {
    pub porter: String,
    pub generation: u64,
    pub predecessor: String,
    pub location: Location,
    pub carriage_public_key: String,
    pub issued_at_ms: i64,
    pub activates_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KnowledgeState {
    IdentityNotKnownLocally,
    CurrentRendezvousKnown,
    KnownRendezvousExpired,
    ContinuityConflictObserved,
}

impl std::fmt::Display for KnowledgeState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = serde_json::to_value(self).map_err(|_| std::fmt::Error)?;
        formatter.write_str(value.as_str().ok_or(std::fmt::Error)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RendezvousStatus {
    pub vocabulary: String,
    pub porter: String,
    pub knowledge: KnowledgeState,
    pub rendezvous: Option<String>,
    pub generation: Option<u64>,
    pub location: Option<Location>,
    pub carriage_public_key: Option<String>,
    pub expires_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<String>,
}

pub struct RendezvousKnowledge {
    root: PathBuf,
    authorities: HashMap<String, VerifyingKey>,
}

impl RendezvousTransition {
    pub fn sign(draft: TransitionDraft, authority: &SigningKey) -> Result<Self> {
        let unsigned = UnsignedTransition {
            vocabulary: "PORTER-RENDEZVOUS/1",
            kind: "RENDEZVOUS_TRANSITION",
            porter: draft.porter,
            generation: draft.generation,
            predecessor: draft.predecessor,
            location: draft.location,
            carriage_public_key: draft.carriage_public_key,
            issued_at_ms: draft.issued_at_ms,
            activates_at_ms: draft.activates_at_ms,
            expires_at_ms: draft.expires_at_ms,
        };
        validate_unsigned(&unsigned)?;
        let bytes = canonical::bytes(&unsigned)?;
        let rendezvous = claim_identity(&bytes);
        let signature = format!(
            "ed25519:{}",
            BASE64.encode(authority.sign(&bytes).to_bytes())
        );
        Ok(Self {
            vocabulary: unsigned.vocabulary.into(),
            kind: unsigned.kind.into(),
            rendezvous,
            porter: unsigned.porter,
            generation: unsigned.generation,
            predecessor: unsigned.predecessor,
            location: unsigned.location,
            carriage_public_key: unsigned.carriage_public_key,
            issued_at_ms: unsigned.issued_at_ms,
            activates_at_ms: unsigned.activates_at_ms,
            expires_at_ms: unsigned.expires_at_ms,
            signature,
        })
    }

    fn unsigned(&self) -> UnsignedTransition<'_> {
        UnsignedTransition {
            vocabulary: &self.vocabulary,
            kind: &self.kind,
            porter: self.porter.clone(),
            generation: self.generation,
            predecessor: self.predecessor.clone(),
            location: self.location.clone(),
            carriage_public_key: self.carriage_public_key.clone(),
            issued_at_ms: self.issued_at_ms,
            activates_at_ms: self.activates_at_ms,
            expires_at_ms: self.expires_at_ms,
        }
    }
}

impl RendezvousKnowledge {
    pub fn new(root: impl Into<PathBuf>, authorities: HashMap<String, [u8; 32]>) -> Result<Self> {
        let root = root.into().join("rendezvous");
        fs::create_dir_all(root.join("facts"))?;
        fs::create_dir_all(root.join("current"))?;
        let authorities = authorities
            .into_iter()
            .map(|(identity, bytes)| {
                VerifyingKey::from_bytes(&bytes)
                    .map(|key| (identity, key))
                    .map_err(|_| Error::Invalid("continuity authority key".into()))
            })
            .collect::<Result<_>>()?;
        Ok(Self { root, authorities })
    }

    pub fn establish_genesis(
        &self,
        porter: &str,
        location: Location,
        carriage_public_key: impl Into<String>,
    ) -> Result<String> {
        if !safe_identity(porter) || !valid_location(&location) {
            return Err(Error::Invalid("genesis rendezvous".into()));
        }
        let mut fact = StoredFact {
            vocabulary: "PORTER-RENDEZVOUS/1".into(),
            kind: "LOCAL_GENESIS".into(),
            rendezvous: String::new(),
            porter: porter.into(),
            generation: 0,
            predecessor: None,
            location,
            carriage_public_key: carriage_public_key.into(),
            issued_at_ms: None,
            activates_at_ms: 0,
            expires_at_ms: i64::MAX,
            signature: None,
            attests: Some("LOCALLY_CONFIGURED_INITIAL_RENDEZVOUS_KNOWLEDGE".into()),
        };
        validate_carriage_key(&fact.carriage_public_key)?;
        let identity_body = GenesisIdentity::from(&fact);
        fact.rendezvous = claim_identity(&canonical::bytes(&identity_body)?);
        let existing_genesis: Vec<_> = self
            .facts_for(porter)?
            .into_iter()
            .filter(|existing| existing.generation == 0)
            .collect();
        if let Some(existing) = existing_genesis.first() {
            if existing_genesis.len() != 1 || existing.rendezvous != fact.rendezvous {
                return Err(Error::IdentityCollision(format!("LOCAL_GENESIS:{porter}")));
            }
            return Ok(existing.rendezvous.clone());
        }
        publish_exact(&self.fact_path(&fact.rendezvous), &fact, &fact.rendezvous)?;
        Ok(fact.rendezvous)
    }

    pub fn accept_bytes(
        &self,
        bytes: &[u8],
        at_ms: i64,
        crash: RendezvousCrashPoint,
    ) -> Result<RendezvousStatus> {
        if bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(Error::RendezvousRefused);
        }
        let value: RendezvousTransition =
            serde_json::from_slice(bytes).map_err(|_| Error::RendezvousRefused)?;
        self.accept(&value, at_ms, crash)
    }

    pub fn accept(
        &self,
        value: &RendezvousTransition,
        at_ms: i64,
        crash: RendezvousCrashPoint,
    ) -> Result<RendezvousStatus> {
        self.verify(value)?;
        let facts = self.facts_for(&value.porter)?;
        if let Some(existing) = facts
            .iter()
            .find(|fact| fact.rendezvous == value.rendezvous)
        {
            let stored: RendezvousTransition =
                serde_json::from_slice(&fs::read(self.fact_path(&existing.rendezvous))?)?;
            if stored != *value {
                return Err(Error::RendezvousRefused);
            }
            return self.status(&value.porter, at_ms);
        }
        let predecessor = facts
            .iter()
            .find(|fact| fact.rendezvous == value.predecessor)
            .ok_or(Error::RendezvousRefused)?;
        if value.generation != predecessor.generation + 1 {
            return Err(Error::RendezvousRefused);
        }
        let successors = facts
            .iter()
            .filter(|fact| fact.predecessor.as_deref() == Some(&value.predecessor))
            .count();
        if successors >= 2 {
            return Err(Error::RendezvousRefused);
        }
        atomic_json(&self.fact_path(&value.rendezvous), value)?;
        interrupted(crash == RendezvousCrashPoint::AfterFact, "rendezvous fact")?;
        let status = self.status(&value.porter, at_ms)?;
        atomic_json(&self.projection_path(&value.porter), &status)?;
        interrupted(
            crash == RendezvousCrashPoint::AfterProjection,
            "rendezvous projection",
        )?;
        Ok(status)
    }

    pub fn status(&self, porter: &str, at_ms: i64) -> Result<RendezvousStatus> {
        let facts = self.facts_for(porter)?;
        let Some(mut current) = facts.iter().find(|fact| fact.generation == 0) else {
            return Ok(RendezvousStatus::unknown(porter));
        };
        let mut conflicts = Vec::new();
        loop {
            let successors: Vec<_> = facts
                .iter()
                .filter(|fact| {
                    fact.predecessor.as_deref() == Some(&current.rendezvous)
                        && fact.generation == current.generation + 1
                })
                .collect();
            match successors.as_slice() {
                [] => break,
                [next] if next.activates_at_ms > at_ms => break,
                [next] => current = next,
                many => {
                    conflicts = many.iter().map(|fact| fact.rendezvous.clone()).collect();
                    conflicts.sort();
                    break;
                }
            }
        }
        let knowledge = if !conflicts.is_empty() {
            KnowledgeState::ContinuityConflictObserved
        } else if current.expires_at_ms <= at_ms {
            KnowledgeState::KnownRendezvousExpired
        } else {
            KnowledgeState::CurrentRendezvousKnown
        };
        Ok(RendezvousStatus {
            vocabulary: "PORTER-RENDEZVOUS/1".into(),
            porter: porter.into(),
            knowledge,
            rendezvous: Some(current.rendezvous.clone()),
            generation: Some(current.generation),
            location: Some(current.location.clone()),
            carriage_public_key: Some(current.carriage_public_key.clone()),
            expires_at_ms: Some(current.expires_at_ms),
            conflicts,
        })
    }

    pub fn route(&self, porter: &str, at_ms: i64) -> Result<(Location, String)> {
        let status = self.status(porter, at_ms)?;
        if status.knowledge != KnowledgeState::CurrentRendezvousKnown {
            return Err(Error::RendezvousUnavailable {
                identity: porter.into(),
                knowledge: status.knowledge.to_string(),
            });
        }
        Ok((
            status.location.ok_or(Error::RendezvousRefused)?,
            status.carriage_public_key.ok_or(Error::RendezvousRefused)?,
        ))
    }

    fn verify(&self, value: &RendezvousTransition) -> Result<()> {
        if canonical::bytes(value)?.len() > MAX_EVIDENCE_BYTES {
            return Err(Error::RendezvousRefused);
        }
        let unsigned = value.unsigned();
        validate_unsigned(&unsigned).map_err(|_| Error::RendezvousRefused)?;
        validate_carriage_key(&value.carriage_public_key).map_err(|_| Error::RendezvousRefused)?;
        let bytes = canonical::bytes(&unsigned)?;
        if value.rendezvous != claim_identity(&bytes) {
            return Err(Error::RendezvousRefused);
        }
        let authority = self
            .authorities
            .get(&value.porter)
            .ok_or(Error::RendezvousRefused)?;
        let encoded = value
            .signature
            .strip_prefix("ed25519:")
            .ok_or(Error::RendezvousRefused)?;
        let signature: [u8; 64] = BASE64
            .decode(encoded)
            .map_err(|_| Error::RendezvousRefused)?
            .try_into()
            .map_err(|_| Error::RendezvousRefused)?;
        authority
            .verify(&bytes, &Signature::from_bytes(&signature))
            .map_err(|_| Error::RendezvousRefused)
    }

    fn facts_for(&self, porter: &str) -> Result<Vec<StoredFact>> {
        let mut facts = Vec::new();
        for entry in fs::read_dir(self.root.join("facts"))? {
            let fact: StoredFact = serde_json::from_slice(&fs::read(entry?.path())?)?;
            if fact.porter == porter {
                facts.push(fact);
            }
        }
        Ok(facts)
    }

    fn fact_path(&self, identity: &str) -> PathBuf {
        self.root.join("facts").join(format!("{identity}.json"))
    }

    fn projection_path(&self, porter: &str) -> PathBuf {
        self.root.join("current").join(format!("{porter}.json"))
    }
}

impl RendezvousStatus {
    fn unknown(porter: &str) -> Self {
        Self {
            vocabulary: "PORTER-RENDEZVOUS/1".into(),
            porter: porter.into(),
            knowledge: KnowledgeState::IdentityNotKnownLocally,
            rendezvous: None,
            generation: None,
            location: None,
            carriage_public_key: None,
            expires_at_ms: None,
            conflicts: Vec::new(),
        }
    }
}

#[derive(Serialize)]
struct UnsignedTransition<'a> {
    vocabulary: &'a str,
    kind: &'a str,
    porter: String,
    generation: u64,
    predecessor: String,
    location: Location,
    carriage_public_key: String,
    issued_at_ms: i64,
    activates_at_ms: i64,
    expires_at_ms: i64,
}

#[derive(Serialize)]
struct GenesisIdentity<'a> {
    vocabulary: &'a str,
    kind: &'a str,
    porter: &'a str,
    generation: u64,
    location: &'a Location,
    carriage_public_key: &'a str,
}

impl<'a> From<&'a StoredFact> for GenesisIdentity<'a> {
    fn from(value: &'a StoredFact) -> Self {
        Self {
            vocabulary: &value.vocabulary,
            kind: &value.kind,
            porter: &value.porter,
            generation: value.generation,
            location: &value.location,
            carriage_public_key: &value.carriage_public_key,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct StoredFact {
    vocabulary: String,
    kind: String,
    rendezvous: String,
    porter: String,
    generation: u64,
    predecessor: Option<String>,
    location: Location,
    carriage_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issued_at_ms: Option<i64>,
    activates_at_ms: i64,
    expires_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attests: Option<String>,
}

fn validate_unsigned(value: &UnsignedTransition<'_>) -> Result<()> {
    if value.vocabulary != "PORTER-RENDEZVOUS/1"
        || value.kind != "RENDEZVOUS_TRANSITION"
        || !safe_identity(&value.porter)
        || value.generation == 0
        || !value.predecessor.starts_with("RV-")
        || !valid_location(&value.location)
        || value.expires_at_ms <= value.activates_at_ms
    {
        return Err(Error::RendezvousRefused);
    }
    Ok(())
}

fn validate_carriage_key(value: &str) -> Result<()> {
    let bytes = BASE64.decode(value).map_err(|_| Error::RendezvousRefused)?;
    if bytes.len() != 32 {
        return Err(Error::RendezvousRefused);
    }
    Ok(())
}

fn valid_location(location: &Location) -> bool {
    !location.host.is_empty() && location.host.len() <= 255 && location.port != 0
}

fn safe_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn claim_identity(bytes: &[u8]) -> String {
    let digest = format!("{:x}", Sha256::digest(bytes));
    format!("RV-{}", &digest[..32])
}

fn publish_exact<T: Serialize>(path: &Path, value: &T, identity: &str) -> Result<()> {
    if path.exists() {
        if fs::read(path)? != [canonical::bytes(value)?, b"\n".to_vec()].concat() {
            return Err(Error::IdentityCollision(identity.into()));
        }
        return Ok(());
    }
    atomic_json(path, value)
}

fn interrupted(condition: bool, threshold: &'static str) -> Result<()> {
    if condition {
        Err(Error::Interrupted(threshold))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn setup() -> (TempDir, RendezvousKnowledge, SigningKey, String) {
        let temporary = TempDir::new().unwrap();
        let authority = SigningKey::from_bytes(&[17; 32]);
        let knowledge = RendezvousKnowledge::new(
            temporary.path(),
            HashMap::from([("service".into(), authority.verifying_key().to_bytes())]),
        )
        .unwrap();
        let genesis = knowledge
            .establish_genesis(
                "service",
                Location {
                    host: "carrier-a".into(),
                    port: 7411,
                },
                BASE64.encode([3; 32]),
            )
            .unwrap();
        (temporary, knowledge, authority, genesis)
    }

    fn transition(
        authority: &SigningKey,
        predecessor: &str,
        generation: u64,
        host: &str,
        activates: i64,
        expires: i64,
    ) -> RendezvousTransition {
        RendezvousTransition::sign(
            TransitionDraft {
                porter: "service".into(),
                generation,
                predecessor: predecessor.into(),
                location: Location {
                    host: host.into(),
                    port: 9177,
                },
                carriage_public_key: BASE64.encode([9; 32]),
                issued_at_ms: 10,
                activates_at_ms: activates,
                expires_at_ms: expires,
            },
            authority,
        )
        .unwrap()
    }

    #[test]
    fn location_and_operational_key_move_without_identity_change() {
        let (_temporary, knowledge, authority, genesis) = setup();
        let value = transition(&authority, &genesis, 1, "carrier-b", 20, 100);
        let status = knowledge
            .accept(&value, 30, RendezvousCrashPoint::None)
            .unwrap();
        assert_eq!(status.porter, "service");
        assert_eq!(status.generation, Some(1));
        assert_eq!(status.location.unwrap().host, "carrier-b");
    }

    #[test]
    fn bootstrap_cannot_silently_replace_local_genesis() {
        let (_temporary, knowledge, _authority, _genesis) = setup();
        assert!(matches!(
            knowledge.establish_genesis(
                "service",
                Location {
                    host: "different-bootstrap".into(),
                    port: 9999,
                },
                BASE64.encode([4; 32]),
            ),
            Err(Error::IdentityCollision(_))
        ));
    }

    #[test]
    fn forged_and_out_of_order_evidence_create_no_fact() {
        let (temporary, knowledge, authority, genesis) = setup();
        let first = transition(&authority, &genesis, 1, "carrier-b", 20, 100);
        let second = transition(&authority, &first.rendezvous, 2, "carrier-c", 30, 120);
        assert!(matches!(
            knowledge.accept(&second, 40, RendezvousCrashPoint::None),
            Err(Error::RendezvousRefused)
        ));
        assert!(!knowledge.fact_path(&second.rendezvous).exists());
        let attacker = SigningKey::from_bytes(&[44; 32]);
        let forged = transition(&attacker, &genesis, 1, "attacker", 20, 100);
        let before = fs::read_dir(temporary.path().join("rendezvous/facts"))
            .unwrap()
            .count();
        assert!(matches!(
            knowledge.accept(&forged, 40, RendezvousCrashPoint::None),
            Err(Error::RendezvousRefused)
        ));
        assert_eq!(
            before,
            fs::read_dir(temporary.path().join("rendezvous/facts"))
                .unwrap()
                .count()
        );
    }

    #[test]
    fn replay_cannot_rewind_and_conflict_suspends_carriage() {
        let (_temporary, knowledge, authority, genesis) = setup();
        let first = transition(&authority, &genesis, 1, "carrier-b", 20, 100);
        knowledge
            .accept(&first, 30, RendezvousCrashPoint::None)
            .unwrap();
        let second = transition(&authority, &first.rendezvous, 2, "carrier-c", 30, 120);
        knowledge
            .accept(&second, 40, RendezvousCrashPoint::None)
            .unwrap();
        assert_eq!(
            knowledge
                .accept(&first, 40, RendezvousCrashPoint::None)
                .unwrap()
                .generation,
            Some(2)
        );
        let conflict = transition(&authority, &first.rendezvous, 2, "carrier-hostile", 30, 120);
        let status = knowledge
            .accept(&conflict, 40, RendezvousCrashPoint::None)
            .unwrap();
        assert_eq!(status.knowledge, KnowledgeState::ContinuityConflictObserved);
        assert!(matches!(
            knowledge.route("service", 40),
            Err(Error::RendezvousUnavailable { .. })
        ));
    }

    #[test]
    fn future_activation_expiry_and_fact_crash_recover_from_history() {
        let (temporary, knowledge, authority, genesis) = setup();
        let future = transition(&authority, &genesis, 1, "carrier-b", 50, 80);
        assert!(matches!(
            knowledge.accept(&future, 20, RendezvousCrashPoint::AfterFact),
            Err(Error::Interrupted("rendezvous fact"))
        ));
        let recovered = RendezvousKnowledge::new(
            temporary.path(),
            HashMap::from([("service".into(), authority.verifying_key().to_bytes())]),
        )
        .unwrap();
        assert_eq!(recovered.status("service", 20).unwrap().generation, Some(0));
        assert_eq!(recovered.route("service", 60).unwrap().0.host, "carrier-b");
        assert!(matches!(
            recovered.route("service", 90),
            Err(Error::RendezvousUnavailable { .. })
        ));
    }
}
