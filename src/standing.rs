use std::fs;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::canonical;
use crate::correspondence::{CrashPoint, PorterStore};
use crate::model::{Acceptance, Collection, Package};
use crate::publication::atomic_json;
use crate::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Terms {
    pub kinds: Vec<String>,
    pub maximum_package_bytes: u64,
    pub maximum_outstanding_count: u64,
    pub maximum_outstanding_bytes: u64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Introduction {
    pub protocol: String,
    pub kind: String,
    pub introduction: String,
    pub sender: String,
    pub recipient: String,
    pub issuer: String,
    pub terms: Terms,
    pub established_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StandingChange {
    pub protocol: String,
    pub kind: String,
    pub change: String,
    pub predecessor: String,
    pub successor: Option<String>,
    pub changed_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Admission {
    Accepted(Box<Acceptance>),
    Refused,
}

pub struct StandingStore {
    root: PathBuf,
    correspondence: PorterStore,
}

impl StandingStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        for directory in ["introductions", "standing_changes", "standing_secrets"] {
            fs::create_dir_all(root.join(directory))?;
        }
        Ok(Self {
            correspondence: PorterStore::new(&root)?,
            root,
        })
    }

    pub fn establish(&self, introduction: &Introduction, capability: &[u8]) -> Result<()> {
        validate_introduction(introduction)?;
        let fact = self.introduction_path(&introduction.introduction);
        publish_exact(&fact, introduction, &introduction.introduction)?;
        let secret = self.secret_path(&introduction.introduction);
        if secret.exists() {
            if fs::read(&secret)? != capability {
                return Err(Error::IdentityCollision(introduction.introduction.clone()));
            }
            return Ok(());
        }
        publish_secret(&secret, capability)
    }

    pub fn change(&self, change: &StandingChange) -> Result<()> {
        if change.protocol != "PORTER-STANDING/1"
            || !change.change.starts_with("SC-")
            || !change.predecessor.starts_with("IN-")
        {
            return Err(Error::Invalid("standing change boundary".into()));
        }
        self.load_introduction(&change.predecessor)?;
        if let Some(successor) = &change.successor {
            self.load_introduction(successor)?;
        }
        publish_exact(
            &self.change_path(&change.predecessor),
            change,
            &change.predecessor,
        )
    }

    pub fn current(&self, first: &str) -> Result<Option<Introduction>> {
        let mut cursor = self.load_introduction(first)?;
        let relationship = (cursor.sender.clone(), cursor.recipient.clone());
        let mut traversed = 0usize;
        loop {
            traversed += 1;
            if traversed > 10_000 {
                return Err(Error::Invalid("standing chain exceeds bound".into()));
            }
            let transition = self.change_path(&cursor.introduction);
            if !transition.exists() {
                return Ok(Some(cursor));
            }
            let change: StandingChange = serde_json::from_slice(&fs::read(transition)?)?;
            let Some(successor) = change.successor else {
                return Ok(None);
            };
            let next = self.load_introduction(&successor)?;
            if (next.sender.clone(), next.recipient.clone()) != relationship {
                return Err(Error::Invalid(
                    "standing successor changed relationship".into(),
                ));
            }
            cursor = next;
        }
    }

    pub fn proof(&self, introduction: &str, package: &Package) -> Result<Vec<u8>> {
        let secret = fs::read(self.secret_path(introduction))?;
        package_proof(&secret, package)
    }

    pub fn admit(
        &self,
        first: &str,
        package: &Package,
        proof: &[u8],
        at_ms: i64,
        crash: CrashPoint,
    ) -> Result<Admission> {
        if let Some(existing) = self.correspondence.replay_acceptance(package)? {
            return Ok(Admission::Accepted(Box::new(existing)));
        }
        let Some(current) = self.current(first)? else {
            return Ok(Admission::Refused);
        };
        let package_bytes = canonical::bytes(package)?.len() as u64;
        if package.sender != current.sender
            || package.recipient != current.recipient
            || !current.terms.kinds.contains(&package.kind)
            || package_bytes > current.terms.maximum_package_bytes
            || at_ms > current.terms.expires_at_ms
            || package.expires < at_ms
        {
            return Ok(Admission::Refused);
        }
        let secret = fs::read(self.secret_path(&current.introduction))?;
        let mut verifier = HmacSha256::new_from_slice(&secret)
            .map_err(|_| Error::Invalid("invalid standing capability".into()))?;
        verifier.update(canonical::digest(package)?.as_bytes());
        if verifier.verify_slice(proof).is_err() {
            return Ok(Admission::Refused);
        }
        let (count, bytes) = self.outstanding(&current.sender, &current.recipient)?;
        if count >= current.terms.maximum_outstanding_count
            || bytes.saturating_add(package_bytes) > current.terms.maximum_outstanding_bytes
        {
            return Ok(Admission::Refused);
        }
        Ok(Admission::Accepted(Box::new(
            self.correspondence.accept(package, at_ms, crash)?,
        )))
    }

    fn outstanding(&self, sender: &str, recipient: &str) -> Result<(u64, u64)> {
        let mut count = 0u64;
        let mut bytes = 0u64;
        for entry in fs::read_dir(self.root.join("acceptances"))? {
            let acceptance: Acceptance = serde_json::from_slice(&fs::read(entry?.path())?)?;
            if acceptance.package.sender != sender || acceptance.package.recipient != recipient {
                continue;
            }
            let collection = self
                .root
                .join("collections")
                .join(format!("{}.json", acceptance.package.package));
            if collection.exists() {
                let _: Collection = serde_json::from_slice(&fs::read(collection)?)?;
                continue;
            }
            count = count.saturating_add(1);
            bytes = bytes.saturating_add(canonical::bytes(&acceptance.package)?.len() as u64);
        }
        Ok((count, bytes))
    }

    fn load_introduction(&self, identity: &str) -> Result<Introduction> {
        let path = self.introduction_path(identity);
        if !path.exists() {
            return Err(Error::MissingFact(format!("Introduction {identity}")));
        }
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }

    fn introduction_path(&self, identity: &str) -> PathBuf {
        self.root
            .join("introductions")
            .join(format!("{identity}.json"))
    }
    fn change_path(&self, predecessor: &str) -> PathBuf {
        self.root
            .join("standing_changes")
            .join(format!("{predecessor}.json"))
    }
    fn secret_path(&self, identity: &str) -> PathBuf {
        self.root
            .join("standing_secrets")
            .join(format!("{identity}.key"))
    }
}

pub fn package_proof(capability: &[u8], package: &Package) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(capability)
        .map_err(|_| Error::Invalid("invalid standing capability".into()))?;
    mac.update(canonical::digest(package)?.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn validate_introduction(value: &Introduction) -> Result<()> {
    if value.protocol != "PORTER-INTRODUCTION/1"
        || value.kind != "INTRODUCTION"
        || !value.introduction.starts_with("IN-")
        || value.sender.is_empty()
        || value.recipient.is_empty()
        || value.terms.kinds.is_empty()
    {
        return Err(Error::Invalid("Introduction boundary".into()));
    }
    Ok(())
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

fn publish_secret(path: &Path, capability: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| Error::Invalid("secret path".into()))?;
    let temporary = parent.join(format!(".secret-{}.tmp", Uuid::new_v4().simple()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(capability)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&temporary, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    fn package(identity: &str) -> Package {
        Package {
            protocol: "PORTER/1".into(),
            package: identity.into(),
            sender: "sender".into(),
            recipient: "recipient".into(),
            kind: "opaque.demo".into(),
            created: 1,
            expires: 10_000,
            payload: json!({"opaque": true}),
            in_reply_to: None,
        }
    }
    fn introduction(identity: &str, count: u64) -> Introduction {
        Introduction {
            protocol: "PORTER-INTRODUCTION/1".into(),
            kind: "INTRODUCTION".into(),
            introduction: identity.into(),
            sender: "sender".into(),
            recipient: "recipient".into(),
            issuer: "fixture-authority".into(),
            terms: Terms {
                kinds: vec!["opaque.demo".into()],
                maximum_package_bytes: 4096,
                maximum_outstanding_count: count,
                maximum_outstanding_bytes: 8192,
                expires_at_ms: 5_000,
            },
            established_at_ms: 1,
        }
    }

    #[test]
    fn exact_historical_replay_precedes_expired_standing() {
        let temporary = TempDir::new().unwrap();
        let standing = StandingStore::new(temporary.path()).unwrap();
        standing
            .establish(&introduction("IN-old", 2), b"old-secret")
            .unwrap();
        let package = package("PKG-00000000000000000000000000000001");
        let proof = standing.proof("IN-old", &package).unwrap();
        let first = standing
            .admit("IN-old", &package, &proof, 100, CrashPoint::None)
            .unwrap();
        let replay = standing
            .admit("IN-old", &package, b"now-invalid", 9_000, CrashPoint::None)
            .unwrap();
        assert_eq!(first, replay);
    }

    #[test]
    fn succession_is_atomic_and_does_not_reset_relationship_budget() {
        let temporary = TempDir::new().unwrap();
        let standing = StandingStore::new(temporary.path()).unwrap();
        standing
            .establish(&introduction("IN-old", 1), b"old-secret")
            .unwrap();
        standing
            .establish(&introduction("IN-new", 1), b"new-secret")
            .unwrap();
        let first = package("PKG-00000000000000000000000000000001");
        let proof = standing.proof("IN-old", &first).unwrap();
        assert!(matches!(
            standing
                .admit("IN-old", &first, &proof, 100, CrashPoint::None)
                .unwrap(),
            Admission::Accepted(_)
        ));
        standing
            .change(&StandingChange {
                protocol: "PORTER-STANDING/1".into(),
                kind: "STANDING_CHANGE".into(),
                change: "SC-one".into(),
                predecessor: "IN-old".into(),
                successor: Some("IN-new".into()),
                changed_at_ms: 200,
            })
            .unwrap();
        let second = package("PKG-00000000000000000000000000000002");
        let proof = standing.proof("IN-new", &second).unwrap();
        assert_eq!(
            standing
                .admit("IN-old", &second, &proof, 300, CrashPoint::None)
                .unwrap(),
            Admission::Refused
        );
    }

    #[test]
    fn changed_bytes_and_forged_possession_are_refused_without_ac() {
        let temporary = TempDir::new().unwrap();
        let standing = StandingStore::new(temporary.path()).unwrap();
        standing
            .establish(&introduction("IN-one", 2), b"secret")
            .unwrap();
        let package = package("PKG-00000000000000000000000000000001");
        assert_eq!(
            standing
                .admit("IN-one", &package, b"forgery", 100, CrashPoint::None)
                .unwrap(),
            Admission::Refused
        );
        assert!(
            !temporary
                .path()
                .join("acceptances")
                .join(format!("{}.json", package.package))
                .exists()
        );
    }
}
