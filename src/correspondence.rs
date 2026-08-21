use std::fs;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::canonical;
use crate::model::{Acceptance, Collection, Lodgement, Package};
use crate::publication::atomic_json;
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashPoint {
    None,
    AfterLodgement,
    AfterAcceptance,
    AfterCollection,
}

pub struct PorterStore {
    root: PathBuf,
}

impl PorterStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let store = Self { root: root.into() };
        for directory in ["lodgements", "acceptances", "collections", "inbox", "collected"] {
            fs::create_dir_all(store.root.join(directory))?;
        }
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn lodge(&self, package: &Package, at_ms: i64, crash: CrashPoint) -> Result<Lodgement> {
        validate_package(package)?;
        let digest = canonical::digest(package)?;
        let path = self.root.join("lodgements").join(format!("{}.json", package.package));
        if path.exists() {
            let existing: Lodgement = serde_json::from_slice(&fs::read(path)?)?;
            if existing.package_digest != digest {
                return Err(Error::IdentityCollision(package.package.clone()));
            }
            return Ok(existing);
        }
        let value = Lodgement {
            protocol: "PORTER/1".into(),
            kind: "LODGEMENT".into(),
            lodgement: identity("LG"),
            package: package.clone(),
            package_digest: digest,
            lodged_at_ms: at_ms,
            attests: "PACKAGE_RECOVERABLY_LODGED_WITH_ORIGIN_PORTER".into(),
        };
        atomic_json(&path, &value)?;
        interrupted(crash == CrashPoint::AfterLodgement, "LG")?;
        Ok(value)
    }

    pub fn accept(&self, package: &Package, at_ms: i64, crash: CrashPoint) -> Result<Acceptance> {
        validate_package(package)?;
        let digest = canonical::digest(package)?;
        let path = self.root.join("acceptances").join(format!("{}.json", package.package));
        if path.exists() {
            let existing: Acceptance = serde_json::from_slice(&fs::read(path)?)?;
            if existing.package_digest != digest {
                return Err(Error::IdentityCollision(package.package.clone()));
            }
            return Ok(existing);
        }
        let value = Acceptance {
            protocol: "PORTER/1".into(),
            kind: "REMOTE_ACCEPTANCE".into(),
            acceptance: identity("AC"),
            recipient: package.recipient.clone(),
            package: package.clone(),
            package_digest: digest,
            accepted_at_ms: at_ms,
            attests: "RECIPIENT_PORTER_ACCEPTED_DURABLE_RESPONSIBILITY".into(),
        };
        atomic_json(&path, &value)?;
        interrupted(crash == CrashPoint::AfterAcceptance, "AC")?;
        atomic_json(&self.root.join("inbox").join(format!("{}.json", package.package)), package)?;
        Ok(value)
    }

    pub fn collect(&self, package_id: &str, collector: &str, at_ms: i64, crash: CrashPoint) -> Result<Collection> {
        let association = self.root.join("collections").join(format!("{package_id}.json"));
        if association.exists() {
            return Ok(serde_json::from_slice(&fs::read(association)?)?);
        }
        let acceptance_path = self.root.join("acceptances").join(format!("{package_id}.json"));
        if !acceptance_path.exists() {
            return Err(Error::MissingFact(format!("AC for {package_id}")));
        }
        let acceptance: Acceptance = serde_json::from_slice(&fs::read(acceptance_path)?)?;
        let value = Collection {
            protocol: "PORTER/1".into(),
            kind: "COLLECTION".into(),
            collection: identity("CL"),
            package: acceptance.package,
            acceptance: acceptance.acceptance,
            collector: collector.into(),
            collected_at_ms: at_ms,
            attests: "PACKAGE_RECOVERABLY_TRANSFERRED_TO_HOST_CUSTODY".into(),
        };
        atomic_json(&association, &value)?;
        interrupted(crash == CrashPoint::AfterCollection, "CL")?;
        atomic_json(&self.root.join("collected").join(format!("{package_id}.json")), &value.package)?;
        let _ = fs::remove_file(self.root.join("inbox").join(format!("{package_id}.json")));
        Ok(value)
    }
}

fn validate_package(package: &Package) -> Result<()> {
    if package.protocol != "PORTER/1" || !package.package.starts_with("PKG-") {
        return Err(Error::Invalid("Package protocol or identity".into()));
    }
    if package.sender.is_empty() || package.recipient.is_empty() || package.kind.is_empty() {
        return Err(Error::Invalid("Package boundary identity or Kind".into()));
    }
    Ok(())
}

fn identity(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

fn interrupted(condition: bool, threshold: &'static str) -> Result<()> {
    if condition { Err(Error::Interrupted(threshold)) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    fn package() -> Package {
        Package { protocol:"PORTER/1".into(), package:"PKG-00000000000000000000000000000001".into(), sender:"a".into(), recipient:"b".into(), kind:"opaque.demo".into(), created:1, expires:2, payload:json!({"meaning":"belongs elsewhere"}), in_reply_to:None }
    }

    #[test]
    fn thresholds_survive_projection_interruption_and_exact_replay() {
        let temporary=TempDir::new().unwrap();let store=PorterStore::new(temporary.path()).unwrap();let package=package();
        assert!(matches!(store.lodge(&package,1,CrashPoint::AfterLodgement),Err(Error::Interrupted("LG"))));
        let lg=store.lodge(&package,2,CrashPoint::None).unwrap();assert_eq!(lg.lodged_at_ms,1);
        assert!(matches!(store.accept(&package,3,CrashPoint::AfterAcceptance),Err(Error::Interrupted("AC"))));
        let ac=store.accept(&package,4,CrashPoint::None).unwrap();assert_eq!(ac.accepted_at_ms,3);
        assert!(matches!(store.collect(&package.package,"host",5,CrashPoint::AfterCollection),Err(Error::Interrupted("CL"))));
        let cl=store.collect(&package.package,"host",6,CrashPoint::None).unwrap();assert_eq!(cl.collected_at_ms,5);
    }

    #[test]
    fn changed_bytes_under_one_identity_are_hostile() {
        let temporary=TempDir::new().unwrap();let store=PorterStore::new(temporary.path()).unwrap();let mut value=package();
        store.accept(&value,1,CrashPoint::None).unwrap();value.payload=json!({"changed":true});
        assert!(matches!(store.accept(&value,2,CrashPoint::None),Err(Error::IdentityCollision(_))));
    }
}
