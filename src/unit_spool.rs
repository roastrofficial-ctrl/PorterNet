use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical;
use crate::model::{Acceptance, Package};
use crate::native::{OpenedUnit, UnitClass};
use crate::publication::atomic_json;
use crate::{CeremonyResult, Error, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "identity",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum EvidenceExpectation {
    Package(String),
    Ceremony(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NativeUnit {
    pub protocol: String,
    pub unit: String,
    #[serde(rename = "class")]
    pub class: UnitClass,
    #[serde(rename = "from")]
    pub sender: String,
    #[serde(rename = "to")]
    pub recipient: String,
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub awaits: Option<EvidenceExpectation>,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransportObservation {
    pub unit: String,
    pub attempts: u64,
    pub last_attempt_at_ms: i64,
    pub last_observation: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRetention {
    pub protocol: String,
    pub original_unit: String,
    pub evidence_unit: String,
    #[serde(rename = "class")]
    pub class: UnitClass,
    #[serde(rename = "from")]
    pub sender: String,
    #[serde(rename = "to")]
    pub recipient: String,
    pub value: Value,
    pub retained_at_ms: i64,
}

pub struct UnitSpool {
    root: PathBuf,
    identity: String,
}

impl UnitSpool {
    pub fn new(root: impl Into<PathBuf>, identity: impl Into<String>) -> Result<Self> {
        let root = root.into().join("native_spool");
        for directory in ["outgoing", "observations", "evidence"] {
            fs::create_dir_all(root.join(directory))?;
        }
        let spool = Self {
            root,
            identity: identity.into(),
        };
        if !safe_boundary_identity(&spool.identity) {
            return Err(Error::Invalid("spool Porter identity".into()));
        }
        spool.recover_settled()?;
        Ok(spool)
    }

    pub fn queue(&self, unit: &NativeUnit) -> Result<NativeUnit> {
        validate_unit(unit, &self.identity)?;
        let path = self.outgoing_path(&unit.unit);
        if path.exists() {
            let existing: NativeUnit = serde_json::from_slice(&fs::read(path)?)?;
            if existing != *unit {
                return Err(Error::IdentityCollision(unit.unit.clone()));
            }
            return Ok(existing);
        }
        atomic_json(&path, unit)?;
        Ok(unit.clone())
    }

    pub fn pending(&self) -> Result<Vec<NativeUnit>> {
        let mut values = Vec::new();
        for entry in fs::read_dir(self.root.join("outgoing"))? {
            values.push(serde_json::from_slice(&fs::read(entry?.path())?)?);
        }
        values.sort_by(|left: &NativeUnit, right: &NativeUnit| left.unit.cmp(&right.unit));
        Ok(values)
    }

    pub fn note_attempt(&self, unit: &str, at_ms: i64, accepted_by_transport: bool) -> Result<()> {
        validate_unit_identity(unit)?;
        if !self.outgoing_path(unit).exists() {
            return Err(Error::MissingFact(format!("outgoing native Unit {unit}")));
        }
        let path = self.observation_path(unit);
        let attempts = if path.exists() {
            let existing: TransportObservation = serde_json::from_slice(&fs::read(&path)?)?;
            existing.attempts.saturating_add(1)
        } else {
            1
        };
        let observation = TransportObservation {
            unit: unit.into(),
            attempts,
            last_attempt_at_ms: at_ms,
            last_observation: if accepted_by_transport {
                "LOWER_TRANSPORT_ACCEPTED_BYTES"
            } else {
                "KNOWN_RENDEZVOUS_ATTEMPT_FAILED"
            }
            .into(),
        };
        atomic_json(&path, &observation)?;

        let outgoing: NativeUnit = serde_json::from_slice(&fs::read(self.outgoing_path(unit))?)?;
        if accepted_by_transport && outgoing.awaits.is_none() {
            fs::remove_file(self.outgoing_path(unit))?;
        }
        Ok(())
    }

    pub fn retain_evidence(
        &self,
        original_unit: &str,
        opened: &OpenedUnit,
        retained_at_ms: i64,
        interrupt_after_retention: bool,
    ) -> Result<EvidenceRetention> {
        validate_unit_identity(original_unit)?;
        let outgoing_path = self.outgoing_path(original_unit);
        if !outgoing_path.exists() {
            let existing_path = self.evidence_path(original_unit);
            if !existing_path.exists() {
                return Err(Error::MissingFact(format!(
                    "outgoing native Unit {original_unit}"
                )));
            }
            let existing: EvidenceRetention = serde_json::from_slice(&fs::read(existing_path)?)?;
            if existing.evidence_unit != opened.unit
                || existing.class != opened.class
                || existing.sender != opened.sender
                || existing.recipient != opened.recipient
                || existing.value != opened.value
            {
                return Err(Error::NativeFrameRefused);
            }
            return Ok(existing);
        }
        let outgoing: NativeUnit = serde_json::from_slice(&fs::read(&outgoing_path)?)?;
        validate_evidence(&outgoing, opened, &self.identity)?;
        let retention = EvidenceRetention {
            protocol: "PORTER-CARRIAGE/1".into(),
            original_unit: original_unit.into(),
            evidence_unit: opened.unit.clone(),
            class: opened.class,
            sender: opened.sender.clone(),
            recipient: opened.recipient.clone(),
            value: opened.value.clone(),
            retained_at_ms,
        };
        publish_exact(
            &self.evidence_path(original_unit),
            &retention,
            original_unit,
        )?;
        if interrupt_after_retention {
            return Err(Error::Interrupted("native evidence retention"));
        }
        fs::remove_file(outgoing_path)?;
        Ok(retention)
    }

    pub fn evidence(&self, original_unit: &str) -> Result<Option<EvidenceRetention>> {
        validate_unit_identity(original_unit)?;
        let path = self.evidence_path(original_unit);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
    }

    fn recover_settled(&self) -> Result<()> {
        for entry in fs::read_dir(self.root.join("evidence"))? {
            let retained: EvidenceRetention = serde_json::from_slice(&fs::read(entry?.path())?)?;
            let outgoing = self.outgoing_path(&retained.original_unit);
            if outgoing.exists() {
                fs::remove_file(outgoing)?;
            }
        }
        Ok(())
    }

    fn outgoing_path(&self, identity: &str) -> PathBuf {
        self.root.join("outgoing").join(format!("{identity}.json"))
    }

    fn observation_path(&self, identity: &str) -> PathBuf {
        self.root
            .join("observations")
            .join(format!("{identity}.json"))
    }

    fn evidence_path(&self, identity: &str) -> PathBuf {
        self.root.join("evidence").join(format!("{identity}.json"))
    }
}

fn validate_unit(unit: &NativeUnit, identity: &str) -> Result<()> {
    if unit.protocol != "PORTER-CARRIAGE/1"
        || validate_unit_identity(&unit.unit).is_err()
        || unit.sender != identity
        || !safe_boundary_identity(&unit.recipient)
        || matches!(unit.class, UnitClass::Package | UnitClass::Ceremony) != unit.awaits.is_some()
        || matches!(
            unit.class,
            UnitClass::AcceptanceEvidence | UnitClass::RefusalEvidence | UnitClass::CeremonyResult
        ) && unit.awaits.is_some()
    {
        return Err(Error::Invalid("outgoing native Unit".into()));
    }
    match (&unit.class, &unit.awaits) {
        (UnitClass::Package, Some(EvidenceExpectation::Package(identity)))
            if identity.starts_with("PKG-") => {}
        (UnitClass::Ceremony, Some(EvidenceExpectation::Ceremony(identity)))
            if identity.starts_with("CM-") => {}
        (
            UnitClass::AcceptanceEvidence | UnitClass::RefusalEvidence | UnitClass::CeremonyResult,
            None,
        ) => {}
        _ => return Err(Error::Invalid("native evidence expectation".into())),
    }
    Ok(())
}

fn validate_evidence(outgoing: &NativeUnit, opened: &OpenedUnit, identity: &str) -> Result<()> {
    if opened.sender != outgoing.recipient || opened.recipient != identity {
        return Err(Error::NativeFrameRefused);
    }
    let matches = match (&outgoing.awaits, opened.class) {
        (Some(EvidenceExpectation::Package(expected)), UnitClass::AcceptanceEvidence) => {
            serde_json::from_value::<Acceptance>(opened.value.clone())
                .ok()
                .zip(outgoing_package(outgoing))
                .is_some_and(|(acceptance, package)| {
                    acceptance.protocol == "PORTER/1"
                        && acceptance.kind == "REMOTE_ACCEPTANCE"
                        && acceptance.recipient == outgoing.recipient
                        && acceptance.package.package == *expected
                        && acceptance.package == package
                        && canonical::digest(&package)
                            .is_ok_and(|digest| acceptance.package_digest == digest)
                })
        }
        (Some(EvidenceExpectation::Package(expected)), UnitClass::RefusalEvidence) => opened
            .value
            .get("package")
            .and_then(Value::as_str)
            .is_some_and(|package| package == expected),
        (Some(EvidenceExpectation::Ceremony(expected)), UnitClass::CeremonyResult) => {
            serde_json::from_value::<CeremonyResult>(opened.value.clone())
                .map(|result| result.ceremony == *expected)
                .unwrap_or(false)
        }
        _ => false,
    };
    if !matches {
        return Err(Error::NativeFrameRefused);
    }
    Ok(())
}

fn outgoing_package(outgoing: &NativeUnit) -> Option<Package> {
    serde_json::from_value(outgoing.value.clone())
        .ok()
        .or_else(|| {
            outgoing
                .value
                .get("package")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok())
        })
}

fn validate_unit_identity(value: &str) -> Result<()> {
    if value.starts_with("CU-") && safe_boundary_identity(value) {
        Ok(())
    } else {
        Err(Error::Invalid("native Unit identity".into()))
    }
}

fn safe_boundary_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
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

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    fn package() -> Package {
        Package {
            protocol: "PORTER/1".into(),
            package: "PKG-one".into(),
            sender: "origin".into(),
            recipient: "recipient".into(),
            kind: "opaque.demo".into(),
            created: 1,
            expires: 100,
            payload: json!({"opaque":true}),
            in_reply_to: None,
        }
    }

    fn outgoing() -> NativeUnit {
        NativeUnit {
            protocol: "PORTER-CARRIAGE/1".into(),
            unit: "CU-package-one".into(),
            class: UnitClass::Package,
            sender: "origin".into(),
            recipient: "recipient".into(),
            value: serde_json::to_value(package()).unwrap(),
            awaits: Some(EvidenceExpectation::Package("PKG-one".into())),
            created_at_ms: 1,
        }
    }

    fn acceptance() -> Acceptance {
        let package = package();
        Acceptance {
            protocol: "PORTER/1".into(),
            kind: "REMOTE_ACCEPTANCE".into(),
            acceptance: "AC-one".into(),
            recipient: "recipient".into(),
            package_digest: canonical::digest(&package).unwrap(),
            package,
            accepted_at_ms: 2,
            attests: "RECIPIENT_PORTER_ACCEPTED_DURABLE_RESPONSIBILITY".into(),
        }
    }

    #[test]
    fn transport_success_cannot_settle_a_unit_awaiting_evidence() {
        let temporary = TempDir::new().unwrap();
        let spool = UnitSpool::new(temporary.path(), "origin").unwrap();
        spool.queue(&outgoing()).unwrap();
        spool.note_attempt("CU-package-one", 10, true).unwrap();
        assert_eq!(spool.pending().unwrap().len(), 1);
        assert!(spool.evidence("CU-package-one").unwrap().is_none());
    }

    #[test]
    fn independent_returned_evidence_settles_only_its_exact_unit() {
        let temporary = TempDir::new().unwrap();
        let spool = UnitSpool::new(temporary.path(), "origin").unwrap();
        spool.queue(&outgoing()).unwrap();
        let opened = OpenedUnit {
            unit: "CU-evidence-one".into(),
            class: UnitClass::AcceptanceEvidence,
            sender: "recipient".into(),
            recipient: "origin".into(),
            value: serde_json::to_value(acceptance()).unwrap(),
        };
        spool
            .retain_evidence("CU-package-one", &opened, 20, false)
            .unwrap();
        assert!(spool.pending().unwrap().is_empty());
        assert!(spool.evidence("CU-package-one").unwrap().is_some());
    }

    #[test]
    fn retained_evidence_repairs_settlement_after_crash() {
        let temporary = TempDir::new().unwrap();
        let spool = UnitSpool::new(temporary.path(), "origin").unwrap();
        spool.queue(&outgoing()).unwrap();
        let opened = OpenedUnit {
            unit: "CU-evidence-one".into(),
            class: UnitClass::AcceptanceEvidence,
            sender: "recipient".into(),
            recipient: "origin".into(),
            value: serde_json::to_value(acceptance()).unwrap(),
        };
        assert!(matches!(
            spool.retain_evidence("CU-package-one", &opened, 20, true),
            Err(Error::Interrupted("native evidence retention"))
        ));
        assert_eq!(spool.pending().unwrap().len(), 1);
        let restarted = UnitSpool::new(temporary.path(), "origin").unwrap();
        assert!(restarted.pending().unwrap().is_empty());
        assert!(restarted.evidence("CU-package-one").unwrap().is_some());
    }

    #[test]
    fn wrong_sender_class_or_subject_cannot_settle_origin_knowledge() {
        let temporary = TempDir::new().unwrap();
        let spool = UnitSpool::new(temporary.path(), "origin").unwrap();
        spool.queue(&outgoing()).unwrap();
        for opened in [
            OpenedUnit {
                unit: "CU-forged".into(),
                class: UnitClass::AcceptanceEvidence,
                sender: "stranger".into(),
                recipient: "origin".into(),
                value: serde_json::to_value(acceptance()).unwrap(),
            },
            OpenedUnit {
                unit: "CU-wrong-class".into(),
                class: UnitClass::CeremonyResult,
                sender: "recipient".into(),
                recipient: "origin".into(),
                value: json!({}),
            },
            OpenedUnit {
                unit: "CU-wrong-subject".into(),
                class: UnitClass::RefusalEvidence,
                sender: "recipient".into(),
                recipient: "origin".into(),
                value: json!({"package":"PKG-other"}),
            },
        ] {
            assert!(matches!(
                spool.retain_evidence("CU-package-one", &opened, 20, false),
                Err(Error::NativeFrameRefused)
            ));
        }
        assert_eq!(spool.pending().unwrap().len(), 1);
        assert!(spool.evidence("CU-package-one").unwrap().is_none());
    }
}
