use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ceremony::{Ceremony, CeremonyEvidence, CeremonyService};
use crate::correspondence::CrashPoint;
use crate::model::Package;
use crate::native::{NativeFrame, OpenedUnit, PorterIdentity, UnitClass};
use crate::rendezvous::RendezvousKnowledge;
use crate::standing::{Admission, StandingStore};
use crate::unit_spool::{EvidenceExpectation, NativeUnit, UnitSpool};
use crate::{Error, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Dispatch {
    PackageAccepted,
    PackageRefused,
    CeremonyApplied,
    CeremonyPending,
    EvidenceRetained,
}

pub struct PorterNode {
    root: PathBuf,
    identity: PorterIdentity,
    peers: HashMap<String, [u8; 32]>,
    relationship_roots: HashMap<String, String>,
    spool: UnitSpool,
}

impl PorterNode {
    pub fn new(
        root: impl Into<PathBuf>,
        identity: PorterIdentity,
        peers: HashMap<String, [u8; 32]>,
        relationship_roots: HashMap<String, String>,
    ) -> Result<Self> {
        let root = root.into();
        let spool = UnitSpool::new(&root, identity.identity())?;
        Ok(Self {
            root,
            identity,
            peers,
            relationship_roots,
            spool,
        })
    }

    pub fn spool(&self) -> &UnitSpool {
        &self.spool
    }

    pub fn queue_package(
        &self,
        package: &Package,
        admission_proof: &[u8],
        at_ms: i64,
    ) -> Result<NativeUnit> {
        if package.sender != self.identity.identity() {
            return Err(Error::Invalid(
                "Porter cannot queue another sender's Package".into(),
            ));
        }
        self.spool.queue(&NativeUnit {
            protocol: "PORTER-CARRIAGE/1".into(),
            unit: format!("CU-PKG-{}", package.package),
            class: UnitClass::Package,
            sender: self.identity.identity().into(),
            recipient: package.recipient.clone(),
            value: serde_json::to_value(PackageCarriage {
                package: package.clone(),
                admission: BASE64.encode(admission_proof),
            })?,
            awaits: Some(EvidenceExpectation::Package(package.package.clone())),
            created_at_ms: at_ms,
        })
    }

    pub fn queue_ceremony(
        &self,
        ceremony: &Ceremony,
        evidence: &CeremonyEvidence,
    ) -> Result<NativeUnit> {
        if ceremony.origin != self.identity.identity() {
            return Err(Error::Invalid(
                "Porter cannot queue another origin's Ceremony".into(),
            ));
        }
        self.spool.queue(&NativeUnit {
            protocol: "PORTER-CARRIAGE/1".into(),
            unit: format!("CU-CM-{}", ceremony.ceremony),
            class: UnitClass::Ceremony,
            sender: self.identity.identity().into(),
            recipient: ceremony.recipient.clone(),
            value: serde_json::to_value(CeremonyCarriage {
                ceremony: ceremony.clone(),
                evidence: evidence.clone(),
            })?,
            awaits: Some(EvidenceExpectation::Ceremony(ceremony.ceremony.clone())),
            created_at_ms: ceremony.created_at_ms,
        })
    }

    pub fn frame(&self, unit: &NativeUnit) -> Result<Vec<u8>> {
        if unit.sender != self.identity.identity() {
            return Err(Error::Invalid(
                "outgoing Unit belongs to another Porter".into(),
            ));
        }
        let public_key = self
            .peers
            .get(&unit.recipient)
            .ok_or(Error::RendezvousUnavailable {
                identity: unit.recipient.clone(),
                knowledge: "IDENTITY_NOT_KNOWN_LOCALLY".into(),
            })?;
        NativeFrame::seal(
            &unit.value,
            &self.identity,
            &unit.recipient,
            *public_key,
            unit.class,
            &unit.unit,
        )
    }

    pub fn frame_at(
        &self,
        unit: &NativeUnit,
        knowledge: &RendezvousKnowledge,
        at_ms: i64,
    ) -> Result<Vec<u8>> {
        if unit.sender != self.identity.identity() {
            return Err(Error::Invalid(
                "outgoing Unit belongs to another Porter".into(),
            ));
        }
        let (_location, encoded_key) = knowledge.route(&unit.recipient, at_ms)?;
        let public_key: [u8; 32] = BASE64
            .decode(encoded_key)
            .map_err(|_| Error::RendezvousRefused)?
            .try_into()
            .map_err(|_| Error::RendezvousRefused)?;
        NativeFrame::seal(
            &unit.value,
            &self.identity,
            &unit.recipient,
            public_key,
            unit.class,
            &unit.unit,
        )
    }

    pub fn receive(&self, frame: &[u8], at_ms: i64) -> Result<Dispatch> {
        let opened = NativeFrame::open(frame, &self.identity, &self.peers)?;
        match opened.class {
            UnitClass::Package => self.receive_package(opened, at_ms),
            UnitClass::Ceremony => self.receive_ceremony(opened, at_ms),
            UnitClass::AcceptanceEvidence | UnitClass::RefusalEvidence => {
                self.receive_package_evidence(opened, at_ms)
            }
            UnitClass::CeremonyResult => self.receive_ceremony_result(opened, at_ms),
        }
    }

    fn receive_package(&self, opened: OpenedUnit, at_ms: i64) -> Result<Dispatch> {
        let carried: PackageCarriage =
            serde_json::from_value(opened.value).map_err(|_| Error::NativeFrameRefused)?;
        if carried.package.sender != opened.sender || carried.package.recipient != opened.recipient
        {
            return Err(Error::NativeFrameRefused);
        }
        let first = self
            .relationship_roots
            .get(&opened.sender)
            .ok_or(Error::CeremonyRefused)?;
        let proof = BASE64
            .decode(carried.admission)
            .map_err(|_| Error::NativeFrameRefused)?;
        let standing = StandingStore::new(&self.root)?;
        match standing.admit(first, &carried.package, &proof, at_ms, CrashPoint::None)? {
            Admission::Accepted(acceptance) => {
                self.queue_evidence(
                    &opened.sender,
                    UnitClass::AcceptanceEvidence,
                    format!("CU-EV-{}", carried.package.package),
                    serde_json::to_value(&*acceptance)?,
                    acceptance.accepted_at_ms,
                )?;
                Ok(Dispatch::PackageAccepted)
            }
            Admission::Refused => {
                self.queue_evidence(
                    &opened.sender,
                    UnitClass::RefusalEvidence,
                    format!("CU-EV-{}", carried.package.package),
                    json!({
                        "kind": "REFUSE",
                        "reason": "CORRESPONDENCE_NOT_ADMITTED",
                        "package": carried.package.package,
                    }),
                    carried.package.created,
                )?;
                Ok(Dispatch::PackageRefused)
            }
        }
    }

    fn receive_ceremony(&self, opened: OpenedUnit, at_ms: i64) -> Result<Dispatch> {
        let carried: CeremonyCarriage =
            serde_json::from_value(opened.value).map_err(|_| Error::NativeFrameRefused)?;
        if carried.ceremony.origin != opened.sender
            || carried.ceremony.recipient != opened.recipient
        {
            return Err(Error::NativeFrameRefused);
        }
        let service = CeremonyService::new(&self.root, self.identity.identity())?;
        let result = service.receive(&carried.ceremony, &carried.evidence, at_ms)?;
        if result.state == "PENDING_PREDECESSOR" {
            return Ok(Dispatch::CeremonyPending);
        }
        self.queue_evidence(
            &opened.sender,
            UnitClass::CeremonyResult,
            format!("CU-CR-{}", carried.ceremony.ceremony),
            serde_json::to_value(result)?,
            carried.ceremony.created_at_ms,
        )?;
        Ok(Dispatch::CeremonyApplied)
    }

    fn receive_package_evidence(&self, opened: OpenedUnit, at_ms: i64) -> Result<Dispatch> {
        let package = opened
            .value
            .get("package")
            .and_then(|value| {
                value.as_str().map(str::to_owned).or_else(|| {
                    value
                        .get("package")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
            })
            .ok_or(Error::NativeFrameRefused)?;
        self.retain_expected(EvidenceExpectation::Package(package), &opened, at_ms)
    }

    fn receive_ceremony_result(&self, opened: OpenedUnit, at_ms: i64) -> Result<Dispatch> {
        let ceremony = opened
            .value
            .get("ceremony")
            .and_then(Value::as_str)
            .ok_or(Error::NativeFrameRefused)?;
        self.retain_expected(
            EvidenceExpectation::Ceremony(ceremony.into()),
            &opened,
            at_ms,
        )
    }

    fn retain_expected(
        &self,
        expectation: EvidenceExpectation,
        opened: &OpenedUnit,
        at_ms: i64,
    ) -> Result<Dispatch> {
        let unit = self
            .spool
            .awaiting(&expectation)?
            .ok_or(Error::NativeFrameRefused)?;
        self.spool
            .retain_evidence(&unit.unit, opened, at_ms, false)?;
        Ok(Dispatch::EvidenceRetained)
    }

    fn queue_evidence(
        &self,
        recipient: &str,
        class: UnitClass,
        unit: String,
        value: Value,
        created_at_ms: i64,
    ) -> Result<NativeUnit> {
        self.spool.queue(&NativeUnit {
            protocol: "PORTER-CARRIAGE/1".into(),
            unit,
            class,
            sender: self.identity.identity().into(),
            recipient: recipient.into(),
            value,
            awaits: None,
            created_at_ms,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageCarriage {
    package: Package,
    admission: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CeremonyCarriage {
    ceremony: Ceremony,
    evidence: CeremonyEvidence,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::canonical;
    use crate::rendezvous::Location;
    use crate::standing::{Introduction, Terms};

    fn package() -> Package {
        Package {
            protocol: "PORTER/1".into(),
            package: "PKG-journey".into(),
            sender: "origin".into(),
            recipient: "recipient".into(),
            kind: "opaque.demo".into(),
            created: 1,
            expires: 10_000,
            payload: json!({"meaning":"belongs elsewhere"}),
            in_reply_to: None,
        }
    }

    #[test]
    fn lost_evidence_then_exact_retry_repairs_origin_knowledge() {
        let temporary = TempDir::new().unwrap();
        let origin_root = temporary.path().join("origin");
        let recipient_root = temporary.path().join("recipient");
        let origin_identity = PorterIdentity::from_private_bytes("origin", [7; 32]).unwrap();
        let recipient_identity = PorterIdentity::from_private_bytes("recipient", [11; 32]).unwrap();
        let origin = PorterNode::new(
            &origin_root,
            origin_identity.clone(),
            HashMap::from([("recipient".into(), recipient_identity.public_bytes())]),
            HashMap::new(),
        )
        .unwrap();
        let recipient = PorterNode::new(
            &recipient_root,
            recipient_identity.clone(),
            HashMap::from([("origin".into(), origin_identity.public_bytes())]),
            HashMap::from([("origin".into(), "IN-origin".into())]),
        )
        .unwrap();
        let standing = StandingStore::new(&recipient_root).unwrap();
        standing
            .establish(
                &Introduction {
                    protocol: "PORTER-INTRODUCTION/1".into(),
                    kind: "INTRODUCTION".into(),
                    introduction: "IN-origin".into(),
                    sender: "origin".into(),
                    recipient: "recipient".into(),
                    issuer: "fixture".into(),
                    terms: Terms {
                        kinds: vec!["opaque.demo".into()],
                        maximum_package_bytes: 4096,
                        maximum_outstanding_count: 4,
                        maximum_outstanding_bytes: 16_384,
                        expires_at_ms: 9_000,
                    },
                    established_at_ms: 1,
                },
                b"operational",
            )
            .unwrap();
        let package = package();
        let proof = standing.proof("IN-origin", &package).unwrap();
        let unit = origin.queue_package(&package, &proof, 2).unwrap();

        let origin_routes = RendezvousKnowledge::new(&origin_root, HashMap::new()).unwrap();
        origin_routes
            .establish_genesis(
                "recipient",
                Location {
                    host: "recipient-carrier".into(),
                    port: 7411,
                },
                BASE64.encode(recipient_identity.public_bytes()),
            )
            .unwrap();
        let recipient_routes = RendezvousKnowledge::new(&recipient_root, HashMap::new()).unwrap();
        recipient_routes
            .establish_genesis(
                "origin",
                Location {
                    host: "origin-carrier".into(),
                    port: 7412,
                },
                BASE64.encode(origin_identity.public_bytes()),
            )
            .unwrap();

        let frame = origin.frame_at(&unit, &origin_routes, 3).unwrap();
        assert_eq!(
            recipient.receive(&frame, 3).unwrap(),
            Dispatch::PackageAccepted
        );
        origin.spool.note_attempt(&unit.unit, 3, true).unwrap();
        assert_eq!(origin.spool.pending().unwrap().len(), 1);
        let acceptance_path = recipient_root.join("acceptances/PKG-journey.json");
        let first_acceptance: crate::Acceptance =
            serde_json::from_slice(&fs::read(&acceptance_path).unwrap()).unwrap();

        // The first evidence journey is lost. Exact Package retry regenerates
        // the same AC and the same evidence Unit without another acceptance.
        assert_eq!(
            recipient.receive(&frame, 4).unwrap(),
            Dispatch::PackageAccepted
        );
        let second_acceptance: crate::Acceptance =
            serde_json::from_slice(&fs::read(&acceptance_path).unwrap()).unwrap();
        assert_eq!(first_acceptance, second_acceptance);
        let evidence = recipient
            .spool
            .pending()
            .unwrap()
            .into_iter()
            .find(|item| item.class == UnitClass::AcceptanceEvidence)
            .unwrap();
        let evidence_frame = recipient.frame_at(&evidence, &recipient_routes, 5).unwrap();
        assert_eq!(
            origin.receive(&evidence_frame, 5).unwrap(),
            Dispatch::EvidenceRetained
        );
        assert!(origin.spool.pending().unwrap().is_empty());
        assert!(origin.spool.evidence(&unit.unit).unwrap().is_some());
        assert_eq!(
            canonical::digest(&package).unwrap(),
            first_acceptance.package_digest
        );
    }
}
