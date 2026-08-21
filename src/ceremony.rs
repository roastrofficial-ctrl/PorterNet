use std::fs;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::canonical;
use crate::publication::atomic_json;
use crate::standing::{Introduction, StandingChange, StandingStore, Terms};
use crate::{Error, Result};

type HmacSha256 = Hmac<Sha256>;
const MAX_CEREMONY_BYTES: usize = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyCrashPoint {
    None,
    AfterPresented,
    AfterAuthorityVerification,
    AfterCandidate,
    AfterChange,
    AfterResult,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CeremonialGrant {
    pub protocol: String,
    pub grant: String,
    pub recipient: String,
    pub origin: String,
    pub relationship_sender: String,
    pub maximum_terms: Terms,
    pub expires_at_ms: i64,
    pub maximum_changes: u64,
    pub maximum_pending: u64,
    pub may_terminate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ceremony {
    pub protocol: String,
    pub ceremony: String,
    #[serde(rename = "from")]
    pub origin: String,
    #[serde(rename = "to")]
    pub recipient: String,
    pub sender: String,
    pub predecessor: String,
    pub successor: Option<String>,
    pub replacement_capability: Option<String>,
    pub terms: Option<Terms>,
    pub reason: String,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CeremonyEvidence {
    pub protocol: String,
    pub ceremony_digest: String,
    pub proof: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CeremonyResult {
    pub protocol: String,
    pub kind: String,
    pub ceremony: String,
    pub recipient: String,
    pub sender: String,
    pub state: String,
    pub ceremony_digest: String,
    pub change: Option<String>,
    pub successor: Option<String>,
}

pub struct CeremonyService {
    root: PathBuf,
    recipient: String,
    standing: StandingStore,
}

impl CeremonyService {
    pub fn new(root: impl Into<PathBuf>, recipient: impl Into<String>) -> Result<Self> {
        let root = root.into();
        for directory in ["grants", "secrets", "presented", "pending", "results"] {
            fs::create_dir_all(root.join("ceremonies").join(directory))?;
        }
        Ok(Self {
            standing: StandingStore::new(&root)?,
            recipient: recipient.into(),
            root,
        })
    }

    pub fn establish_grant(&self, grant: &CeremonialGrant, capability: &[u8]) -> Result<()> {
        if grant.protocol != "PORTER-CEREMONIAL-GRANT/1"
            || !grant.grant.starts_with("CG-")
            || grant.recipient != self.recipient
            || grant.origin != grant.relationship_sender
            || !safe_identity(&grant.origin)
            || grant.maximum_changes == 0
        {
            return Err(Error::Invalid("ceremonial grant boundary".into()));
        }
        publish_exact(&self.grant_path(&grant.origin), grant, &grant.grant)?;
        publish_secret(&self.secret_path(&grant.origin), capability)
    }

    pub fn evidence(capability: &[u8], ceremony: &Ceremony) -> Result<CeremonyEvidence> {
        let digest = canonical::digest(ceremony)?;
        let mut mac = HmacSha256::new_from_slice(capability)
            .map_err(|_| Error::Invalid("invalid ceremonial capability".into()))?;
        mac.update(digest.as_bytes());
        Ok(CeremonyEvidence {
            protocol: "PORTER-CEREMONY/1".into(),
            ceremony_digest: digest,
            proof: format!("hmac-sha256:{:x}", mac.finalize().into_bytes()),
        })
    }

    pub fn receive(
        &self,
        ceremony: &Ceremony,
        evidence: &CeremonyEvidence,
        at_ms: i64,
    ) -> Result<CeremonyResult> {
        self.receive_with_crash(ceremony, evidence, at_ms, CeremonyCrashPoint::None)
    }

    pub fn receive_with_crash(
        &self,
        ceremony: &Ceremony,
        evidence: &CeremonyEvidence,
        at_ms: i64,
        crash: CeremonyCrashPoint,
    ) -> Result<CeremonyResult> {
        self.receive_inner(ceremony, evidence, at_ms, true, crash)
    }

    fn receive_inner(
        &self,
        ceremony: &Ceremony,
        evidence: &CeremonyEvidence,
        at_ms: i64,
        drain: bool,
        crash: CeremonyCrashPoint,
    ) -> Result<CeremonyResult> {
        if canonical::bytes(ceremony)?.len() > MAX_CEREMONY_BYTES || !self.valid_shape(ceremony) {
            return Err(Error::CeremonyRefused);
        }
        let grant: CeremonialGrant = read_required(&self.grant_path(&ceremony.origin))?;
        let secret = fs::read(self.secret_path(&ceremony.origin))?;
        if grant.expires_at_ms <= at_ms
            || !terms_within(ceremony.terms.as_ref(), &grant)
            || !verify_evidence(&secret, ceremony, evidence)?
        {
            return Err(Error::CeremonyRefused);
        }

        let digest = canonical::digest(ceremony)?;
        self.reject_collision(&self.presented_path(&ceremony.ceremony), &digest)?;
        self.reject_collision(&self.pending_path(&ceremony.ceremony), &digest)?;
        let result_path = self.result_path(&ceremony.ceremony);
        if result_path.exists() {
            return read_required(&result_path);
        }
        if let Some(change) = self.standing.transition(&ceremony.predecessor)? {
            if change.cause.as_deref() != Some(&ceremony.ceremony) {
                return Err(Error::CeremonyRefused);
            }
            let result = self.applied_result(ceremony, &change)?;
            atomic_json(&result_path, &result)?;
            return Ok(result);
        }

        let current = self
            .standing
            .current_for(&ceremony.sender, &ceremony.recipient)?;
        if current.as_ref().map(|value| value.introduction.as_str())
            != Some(ceremony.predecessor.as_str())
        {
            if self.standing.introduction(&ceremony.predecessor).is_ok() {
                return Err(Error::CeremonyRefused);
            }
            if self.pending_count()? >= grant.maximum_pending {
                return Err(Error::CeremonyRefused);
            }
            let pending = Pending {
                digest,
                ceremony: ceremony.clone(),
                evidence: evidence.clone(),
            };
            publish_exact(
                &self.pending_path(&ceremony.ceremony),
                &pending,
                &ceremony.ceremony,
            )?;
            return self.result(ceremony, "PENDING_PREDECESSOR", None);
        }
        if self.change_count(&ceremony.sender)? >= grant.maximum_changes {
            return Err(Error::CeremonyRefused);
        }
        publish_exact(
            &self.presented_path(&ceremony.ceremony),
            &Presented {
                digest,
                ceremony: ceremony.clone(),
            },
            &ceremony.ceremony,
        )?;
        interrupted(
            crash == CeremonyCrashPoint::AfterPresented,
            "ceremony presentation",
        )?;
        interrupted(
            crash == CeremonyCrashPoint::AfterAuthorityVerification,
            "ceremonial authority verification",
        )?;

        if let (Some(successor), Some(terms), Some(capability)) = (
            ceremony.successor.as_ref(),
            ceremony.terms.as_ref(),
            ceremony.replacement_capability.as_ref(),
        ) {
            self.standing.establish(
                &Introduction {
                    protocol: "PORTER-INTRODUCTION/1".into(),
                    kind: "INTRODUCTION".into(),
                    introduction: successor.clone(),
                    sender: ceremony.sender.clone(),
                    recipient: ceremony.recipient.clone(),
                    issuer: "CEREMONIAL_AUTHORITY".into(),
                    terms: terms.clone(),
                    established_at_ms: ceremony.created_at_ms,
                },
                capability.as_bytes(),
            )?;
        }
        interrupted(
            crash == CeremonyCrashPoint::AfterCandidate,
            "candidate Introduction",
        )?;
        let change = StandingChange {
            protocol: "PORTER-STANDING/1".into(),
            kind: "STANDING_CHANGE".into(),
            change: format!("SC-{}", &ceremony.ceremony[3..]),
            predecessor: ceremony.predecessor.clone(),
            successor: ceremony.successor.clone(),
            cause: Some(ceremony.ceremony.clone()),
            changed_at_ms: at_ms,
        };
        self.standing.change(&change)?;
        interrupted(crash == CeremonyCrashPoint::AfterChange, "SC")?;
        let result = self.applied_result(ceremony, &change)?;
        atomic_json(&result_path, &result)?;
        interrupted(crash == CeremonyCrashPoint::AfterResult, "ceremony result")?;
        let _ = fs::remove_file(self.pending_path(&ceremony.ceremony));
        if drain {
            self.drain_pending(at_ms)?;
        }
        Ok(result)
    }

    fn drain_pending(&self, at_ms: i64) -> Result<()> {
        loop {
            let mut progressed = false;
            for entry in fs::read_dir(self.root.join("ceremonies/pending"))? {
                let pending: Pending = serde_json::from_slice(&fs::read(entry?.path())?)?;
                let current = self
                    .standing
                    .current_for(&pending.ceremony.sender, &pending.ceremony.recipient)?;
                if current.as_ref().map(|value| value.introduction.as_str())
                    == Some(pending.ceremony.predecessor.as_str())
                {
                    self.receive_inner(
                        &pending.ceremony,
                        &pending.evidence,
                        at_ms,
                        false,
                        CeremonyCrashPoint::None,
                    )?;
                    progressed = true;
                    break;
                }
            }
            if !progressed {
                return Ok(());
            }
        }
    }

    fn valid_shape(&self, value: &Ceremony) -> bool {
        value.protocol == "PORTER-CEREMONY/1"
            && value.ceremony.starts_with("CM-")
            && value.recipient == self.recipient
            && value.sender == value.origin
            && safe_identity(&value.origin)
            && value.predecessor.starts_with("IN-")
            && match (
                &value.terms,
                &value.successor,
                &value.replacement_capability,
            ) {
                (None, None, None) => true,
                (Some(_), Some(successor), Some(_)) => successor.starts_with("IN-"),
                _ => false,
            }
    }

    fn result(
        &self,
        value: &Ceremony,
        state: &str,
        change: Option<&StandingChange>,
    ) -> Result<CeremonyResult> {
        Ok(CeremonyResult {
            protocol: "PORTER-CEREMONY/1".into(),
            kind: "CEREMONY_RESULT".into(),
            ceremony: value.ceremony.clone(),
            recipient: self.recipient.clone(),
            sender: value.sender.clone(),
            state: state.into(),
            ceremony_digest: canonical::digest(value)?,
            change: change.map(|item| item.change.clone()),
            successor: change.and_then(|item| item.successor.clone()),
        })
    }
    fn applied_result(&self, value: &Ceremony, change: &StandingChange) -> Result<CeremonyResult> {
        self.result(value, "APPLIED", Some(change))
    }
    fn reject_collision(&self, path: &Path, digest: &str) -> Result<()> {
        if path.exists() {
            let stored: StoredDigest = serde_json::from_slice(&fs::read(path)?)?;
            if stored.digest() != digest {
                return Err(Error::CeremonyRefused);
            }
        }
        Ok(())
    }
    fn pending_count(&self) -> Result<u64> {
        Ok(fs::read_dir(self.root.join("ceremonies/pending"))?.count() as u64)
    }
    fn change_count(&self, sender: &str) -> Result<u64> {
        let mut count = 0;
        for entry in fs::read_dir(self.root.join("standing_changes"))? {
            let change: StandingChange = serde_json::from_slice(&fs::read(entry?.path())?)?;
            if change
                .cause
                .as_deref()
                .is_some_and(|cause| cause.starts_with("CM-"))
                && self.standing.introduction(&change.predecessor)?.sender == sender
            {
                count += 1;
            }
        }
        Ok(count)
    }
    fn grant_path(&self, origin: &str) -> PathBuf {
        self.root
            .join("ceremonies/grants")
            .join(format!("{origin}.json"))
    }
    fn secret_path(&self, origin: &str) -> PathBuf {
        self.root
            .join("ceremonies/secrets")
            .join(format!("{origin}.key"))
    }
    fn presented_path(&self, identity: &str) -> PathBuf {
        self.root
            .join("ceremonies/presented")
            .join(format!("{identity}.json"))
    }
    fn pending_path(&self, identity: &str) -> PathBuf {
        self.root
            .join("ceremonies/pending")
            .join(format!("{identity}.json"))
    }
    fn result_path(&self, identity: &str) -> PathBuf {
        self.root
            .join("ceremonies/results")
            .join(format!("{identity}.json"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Presented {
    digest: String,
    ceremony: Ceremony,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Pending {
    digest: String,
    ceremony: Ceremony,
    evidence: CeremonyEvidence,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredDigest {
    Presented(Presented),
    Pending(Pending),
}
impl StoredDigest {
    fn digest(&self) -> &str {
        match self {
            Self::Presented(v) => &v.digest,
            Self::Pending(v) => &v.digest,
        }
    }
}

fn terms_within(terms: Option<&Terms>, grant: &CeremonialGrant) -> bool {
    let Some(terms) = terms else {
        return grant.may_terminate;
    };
    terms
        .kinds
        .iter()
        .all(|kind| grant.maximum_terms.kinds.contains(kind))
        && terms.maximum_package_bytes <= grant.maximum_terms.maximum_package_bytes
        && terms.maximum_outstanding_count <= grant.maximum_terms.maximum_outstanding_count
        && terms.maximum_outstanding_bytes <= grant.maximum_terms.maximum_outstanding_bytes
        && terms.expires_at_ms <= grant.maximum_terms.expires_at_ms
}

fn verify_evidence(
    capability: &[u8],
    ceremony: &Ceremony,
    evidence: &CeremonyEvidence,
) -> Result<bool> {
    let digest = canonical::digest(ceremony)?;
    if evidence.protocol != "PORTER-CEREMONY/1" || evidence.ceremony_digest != digest {
        return Ok(false);
    }
    let Some(encoded) = evidence.proof.strip_prefix("hmac-sha256:") else {
        return Ok(false);
    };
    let Some(tag) = decode_hex(encoded) else {
        return Ok(false);
    };
    let mut mac = HmacSha256::new_from_slice(capability)
        .map_err(|_| Error::Invalid("invalid ceremonial capability".into()))?;
    mac.update(digest.as_bytes());
    Ok(mac.verify_slice(&tag).is_ok())
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

fn read_required<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    if !path.exists() {
        return Err(Error::CeremonyRefused);
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
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
    if path.exists() {
        return if fs::read(path)? == capability {
            Ok(())
        } else {
            Err(Error::IdentityCollision(path.display().to_string()))
        };
    }
    use std::io::Write;
    let temporary = path.with_extension("tmp");
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
    fs::rename(temporary, path)?;
    Ok(())
}

fn safe_identity(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
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

    const CEREMONIAL: &[u8] = b"separate-ceremonial-root";

    fn terms() -> Terms {
        Terms {
            kinds: vec!["opaque.demo".into()],
            maximum_package_bytes: 4096,
            maximum_outstanding_count: 2,
            maximum_outstanding_bytes: 8192,
            expires_at_ms: 10_000,
        }
    }

    fn setup(maximum_changes: u64, maximum_pending: u64) -> (TempDir, CeremonyService) {
        let temporary = TempDir::new().unwrap();
        let standing = StandingStore::new(temporary.path()).unwrap();
        standing
            .establish(
                &Introduction {
                    protocol: "PORTER-INTRODUCTION/1".into(),
                    kind: "INTRODUCTION".into(),
                    introduction: "IN-first".into(),
                    sender: "origin".into(),
                    recipient: "recipient".into(),
                    issuer: "fixture-authority".into(),
                    terms: terms(),
                    established_at_ms: 1,
                },
                b"operational-old",
            )
            .unwrap();
        let service = CeremonyService::new(temporary.path(), "recipient").unwrap();
        service
            .establish_grant(
                &CeremonialGrant {
                    protocol: "PORTER-CEREMONIAL-GRANT/1".into(),
                    grant: "CG-origin-recipient".into(),
                    recipient: "recipient".into(),
                    origin: "origin".into(),
                    relationship_sender: "origin".into(),
                    maximum_terms: terms(),
                    expires_at_ms: 20_000,
                    maximum_changes,
                    maximum_pending,
                    may_terminate: true,
                },
                CEREMONIAL,
            )
            .unwrap();
        (temporary, service)
    }

    fn ceremony(identity: &str, predecessor: &str, successor: &str) -> Ceremony {
        Ceremony {
            protocol: "PORTER-CEREMONY/1".into(),
            ceremony: identity.into(),
            origin: "origin".into(),
            recipient: "recipient".into(),
            sender: "origin".into(),
            predecessor: predecessor.into(),
            successor: Some(successor.into()),
            replacement_capability: Some(format!("capability-{successor}")),
            terms: Some(terms()),
            reason: "COMPROMISE_KNOWN".into(),
            created_at_ms: 100,
        }
    }

    #[test]
    fn ceremony_applies_at_sc_replays_and_creates_no_host_correspondence() {
        let (temporary, service) = setup(2, 2);
        let value = ceremony("CM-one", "IN-first", "IN-second");
        let evidence = CeremonyService::evidence(CEREMONIAL, &value).unwrap();
        let first = service.receive(&value, &evidence, 200).unwrap();
        assert_eq!(first.state, "APPLIED");
        assert_eq!(first, service.receive(&value, &evidence, 300).unwrap());
        assert!(
            temporary
                .path()
                .join("acceptances")
                .read_dir()
                .unwrap()
                .next()
                .is_none()
        );
        assert!(
            temporary
                .path()
                .join("collections")
                .read_dir()
                .unwrap()
                .next()
                .is_none()
        );
        let mut changed = value;
        changed.reason = "ATTACKER_MUTATION".into();
        let changed_evidence = CeremonyService::evidence(CEREMONIAL, &changed).unwrap();
        assert!(matches!(
            service.receive(&changed, &changed_evidence, 300),
            Err(Error::CeremonyRefused)
        ));
    }

    #[test]
    fn valid_out_of_order_ceremony_is_bounded_then_drained() {
        let (_temporary, service) = setup(2, 1);
        let first = ceremony("CM-one", "IN-first", "IN-second");
        let second = ceremony("CM-two", "IN-second", "IN-third");
        let second_evidence = CeremonyService::evidence(CEREMONIAL, &second).unwrap();
        assert_eq!(
            service
                .receive(&second, &second_evidence, 100)
                .unwrap()
                .state,
            "PENDING_PREDECESSOR"
        );
        let excess = ceremony("CM-excess", "IN-unknown", "IN-fourth");
        let excess_evidence = CeremonyService::evidence(CEREMONIAL, &excess).unwrap();
        assert!(matches!(
            service.receive(&excess, &excess_evidence, 100),
            Err(Error::CeremonyRefused)
        ));
        let first_evidence = CeremonyService::evidence(CEREMONIAL, &first).unwrap();
        service.receive(&first, &first_evidence, 200).unwrap();
        assert_eq!(
            service
                .receive(&second, &second_evidence, 300)
                .unwrap()
                .state,
            "APPLIED"
        );
    }

    #[test]
    fn distinct_authority_and_finite_grant_are_enforced_before_state() {
        let (temporary, service) = setup(1, 1);
        let value = ceremony("CM-one", "IN-first", "IN-second");
        let forged = CeremonyService::evidence(b"operational-old", &value).unwrap();
        let before = fs::read_dir(temporary.path().join("ceremonies/presented"))
            .unwrap()
            .count();
        assert!(matches!(
            service.receive(&value, &forged, 100),
            Err(Error::CeremonyRefused)
        ));
        assert_eq!(
            before,
            fs::read_dir(temporary.path().join("ceremonies/presented"))
                .unwrap()
                .count()
        );
        let evidence = CeremonyService::evidence(CEREMONIAL, &value).unwrap();
        service.receive(&value, &evidence, 100).unwrap();
        let second = ceremony("CM-two", "IN-second", "IN-third");
        let evidence = CeremonyService::evidence(CEREMONIAL, &second).unwrap();
        assert!(matches!(
            service.receive(&second, &evidence, 200),
            Err(Error::CeremonyRefused)
        ));
    }

    #[test]
    fn crash_matrix_reconstructs_from_the_sc_threshold() {
        for point in [
            CeremonyCrashPoint::AfterPresented,
            CeremonyCrashPoint::AfterAuthorityVerification,
            CeremonyCrashPoint::AfterCandidate,
            CeremonyCrashPoint::AfterChange,
            CeremonyCrashPoint::AfterResult,
        ] {
            let (temporary, service) = setup(2, 2);
            let value = ceremony("CM-crash", "IN-first", "IN-second");
            let evidence = CeremonyService::evidence(CEREMONIAL, &value).unwrap();
            assert!(matches!(
                service.receive_with_crash(&value, &evidence, 200, point),
                Err(Error::Interrupted(_))
            ));

            let restarted = CeremonyService::new(temporary.path(), "recipient").unwrap();
            let standing = StandingStore::new(temporary.path()).unwrap();
            let before_threshold = matches!(
                point,
                CeremonyCrashPoint::AfterPresented
                    | CeremonyCrashPoint::AfterAuthorityVerification
                    | CeremonyCrashPoint::AfterCandidate
            );
            assert_eq!(
                standing
                    .current_for("origin", "recipient")
                    .unwrap()
                    .unwrap()
                    .introduction,
                if before_threshold {
                    "IN-first"
                } else {
                    "IN-second"
                }
            );

            let repaired = restarted.receive(&value, &evidence, 300).unwrap();
            assert_eq!(repaired.state, "APPLIED");
            assert_eq!(repaired.successor.as_deref(), Some("IN-second"));
            assert_eq!(
                standing
                    .current_for("origin", "recipient")
                    .unwrap()
                    .unwrap()
                    .introduction,
                "IN-second"
            );
            assert!(
                temporary
                    .path()
                    .join("acceptances")
                    .read_dir()
                    .unwrap()
                    .next()
                    .is_none()
            );
            assert!(
                temporary
                    .path()
                    .join("collections")
                    .read_dir()
                    .unwrap()
                    .next()
                    .is_none()
            );
        }
    }
}
