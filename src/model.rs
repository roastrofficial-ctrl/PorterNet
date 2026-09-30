use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Package {
    pub protocol: String,
    pub package: String,
    #[serde(rename = "from")]
    pub sender: String,
    #[serde(rename = "to")]
    pub recipient: String,
    pub kind: String,
    pub created: i64,
    pub expires: i64,
    pub payload: Value,
    #[serde(flatten)]
    pub extensions: std::collections::BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Lodgement {
    pub protocol: String,
    pub kind: String,
    pub lodgement: String,
    pub package: Package,
    pub package_digest: String,
    pub lodged_at_ms: i64,
    pub attests: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Acceptance {
    pub protocol: String,
    pub kind: String,
    pub acceptance: String,
    pub recipient: String,
    pub package: Package,
    pub package_digest: String,
    pub accepted_at_ms: i64,
    pub attests: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Collection {
    pub protocol: String,
    pub kind: String,
    pub collection: String,
    pub package: Package,
    pub acceptance: String,
    pub collector: String,
    pub collected_at_ms: i64,
    pub attests: String,
}

/// Protected AC evidence; local Acceptance storage is a separate representation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceReceipt {
    pub protocol: String,
    pub kind: String,
    pub package: String,
    pub state: String,
    pub recipient: String,
    pub acceptance: String,
    pub accepted_at_ms: i64,
    pub package_digest: String,
    pub attests: String,
}
impl From<&Acceptance> for AcceptanceReceipt {
    fn from(ac: &Acceptance) -> Self {
        Self {
            protocol: "PORTER/1".into(),
            kind: "RECEIPT".into(),
            package: ac.package.package.clone(),
            state: "REMOTE_PORTER_DURABLY_ACCEPTED".into(),
            recipient: ac.recipient.clone(),
            acceptance: ac.acceptance.clone(),
            accepted_at_ms: ac.accepted_at_ms,
            package_digest: ac.package_digest.clone(),
            attests: "RECIPIENT_PORTER_ACCEPTED_RESPONSIBILITY".into(),
        }
    }
}
