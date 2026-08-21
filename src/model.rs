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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
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
