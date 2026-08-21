use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid PORTER value: {0}")]
    Invalid(String),
    #[error("identity replay used different canonical bytes: {0}")]
    IdentityCollision(String),
    #[error("canonical fact does not exist: {0}")]
    MissingFact(String),
    #[error("simulated interruption after {0}")]
    Interrupted(&'static str),
    #[error("CEREMONY_NOT_ADMITTED")]
    CeremonyRefused,
    #[error("I/O failure: {0}")]
    Io(#[from] io::Error),
    #[error("JSON failure: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
