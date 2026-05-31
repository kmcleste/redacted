use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("vault entry not found: {0}")]
    VaultNotFound(String),

    #[error("vault entry expired: {0}")]
    VaultExpired(String),

    #[error("vault crypto error: {0}")]
    VaultCrypto(String),

    #[error("regex compilation error: {0}")]
    RegexCompile(#[from] regex::Error),
}

pub type Result<T> = std::result::Result<T, EngineError>;
