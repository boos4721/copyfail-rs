use std::io;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, CopyfailError>;

#[derive(Debug, Error)]
pub enum CopyfailError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid payload hex: {0}")]
    InvalidPayloadHex(#[from] hex::FromHexError),

    #[error("unsupported architecture: {0}")]
    UnsupportedArchitecture(String),

    #[error("syscall failure in {operation}: {source}")]
    SyscallFailure { operation: &'static str, source: io::Error },

    #[error("su not found")]
    SuNotFound,
}
