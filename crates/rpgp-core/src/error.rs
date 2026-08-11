/// Errors surfaced to the GUI.
///
/// Sequoia reports failures as `anyhow::Error`, so most variants are a thin
/// wrapper that keeps the original chain intact for the details pane.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("OpenPGP operation failed: {0:#}")]
    OpenPgp(#[from] anyhow::Error),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// An I/O failure from inside a Sequoia writer stack, where there is no
    /// useful path to attach.
    #[error("I/O error: {0}")]
    RawIo(#[from] std::io::Error),

    #[error("no certificate store directory could be determined")]
    NoStoreDir,

    #[error("no certificate matches {0}")]
    NoSuchCert(String),

    #[error("no usable secret key for {0}")]
    NoSecretKey(String),

    #[error("no usable encryption key for {0}")]
    NoEncryptionKey(String),

    #[error("{0}")]
    Invalid(String),
}

impl Error {
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Error::Invalid(message.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
