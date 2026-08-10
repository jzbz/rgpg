//! Key generation.

use std::time::Duration;

use sequoia_openpgp::Cert;
use sequoia_openpgp::cert::{CertBuilder, CipherSuite};
use sequoia_openpgp::packet::Signature;

use crate::error::Result;

/// Key types offered in the new-key dialog.
///
/// Deliberately short: Kleopatra's full algorithm matrix is a footgun, and the
/// only two answers that matter are "the modern default" and "RSA, because the
/// other end is old".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyType {
    /// Ed25519 signing, X25519 encryption.
    #[default]
    Curve25519,
    Rsa3072,
    Rsa4096,
}

impl KeyType {
    fn cipher_suite(self) -> CipherSuite {
        match self {
            KeyType::Curve25519 => CipherSuite::Cv25519,
            KeyType::Rsa3072 => CipherSuite::RSA3k,
            KeyType::Rsa4096 => CipherSuite::RSA4k,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            KeyType::Curve25519 => "Curve 25519 (recommended)",
            KeyType::Rsa3072 => "RSA 3072",
            KeyType::Rsa4096 => "RSA 4096",
        }
    }

    pub const ALL: [KeyType; 3] = [KeyType::Curve25519, KeyType::Rsa3072, KeyType::Rsa4096];
}

#[derive(Debug, Clone)]
pub struct KeyGenRequest {
    /// Full user IDs, e.g. `Alice <alice@example.org>`.
    pub user_ids: Vec<String>,
    pub key_type: KeyType,
    /// Lifetime from now. `None` means the key never expires; an expiry that
    /// can be extended later is the better default, so the GUI pre-fills two
    /// years rather than "never".
    pub validity: Option<Duration>,
    pub password: Option<String>,
}

impl KeyGenRequest {
    pub fn new(user_id: impl Into<String>) -> Self {
        KeyGenRequest {
            user_ids: vec![user_id.into()],
            key_type: KeyType::default(),
            validity: Some(TWO_YEARS),
            password: None,
        }
    }
}

pub const TWO_YEARS: Duration = Duration::from_secs(2 * 365 * 24 * 60 * 60);

pub struct GeneratedKey {
    pub cert: Cert,
    /// A pre-made revocation certificate. It is produced once, at generation
    /// time, and cannot be recreated later without the secret key — losing it
    /// is how people end up with an un-retractable key.
    pub revocation: Signature,
}

pub fn generate(request: &KeyGenRequest) -> Result<GeneratedKey> {
    if request.user_ids.iter().all(|u| u.trim().is_empty()) {
        return Err(crate::Error::invalid("a key needs at least one user ID"));
    }

    let mut builder = CertBuilder::new()
        .set_cipher_suite(request.key_type.cipher_suite())
        .set_validity_period(request.validity)
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .add_storage_encryption_subkey();

    for uid in request.user_ids.iter().filter(|u| !u.trim().is_empty()) {
        builder = builder.add_userid(uid.trim());
    }

    if let Some(password) = request.password.as_deref().filter(|p| !p.is_empty()) {
        builder = builder.set_password(Some(password.into()));
    }

    let (cert, revocation) = builder.generate()?;
    Ok(GeneratedKey { cert, revocation })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_usable_key() {
        let key = generate(&KeyGenRequest::new("Alice <alice@example.org>")).unwrap();
        let summary = crate::CertSummary::from_cert(&key.cert);

        assert_eq!(summary.primary_user_id, "Alice <alice@example.org>");
        assert_eq!(summary.validity, crate::Validity::Valid);
        assert!(summary.has_secret);
        assert_eq!(summary.capabilities(), "CSE");
        assert!(summary.expires.is_some());
    }

    #[test]
    fn rejects_an_empty_user_id() {
        let mut request = KeyGenRequest::new("");
        request.user_ids = vec!["   ".into()];
        assert!(generate(&request).is_err());
    }
}
