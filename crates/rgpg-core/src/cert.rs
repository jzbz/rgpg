//! Flattened, GUI-friendly view of a certificate.

use std::time::SystemTime;

use sequoia_openpgp::Cert;
use sequoia_openpgp::types::RevocationStatus;

use crate::policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// Binding signatures check out under the standard policy and the
    /// certificate has not expired.
    Valid,
    Expired,
    Revoked,
    /// Nothing in the certificate is usable under the standard policy: the
    /// algorithms are too weak, or the self-signatures are missing or broken.
    Unusable,
}

impl Validity {
    pub fn as_str(self) -> &'static str {
        match self {
            Validity::Valid => "valid",
            Validity::Expired => "expired",
            Validity::Revoked => "revoked",
            Validity::Unusable => "unusable",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertSummary {
    pub fingerprint: String,
    pub key_id: String,
    /// Primary user ID, or a placeholder when the certificate has none that is
    /// valid under the policy.
    pub primary_user_id: String,
    pub user_ids: Vec<String>,
    pub algorithm: String,
    pub created: SystemTime,
    pub expires: Option<SystemTime>,
    pub validity: Validity,
    pub can_certify: bool,
    pub can_sign: bool,
    pub can_encrypt: bool,
    /// Whether this certificate carries secret key material.
    pub has_secret: bool,
}

impl CertSummary {
    pub fn from_cert(cert: &Cert) -> Self {
        let policy = policy();
        let now = SystemTime::now();

        let fingerprint = cert.fingerprint().to_hex();
        let key_id = cert.keyid().to_hex();
        let algorithm = format!("{}", cert.primary_key().key().pk_algo());
        let created = cert.primary_key().key().creation_time();
        let has_secret = cert.is_tsk();

        // Everything below needs the certificate interpreted under the policy.
        // A certificate that fails to validate still gets a row in the list —
        // Kleopatra shows unusable certificates rather than hiding them — so
        // fall back to the unpoliced parts instead of returning an error.
        let valid = cert.with_policy(&policy, now).ok();

        let revoked = matches!(
            cert.revocation_status(&policy, now),
            RevocationStatus::Revoked(_)
        );

        let user_ids: Vec<String> = match valid.as_ref() {
            Some(vc) => vc
                .userids()
                .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
                .collect(),
            None => cert
                .userids()
                .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
                .collect(),
        };

        let primary_user_id = valid
            .as_ref()
            .and_then(|vc| vc.primary_userid().ok())
            .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
            .or_else(|| user_ids.first().cloned())
            .unwrap_or_else(|| "(no user ID)".to_string());

        let expires = valid
            .as_ref()
            .and_then(|vc| vc.primary_key().key_expiration_time());

        let (can_certify, can_sign, can_encrypt) = match valid.as_ref() {
            Some(vc) => {
                let alive = || vc.keys().alive().revoked(false);
                (
                    alive().for_certification().next().is_some(),
                    alive().for_signing().next().is_some(),
                    alive()
                        .for_transport_encryption()
                        .chain(vc.keys().alive().revoked(false).for_storage_encryption())
                        .next()
                        .is_some(),
                )
            }
            None => (false, false, false),
        };

        let expired = expires.is_some_and(|t| t <= now);
        let validity = if revoked {
            Validity::Revoked
        } else if valid.is_none() {
            Validity::Unusable
        } else if expired {
            Validity::Expired
        } else {
            Validity::Valid
        };

        CertSummary {
            fingerprint,
            key_id,
            primary_user_id,
            user_ids,
            algorithm,
            created,
            expires,
            validity,
            can_certify,
            can_sign,
            can_encrypt,
            has_secret,
        }
    }

    /// `SCE` in Kleopatra's shorthand: certify, sign, encrypt.
    pub fn capabilities(&self) -> String {
        let mut out = String::new();
        if self.can_certify {
            out.push('C');
        }
        if self.can_sign {
            out.push('S');
        }
        if self.can_encrypt {
            out.push('E');
        }
        if out.is_empty() {
            out.push('-');
        }
        out
    }

    /// Fingerprint in the spaced, four-hex-digit grouping used for reading
    /// aloud and comparing by eye.
    pub fn fingerprint_pretty(&self) -> String {
        self.fingerprint
            .as_bytes()
            .chunks(4)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// True when `needle` (lowercased by the caller) appears in any field a
    /// user would plausibly search by.
    pub fn matches(&self, needle: &str) -> bool {
        if needle.is_empty() {
            return true;
        }
        self.fingerprint.to_lowercase().contains(needle)
            || self.key_id.to_lowercase().contains(needle)
            || self
                .user_ids
                .iter()
                .any(|u| u.to_lowercase().contains(needle))
    }
}

/// Render a timestamp as a local-time date, or `""` for "never".
pub fn format_time(time: Option<SystemTime>) -> String {
    match time {
        Some(t) => chrono::DateTime::<chrono::Local>::from(t)
            .format("%Y-%m-%d")
            .to_string(),
        None => String::new(),
    }
}
