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
    /// Filled in by the caller from [`crate::wot`]; `from_cert` cannot know it,
    /// because authentication is a property of the whole store, not of one
    /// certificate.
    pub authentication: crate::Authentication,
    /// Whether the user has designated this certificate a trust root.
    pub is_trust_root: bool,
    /// Why the certificate was revoked, when it has been.
    pub revocation: Option<String>,
    /// Serial of the smartcard whose key can sign for this certificate, when
    /// the user's gpg-agent reports one. Filled in by the caller.
    pub card_serial: Option<String>,
    /// The agent can sign for this certificate, card or not.
    pub agent_backed: bool,
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
            authentication: crate::Authentication::Unknown,
            is_trust_root: false,
            revocation: revoked.then(|| describe_revocation(cert)).flatten(),
            card_serial: None,
            agent_backed: false,
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

/// One subkey, flattened for the details dialog.
#[derive(Debug, Clone)]
pub struct SubkeySummary {
    pub fingerprint: String,
    pub algorithm: String,
    pub created: SystemTime,
    pub expires: Option<SystemTime>,
    pub can_sign: bool,
    pub can_encrypt: bool,
    pub can_certify: bool,
    pub revoked: bool,
    pub has_secret: bool,
}

impl SubkeySummary {
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
}

/// Every subkey of `cert`, primary key excluded — it is already the headline
/// of the details pane.
pub fn subkeys(cert: &Cert) -> Vec<SubkeySummary> {
    let policy = policy();
    let now = SystemTime::now();
    let Ok(valid) = cert.with_policy(&policy, now) else {
        return Vec::new();
    };

    // ValidKeyAmalgamation has no revocation_status; ask the iterator for the
    // revoked ones and match on fingerprint.
    let revoked: std::collections::HashSet<String> = valid
        .keys()
        .subkeys()
        .revoked(true)
        .map(|ka| ka.key().fingerprint().to_hex())
        .collect();

    valid
        .keys()
        .subkeys()
        .map(|ka| SubkeySummary {
            fingerprint: ka.key().fingerprint().to_hex(),
            algorithm: format!("{}", ka.key().pk_algo()),
            created: ka.key().creation_time(),
            expires: ka.key_expiration_time(),
            can_sign: ka.for_signing(),
            can_encrypt: ka.for_transport_encryption() || ka.for_storage_encryption(),
            can_certify: ka.for_certification(),
            revoked: revoked.contains(&ka.key().fingerprint().to_hex()),
            has_secret: ka.key().has_secret(),
        })
        .collect()
}

/// One user ID with the parts the summary pane cannot show.
#[derive(Debug, Clone)]
pub struct UserIdDetail {
    pub text: String,
    pub is_primary: bool,
    pub revoked: bool,
    /// When the holder last self-signed this identity.
    pub self_signed: Option<SystemTime>,
}

pub fn user_ids(cert: &Cert) -> Vec<UserIdDetail> {
    let policy = policy();
    let now = SystemTime::now();
    let primary = cert
        .with_policy(&policy, now)
        .ok()
        .and_then(|vc| vc.primary_userid().ok())
        .map(|ua| ua.userid().clone());

    cert.userids()
        .map(|ua| UserIdDetail {
            text: String::from_utf8_lossy(ua.userid().value()).into_owned(),
            is_primary: primary.as_ref() == Some(ua.userid()),
            revoked: matches!(
                ua.revocation_status(&policy, now),
                RevocationStatus::Revoked(_)
            ),
            self_signed: ua
                .self_signatures()
                .filter_map(|sig| sig.signature_creation_time())
                .max(),
        })
        .collect()
}

fn describe_revocation(cert: &Cert) -> Option<String> {
    let (reason, message) = crate::revoke::revocation_reason(cert)?;
    Some(if message.is_empty() {
        reason.label().to_string()
    } else {
        format!("{} — {message}", reason.label())
    })
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
