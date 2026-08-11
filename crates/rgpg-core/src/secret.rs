//! The one place a secret key is unlocked.
//!
//! Choosing *which* key to use is deliberately not here. Signing, certification
//! and decryption each want a different key, and they disagree about what
//! counts as usable — decryption accepts expired and revoked keys on purpose,
//! because revoking a key withdraws it for future use and does not burn the
//! archive. Folding those filters together would silently change which subkey
//! an operation reaches for, so each caller still selects its own.
//!
//! What every caller does share is the last step: if the key is
//! passphrase-protected, decrypt it, then turn it into something that can sign
//! or decrypt. That is what lives here — so that if key material ever moves out
//! of this process, this is the file that changes.
//!
//! Nothing here caches. A key is unlocked for one operation and dropped, and
//! sequoia zeroes it on the way out. See [`crate::store`] for what that does
//! and does not protect against.

use sequoia_openpgp::crypto::{KeyPair, Password, Signer};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::packet::key::{KeyRole, SecretParts};

use crate::error::{Error, Result};

/// Decrypt `key` if it is passphrase-protected, otherwise hand it back as-is.
///
/// A missing passphrase is an error rather than an attempt with an empty one:
/// the caller has a key it cannot use, and saying so beats a decrypt failure
/// that reads like a wrong passphrase.
///
/// Generic over the key's role, and that is load-bearing rather than tidiness.
/// An RFC 9580 key's secret is AEAD-protected, and the packet tag that goes
/// into the AEAD schedule depends on whether the key is a primary or a subkey.
/// A key whose role has been erased with `role_into_unspecified` cannot supply
/// that tag, and sequoia refuses it: *cannot decrypt key with unspecified
/// role*. RFC 4880 keys use CFB, never consult the role, and so hide the
/// problem. Take the caller's role and give it back rather than flattening it.
pub fn unlock<R: KeyRole>(
    key: Key<SecretParts, R>,
    password: Option<&str>,
) -> Result<Key<SecretParts, R>> {
    if !key.secret().is_encrypted() {
        // Saying nothing here would be worse than pedantic. The operation
        // succeeds either way, so a passphrase typed against a key that has
        // none looks accepted — and the next time it is typed wrongly against
        // a key that *is* protected, the failure is a surprise. It usually
        // means the wrong key is selected.
        if password.is_some_and(|p| !p.is_empty()) {
            return Err(Error::invalid(
                "this key has no passphrase; leave the passphrase field empty",
            ));
        }
        return Ok(key);
    }
    let password: Password = password
        .filter(|p| !p.is_empty())
        .ok_or_else(|| Error::invalid("this key is passphrase-protected"))?
        .into();
    Ok(key.decrypt_secret(&password)?)
}

/// [`unlock`], for a caller working through a list of candidate keys.
///
/// Returns `None` where [`unlock`] would return an error, because a key that
/// cannot be opened is a reason to try the next one rather than to give up. The
/// decryption path needs this: a message may name several recipients, and only
/// one of them has to work.
///
/// That includes [`unlock`]'s objection to a passphrase supplied for a key that
/// has none. There the caller named one key and one passphrase, so a mismatch
/// is worth reporting; here the same secret is tried against every candidate
/// key and against the message's own passwords, so it carries no such claim.
pub fn try_unlock<R: KeyRole>(
    key: Key<SecretParts, R>,
    password: Option<&str>,
) -> Option<Key<SecretParts, R>> {
    unlock(key, password).ok()
}

/// Unlock a key and turn it into a keypair.
pub fn keypair<R: KeyRole>(key: Key<SecretParts, R>, password: Option<&str>) -> Result<KeyPair> {
    Ok(unlock(key, password)?.into_keypair()?)
}

/// Unlock a key and box it as a signer.
///
/// The boxed form is what the callers that may instead fall back to gpg-agent
/// need, since an agent-backed signer is a different concrete type.
pub fn signer<R: KeyRole>(
    key: Key<SecretParts, R>,
    password: Option<&str>,
) -> Result<Box<dyn Signer + Send + Sync>> {
    Ok(Box::new(keypair(key, password)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{KeyGenRequest, generate};

    fn primary(
        request: &KeyGenRequest,
    ) -> Key<SecretParts, sequoia_openpgp::packet::key::PrimaryRole> {
        generate(request)
            .unwrap()
            .cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
    }

    #[test]
    fn an_unprotected_key_needs_no_passphrase() {
        let key = primary(&KeyGenRequest::new("Alice <alice@example.org>"));
        assert!(!key.secret().is_encrypted());
        assert!(unlock(key.clone(), None).is_ok());
        assert!(unlock(key.clone(), Some("")).is_ok());

        // A passphrase for a key that has none is refused rather than ignored:
        // silently accepting it makes the field look checked when it is not.
        assert!(unlock(key.clone(), Some("hunter2")).is_err());
        // But not when walking candidates, where the same secret is offered to
        // every key and to the message's own passwords.
        assert!(try_unlock(key, Some("hunter2")).is_none());
    }

    #[test]
    fn a_protected_key_round_trips() {
        let mut request = KeyGenRequest::new("Alice <alice@example.org>");
        request.password = Some("correct horse".to_string().into());
        let key = primary(&request);
        assert!(key.secret().is_encrypted());

        assert!(keypair(key.clone(), Some("correct horse")).is_ok());

        // The three ways it can go wrong all have to fail, and `try_unlock`
        // has to report them as "skip this key" rather than propagating.
        for wrong in [None, Some(""), Some("hunter2")] {
            assert!(
                unlock(key.clone(), wrong).is_err(),
                "{wrong:?} should not unlock"
            );
            assert!(
                try_unlock(key.clone(), wrong).is_none(),
                "{wrong:?} should be skipped"
            );
        }
    }
}
