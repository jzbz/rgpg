//! Every operation that unlocks a key locally, against a passphrase-protected
//! key of both profiles.
//!
//! These exist because of a bug that only one profile could show. An RFC 9580
//! secret is AEAD-protected and the packet tag feeding the AEAD schedule
//! depends on the key's role, so a key whose role had been erased with
//! `role_into_unspecified` could not be decrypted at all — sequoia answers
//! *cannot decrypt key with unspecified role*. RFC 4880 keys use CFB, never
//! consult the role, and pass regardless. Since RFC 9580 is rgpg's default,
//! changing the expiry of, adding a user ID to, or revoking a passphrase-
//! protected key failed for anyone who had not opted into the older profile.
//!
//! Hence the loop over both profiles: testing one alone is what let this
//! through.

use std::time::Duration;

use rgpg_core::keygen::{KeyGenRequest, Standard, generate};
use rgpg_core::{Store, lifecycle, revoke};

const PASSPHRASE: &str = "correct horse";

fn scratch_with_key(standard: Standard) -> (tempfile::TempDir, Store, String) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();

    let mut request = KeyGenRequest::new("Alice <alice@example.org>");
    request.standard = standard;
    request.password = Some(PASSPHRASE.to_string().into());
    let cert = generate(&request).unwrap().cert;
    store.insert_secret(&cert).unwrap();

    let fingerprint = cert.fingerprint().to_hex();
    (dir, store, fingerprint)
}

#[test]
fn lifecycle_operations_work_on_a_protected_key() {
    for standard in Standard::ALL {
        let (_dir, store, fingerprint) = scratch_with_key(standard);

        let updated = lifecycle::set_expiry(
            &store,
            &fingerprint,
            Some(Duration::from_secs(60 * 60 * 24 * 30)),
            Some(PASSPHRASE),
        )
        .unwrap_or_else(|e| panic!("{standard:?}: set_expiry: {e}"));
        assert!(rgpg_core::CertSummary::from_cert(&updated).expires.is_some());

        lifecycle::add_user_id(&store, &fingerprint, "Alice <alice@example.net>", Some(PASSPHRASE))
            .unwrap_or_else(|e| panic!("{standard:?}: add_user_id: {e}"));
    }
}

#[test]
fn revoking_works_on_a_protected_key() {
    for standard in Standard::ALL {
        let (_dir, store, fingerprint) = scratch_with_key(standard);

        let request = revoke::RevokeRequest {
            fingerprint: fingerprint.clone(),
            reason: revoke::Reason::Retired,
            message: "no longer used".into(),
            password: Some(PASSPHRASE.to_string().into()),
        };
        let revoked = revoke::revoke_cert(&store, &request)
            .unwrap_or_else(|e| panic!("{standard:?}: revoke_cert: {e}"));

        assert_eq!(
            rgpg_core::CertSummary::from_cert(&revoked).validity,
            rgpg_core::Validity::Revoked,
        );
    }
}

/// The wrong passphrase must still be refused, on both profiles — the fix
/// preserves a role, it does not weaken the check.
#[test]
fn the_wrong_passphrase_is_still_refused() {
    for standard in Standard::ALL {
        let (_dir, store, fingerprint) = scratch_with_key(standard);
        assert!(
            lifecycle::set_expiry(&store, &fingerprint, None, Some("hunter2")).is_err(),
            "{standard:?}: the wrong passphrase should not unlock the key",
        );
        assert!(
            lifecycle::set_expiry(&store, &fingerprint, None, None).is_err(),
            "{standard:?}: no passphrase should not unlock the key",
        );
    }
}
