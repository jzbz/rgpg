//! Owning a key over time: changing when it expires, and managing the
//! identities bound to it.
//!
//! All three operations here are new self-signatures by the certificate's own
//! primary key. None of them removes anything: OpenPGP has no delete, only
//! newer signatures that supersede older ones and revocations that retract
//! them. A user ID "removed" from a key is a user ID everyone else still has.

use std::time::{Duration, SystemTime};

use sequoia_openpgp::cert::{SubkeyRevocationBuilder, UserIDRevocationBuilder};
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::{Signature, UserID};
use sequoia_openpgp::types::{ReasonForRevocation, SignatureType};
use sequoia_openpgp::{Cert, Packet};

use crate::error::{Error, Result};
use crate::policy;
use crate::store::Store;

/// Set — or clear — when a certificate expires.
///
/// `None` makes it never expire. The change is a fresh self-signature over the
/// primary key and every valid subkey, so an expiry can be extended after the
/// fact: a key that lapsed last week can be brought back by setting a date in
/// the future.
///
/// One wrinkle: signature timestamps have one-second resolution and a new
/// self-signature only supersedes one made strictly earlier, so two expiry
/// changes within the same second leave the first standing. It matters only to
/// a caller changing expiry twice in a row, which a person clicking a button
/// will not do, but a test will.
pub fn set_expiry(
    store: &Store,
    fingerprint: &str,
    expires_in: Option<Duration>,
    password: Option<&str>,
) -> Result<Cert> {
    let cert = store.secret_cert(fingerprint)?;
    let policy = policy();
    let mut signer = unlock_primary(&cert, password)?;

    let valid = cert
        .with_policy(&policy, None)
        .map_err(|_| Error::invalid("this certificate is not valid under the standard policy"))?;

    let expiration = expires_in.map(|d| SystemTime::now() + d);
    // Lives on the primary key's amalgamation, not on ValidCert: expiry is a
    // property of the primary key's binding, and the call also reissues the
    // subkey bindings so they do not outlive it.
    let signatures = valid
        .primary_key()
        .set_expiration_time(&mut signer, expiration)
        .map_err(Error::OpenPgp)?;

    store_both(store, cert, signatures)
}

/// Bind a new identity to a certificate.
pub fn add_user_id(
    store: &Store,
    fingerprint: &str,
    user_id: &str,
    password: Option<&str>,
) -> Result<Cert> {
    let user_id = user_id.trim();
    if user_id.is_empty() {
        return Err(Error::invalid("a user ID cannot be empty"));
    }

    let cert = store.secret_cert(fingerprint)?;
    if cert
        .userids()
        .any(|ua| String::from_utf8_lossy(ua.userid().value()) == user_id)
    {
        return Err(Error::invalid(format!("{user_id} is already on this key")));
    }

    let mut signer = unlock_primary(&cert, password)?;
    let userid = UserID::from(user_id);
    let binding = SignatureBuilder::new(SignatureType::PositiveCertification).sign_userid_binding(
        &mut signer,
        cert.primary_key().key(),
        &userid,
    )?;

    let packets: Vec<Packet> = vec![Packet::from(userid), Packet::from(binding)];
    let updated = cert.clone().insert_packets(packets)?.0;
    store.insert(&updated)?;
    if store.has_secret(fingerprint) {
        store.insert_secret(
            &cert
                .insert_packets(
                    updated
                        .userids()
                        .find(|ua| String::from_utf8_lossy(ua.userid().value()) == user_id)
                        .map(|ua| {
                            let mut out: Vec<Packet> = vec![Packet::from(ua.userid().clone())];
                            out.extend(ua.self_signatures().cloned().map(Packet::from));
                            out
                        })
                        .unwrap_or_default(),
                )?
                .0,
        )?;
    }
    Ok(updated)
}

/// Retract one of a certificate's own identities.
///
/// The user ID stays on the key — it has to, so anyone holding an old copy can
/// see it was withdrawn rather than simply not knowing about it.
pub fn revoke_user_id(
    store: &Store,
    fingerprint: &str,
    user_id: &str,
    message: &str,
    password: Option<&str>,
) -> Result<Cert> {
    let cert = store.secret_cert(fingerprint)?;
    let userid = cert
        .userids()
        .map(|ua| ua.userid().clone())
        .find(|uid| String::from_utf8_lossy(uid.value()) == user_id)
        .ok_or_else(|| Error::invalid(format!("{user_id} is not a user ID on this key")))?;

    if cert.userids().count() < 2 {
        return Err(Error::invalid(
            "this is the only user ID; revoking the whole certificate is the honest \
             way to retire it",
        ));
    }

    let mut signer = unlock_primary(&cert, password)?;
    let signature = UserIDRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::UIDRetired, message.as_bytes())?
        .build(&mut signer, &cert, &userid, None)?;

    store_both(store, cert, vec![signature])
}

/// Retract a single subkey, leaving the rest of the certificate intact.
///
/// Useful when one subkey's secret is exposed but the primary key is not: the
/// identity survives and only the compromised part is withdrawn.
pub fn revoke_subkey(
    store: &Store,
    fingerprint: &str,
    subkey_fingerprint: &str,
    message: &str,
    password: Option<&str>,
) -> Result<Cert> {
    let cert = store.secret_cert(fingerprint)?;
    let wanted = subkey_fingerprint.to_uppercase();

    let subkey = cert
        .keys()
        .subkeys()
        .map(|ka| ka.key().clone())
        .find(|key| key.fingerprint().to_hex().eq_ignore_ascii_case(&wanted))
        .ok_or_else(|| {
            Error::invalid(format!("{subkey_fingerprint} is not a subkey of this key"))
        })?;

    let mut signer = unlock_primary(&cert, password)?;
    let signature = SubkeyRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::KeyRetired, message.as_bytes())?
        .build(&mut signer, &cert, &subkey, None)?;

    store_both(store, cert, vec![signature])
}

/// Merge new self-signatures into both halves of the store.
fn store_both(store: &Store, cert: Cert, signatures: Vec<Signature>) -> Result<Cert> {
    let fingerprint = cert.fingerprint().to_hex();
    let updated = cert.insert_packets(signatures)?.0;

    // The secret certificate is the one that carries key material, so it is
    // the copy that must not fall behind; cert-d gets the public half.
    if store.has_secret(&fingerprint) {
        store.insert_secret(&updated)?;
    }
    store.insert(&updated)?;
    Ok(updated)
}

fn unlock_primary(
    cert: &Cert,
    password: Option<&str>,
) -> Result<Box<dyn sequoia_openpgp::crypto::Signer + Send + Sync>> {
    let key = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|_| Error::NoSecretKey(cert.fingerprint().to_hex()))?;

    crate::secret::signer(key, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Validity;
    use crate::keygen::{KeyGenRequest, generate};
    use crate::{CertSummary, cert};

    fn scratch() -> (tempfile::TempDir, Store, Cert) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let cert = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&cert).unwrap();
        (dir, store, cert)
    }

    #[test]
    fn extends_and_clears_expiry() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();
        let original = CertSummary::from_cert(&cert).expires.unwrap();

        let ten_years = Duration::from_secs(10 * 365 * 24 * 60 * 60);
        let updated = set_expiry(&store, &fingerprint, Some(ten_years), None).unwrap();
        let extended = CertSummary::from_cert(&updated).expires.unwrap();
        assert!(extended > original, "expiry should have moved outwards");

        // Signature timestamps have one-second granularity, and a new
        // self-signature only supersedes one made strictly earlier. Two expiry
        // changes inside the same second tie, and the older wins — see the note
        // on `set_expiry`.
        std::thread::sleep(Duration::from_millis(1100));

        let updated = set_expiry(&store, &fingerprint, None, None).unwrap();
        assert!(CertSummary::from_cert(&updated).expires.is_none());

        // Both halves of the store must agree, or a reload undoes it.
        assert!(
            CertSummary::from_cert(&store.lookup(&fingerprint).unwrap())
                .expires
                .is_none()
        );
        assert!(
            CertSummary::from_cert(&store.secret_cert(&fingerprint).unwrap())
                .expires
                .is_none()
        );
    }

    #[test]
    fn revives_a_lapsed_certificate() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();

        // Expire it a second from now, then push the expiry back out.
        set_expiry(&store, &fingerprint, Some(Duration::from_secs(1)), None).unwrap();
        std::thread::sleep(Duration::from_millis(1500));
        let lapsed = store.secret_cert(&fingerprint).unwrap();
        assert_eq!(CertSummary::from_cert(&lapsed).validity, Validity::Expired);

        let year = Duration::from_secs(365 * 24 * 60 * 60);
        let revived = set_expiry(&store, &fingerprint, Some(year), None).unwrap();
        assert_eq!(CertSummary::from_cert(&revived).validity, Validity::Valid);
    }

    #[test]
    fn adds_a_user_id() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();

        let updated =
            add_user_id(&store, &fingerprint, "Alice <alice@work.example>", None).unwrap();
        let ids: Vec<String> = cert::user_ids(&updated)
            .iter()
            .map(|u| u.text.clone())
            .collect();
        assert!(ids.iter().any(|u| u == "Alice <alice@work.example>"));
        assert!(ids.iter().any(|u| u == "Alice <alice@example.org>"));

        // Adding the same identity twice is refused rather than duplicated.
        assert!(add_user_id(&store, &fingerprint, "Alice <alice@work.example>", None).is_err());
        assert!(add_user_id(&store, &fingerprint, "   ", None).is_err());
    }

    #[test]
    fn revokes_one_subkey_and_leaves_the_others() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();

        let before = cert::subkeys(&cert);
        assert!(before.len() > 1, "the test key should have several subkeys");
        let victim = before[0].fingerprint.clone();

        let updated = revoke_subkey(&store, &fingerprint, &victim, "secret exposed", None).unwrap();

        let after = cert::subkeys(&updated);
        assert!(
            after
                .iter()
                .find(|k| k.fingerprint == victim)
                .is_some_and(|k| k.revoked),
            "the named subkey should be revoked"
        );
        assert!(
            after
                .iter()
                .filter(|k| k.fingerprint != victim)
                .all(|k| !k.revoked),
            "no other subkey should be touched"
        );
        // The certificate itself is still usable.
        assert_eq!(CertSummary::from_cert(&updated).validity, Validity::Valid);

        assert!(revoke_subkey(&store, &fingerprint, &fingerprint, "", None).is_err());
    }

    #[test]
    fn revokes_a_user_id_but_keeps_it_visible() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();

        // The last remaining identity cannot be revoked on its own.
        assert!(
            revoke_user_id(&store, &fingerprint, "Alice <alice@example.org>", "", None).is_err()
        );

        add_user_id(&store, &fingerprint, "Alice <alice@work.example>", None).unwrap();
        let updated = revoke_user_id(
            &store,
            &fingerprint,
            "Alice <alice@work.example>",
            "left the job",
            None,
        )
        .unwrap();

        let ids = cert::user_ids(&updated);
        let revoked = ids
            .iter()
            .find(|u| u.text == "Alice <alice@work.example>")
            .expect("a revoked user ID stays on the key");
        assert!(revoked.revoked);
        assert!(
            ids.iter()
                .any(|u| u.text == "Alice <alice@example.org>" && !u.revoked)
        );
    }
}
