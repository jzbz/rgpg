//! Web-of-trust authentication.
//!
//! Certificate *validity* — what [`crate::cert::Validity`] reports — only says
//! the certificate is internally sound: the self-signatures check out and it
//! has not expired or been revoked. It says nothing about whether the name on
//! it is real. That second question is what this module answers, by looking for
//! a chain of certifications from one of the store's trust roots to the binding
//! between a certificate and one of its user IDs.
//!
//! The two are independent, and both matter: a perfectly valid certificate from
//! a stranger is unauthenticated, and an expired certificate can still be one
//! you long ago confirmed belongs to a friend.

use std::collections::HashMap;

use sequoia_openpgp::{Cert, Fingerprint};
use sequoia_wot::Network;

/// How well a certificate's identity is backed by the web of trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Authentication {
    /// No chain of certifications reaches this binding from a trust root.
    #[default]
    Unknown,
    /// Some evidence, but below the threshold to accept the name outright.
    Marginal,
    /// Authenticated: a chain of sufficient weight reaches it.
    Full,
}

impl Authentication {
    pub fn as_str(self) -> &'static str {
        match self {
            Authentication::Unknown => "unverified",
            Authentication::Marginal => "partly verified",
            Authentication::Full => "verified",
        }
    }

    fn from_amount(amount: usize) -> Self {
        if amount >= sequoia_wot::FULLY_TRUSTED {
            Authentication::Full
        } else if amount >= sequoia_wot::PARTIALLY_TRUSTED {
            Authentication::Marginal
        } else {
            Authentication::Unknown
        }
    }
}

/// Authenticate every certificate in `certs` against `roots`.
///
/// Returns the best result across each certificate's user IDs, keyed by
/// uppercase fingerprint. The network is built once for the whole set because
/// that is the expensive part; asking it about one more binding is cheap.
///
/// A failure to build the network is reported as "nothing is authenticated"
/// rather than as an error: an unusable trust graph should grey out the
/// trust column, not stop the list from being shown.
pub fn authenticate_all(certs: &[Cert], roots: &[String]) -> HashMap<String, Authentication> {
    // The all-Unknown map is only what the two early returns below hand back.
    // Building it up front meant the success path inserted every key twice —
    // once as Unknown and once with the real verdict — allocating the key
    // string both times, for every certificate on every reload.
    let unknown = || -> HashMap<String, Authentication> {
        certs
            .iter()
            .map(|cert| {
                (
                    cert.fingerprint().to_hex().to_uppercase(),
                    Authentication::Unknown,
                )
            })
            .collect()
    };

    let roots: Vec<Fingerprint> = roots.iter().filter_map(|r| r.parse().ok()).collect();
    if roots.is_empty() {
        return unknown();
    }

    let policy = crate::policy();
    let Ok(network) = Network::from_cert_refs(certs.iter(), &policy, None, roots.as_slice()) else {
        return unknown();
    };

    let mut result: HashMap<String, Authentication> = HashMap::with_capacity(certs.len());
    for cert in certs {
        let fingerprint = cert.fingerprint();
        let mut best = Authentication::Unknown;

        for ua in cert.userids() {
            let paths = network.authenticate(
                ua.userid().clone(),
                fingerprint.clone(),
                sequoia_wot::FULLY_TRUSTED,
            );
            let found = Authentication::from_amount(paths.amount());
            if found > best {
                best = found;
            }
            if best == Authentication::Full {
                break;
            }
        }

        result.insert(fingerprint.to_hex().to_uppercase(), best);
    }

    result
}

// Ordering so `if found > best` above means "more authenticated".
impl PartialOrd for Authentication {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Authentication {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn rank(a: Authentication) -> u8 {
            match a {
                Authentication::Unknown => 0,
                Authentication::Marginal => 1,
                Authentication::Full => 2,
            }
        }
        rank(*self).cmp(&rank(*other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certify::{CertifyRequest, FULL, PARTIAL, certify};
    use crate::keygen::{KeyGenRequest, generate};
    use crate::store::Store;

    fn scratch() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        (dir, store)
    }

    fn authentication_of(store: &Store, fingerprint: &str) -> Authentication {
        let certs = store.certs().unwrap();
        let roots: Vec<String> = store.effective_roots().unwrap().into_iter().collect();
        authenticate_all(&certs, &roots)
            .get(&fingerprint.to_uppercase())
            .copied()
            .unwrap_or_default()
    }

    #[test]
    fn a_stranger_is_unauthenticated_until_certified() {
        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let stranger = generate(&KeyGenRequest::new("Stranger <them@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&me).unwrap();
        store.insert(&stranger).unwrap();

        let stranger_fpr = stranger.fingerprint().to_hex();
        assert_eq!(
            authentication_of(&store, &stranger_fpr),
            Authentication::Unknown
        );

        // My own key is a root, so it authenticates itself.
        assert_eq!(
            authentication_of(&store, &me.fingerprint().to_hex()),
            Authentication::Full
        );

        let mut request = CertifyRequest::new(me.fingerprint().to_hex(), &stranger_fpr);
        request.user_ids = vec!["Stranger <them@example.org>".to_string()];
        certify(&store, &request).unwrap();

        assert_eq!(
            authentication_of(&store, &stranger_fpr),
            Authentication::Full
        );
    }

    #[test]
    fn a_partial_certification_only_gets_partway() {
        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let acquaintance = generate(&KeyGenRequest::new("Pat <pat@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&me).unwrap();
        store.insert(&acquaintance).unwrap();

        let mut request = CertifyRequest::new(
            me.fingerprint().to_hex(),
            acquaintance.fingerprint().to_hex(),
        );
        request.user_ids = vec!["Pat <pat@example.org>".to_string()];
        request.amount = PARTIAL;
        certify(&store, &request).unwrap();

        assert_eq!(
            authentication_of(&store, &acquaintance.fingerprint().to_hex()),
            Authentication::Marginal
        );
    }

    #[test]
    fn a_trusted_introducer_extends_authentication_one_hop() {
        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let introducer = generate(&KeyGenRequest::new("Introducer <intro@example.org>"))
            .unwrap()
            .cert;
        let friend_of_friend = generate(&KeyGenRequest::new("Distant <far@example.org>"))
            .unwrap()
            .cert;

        store.insert_secret(&me).unwrap();
        // The introducer's secret key is needed only to make the second
        // certification inside this test; it is the delegation that matters.
        store.insert_secret(&introducer).unwrap();
        store.insert(&friend_of_friend).unwrap();

        // Without the delegation, the distant certificate is a stranger.
        let mut onward = CertifyRequest::new(
            introducer.fingerprint().to_hex(),
            friend_of_friend.fingerprint().to_hex(),
        );
        onward.user_ids = vec!["Distant <far@example.org>".to_string()];
        certify(&store, &onward).unwrap();

        let mut delegate =
            CertifyRequest::new(me.fingerprint().to_hex(), introducer.fingerprint().to_hex());
        delegate.user_ids = vec!["Introducer <intro@example.org>".to_string()];
        delegate.depth = 1;
        delegate.amount = FULL;
        certify(&store, &delegate).unwrap();

        assert_eq!(
            authentication_of(&store, &friend_of_friend.fingerprint().to_hex()),
            Authentication::Full
        );
    }

    #[test]
    fn explicit_trust_roots_are_honoured() {
        let (_dir, store) = scratch();
        let outside = generate(&KeyGenRequest::new("Outside <out@example.org>"))
            .unwrap()
            .cert;
        let vouched = generate(&KeyGenRequest::new("Vouched <v@example.org>"))
            .unwrap()
            .cert;
        // Neither secret key is ours, so nothing is a root to begin with.
        store.insert_secret(&outside).unwrap();
        store.insert(&vouched).unwrap();

        let mut request = CertifyRequest::new(
            outside.fingerprint().to_hex(),
            vouched.fingerprint().to_hex(),
        );
        request.user_ids = vec!["Vouched <v@example.org>".to_string()];
        certify(&store, &request).unwrap();

        assert!(store.trust_roots().unwrap().is_empty());
        store
            .set_trust_root(&outside.fingerprint().to_hex(), true)
            .unwrap();
        assert_eq!(store.trust_roots().unwrap().len(), 1);

        assert_eq!(
            authentication_of(&store, &vouched.fingerprint().to_hex()),
            Authentication::Full
        );

        store
            .set_trust_root(&outside.fingerprint().to_hex(), false)
            .unwrap();
        assert!(store.trust_roots().unwrap().is_empty());
    }
}
