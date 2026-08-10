//! Reaching keys held by the user's `gpg-agent`, including smartcard keys.
//!
//! This is the only workable route to a YubiKey on a machine that has GnuPG
//! set up. `scdaemon` claims the card reader with an exclusive PC/SC
//! transaction, so a second process asking the reader directly gets
//! `SCARD_E_SHARING_VIOLATION` — shared *and* exclusive modes both fail. Going
//! through the agent sidesteps the fight entirely.
//!
//! It also keeps rgpg out of the PIN business: the agent runs the user's own
//! `pinentry`, so the passphrase or card PIN never passes through this process.
//!
//! `sequoia-gpg-agent` is async and the rest of this crate is not, so calls are
//! driven on a small dedicated runtime created once per process.

use std::sync::OnceLock;

use sequoia_gpg_agent::Agent;
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use tokio::runtime::Runtime;

use crate::error::{Error, Result};

/// A secret key the agent can use on our behalf.
#[derive(Debug, Clone)]
pub struct AgentKey {
    /// GnuPG's identifier for the key. Not an OpenPGP fingerprint: it is a
    /// hash of the public key parameters, and is how the agent is addressed.
    pub keygrip: String,
    /// Serial number of the smartcard holding the key, when it is on one.
    /// `None` means the key material is a file in the agent's store.
    pub card_serial: Option<String>,
}

impl AgentKey {
    pub fn is_on_card(&self) -> bool {
        self.card_serial.is_some()
    }
}

/// The runtime the agent calls are driven on.
///
/// One per process, built lazily: most runs of rgpg never touch the agent, and
/// spinning up a runtime for them would be waste.
fn runtime() -> Result<&'static Runtime> {
    static RUNTIME: OnceLock<std::result::Result<Runtime, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| Error::invalid(format!("cannot start the agent runtime: {e}")))
}

fn connect() -> Result<Agent> {
    runtime()?.block_on(async {
        Agent::connect_to_default()
            .await
            .map_err(|e| Error::invalid(format!("no gpg-agent to talk to: {e}")))
    })
}

/// Whether a gpg-agent is reachable at all.
///
/// Used to decide whether to offer card-backed keys in the UI, so a machine
/// without GnuPG simply does not show the option.
pub fn available() -> bool {
    connect().is_ok()
}

/// Every key the agent holds.
pub fn keys() -> Result<Vec<AgentKey>> {
    let mut agent = connect()?;
    runtime()?.block_on(async {
        let listing = agent
            .list_keys()
            .await
            .map_err(|e| Error::invalid(format!("the agent would not list its keys: {e}")))?;

        Ok(listing
            .iter()
            .map(|info| AgentKey {
                keygrip: info.keygrip().to_string(),
                card_serial: info.serialno().map(str::to_owned),
            })
            .collect())
    })
}

/// Only the keys that live on a smartcard.
pub fn card_keys() -> Result<Vec<AgentKey>> {
    Ok(keys()?.into_iter().filter(AgentKey::is_on_card).collect())
}

/// A signer backed by the agent, for a public key the agent has the secret
/// half of.
///
/// The agent finds the secret half by keygrip, so only the public key is
/// needed here. Any PIN or passphrase prompt happens in the user's pinentry
/// while this call blocks.
pub fn signer(
    key: &Key<PublicParts, UnspecifiedRole>,
) -> Result<sequoia_gpg_agent::KeyPair> {
    let agent = connect()?;
    // Only connecting is async. The returned KeyPair implements Sequoia's
    // Signer and Decryptor synchronously, so it drops straight into the
    // existing stream builders with no runtime in sight.
    agent
        .keypair(key)
        .map_err(|e| Error::invalid(format!("the agent cannot use this key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Enumeration against whatever agent the developer happens to be running.
    ///
    /// Skips rather than fails when there is no agent: CI has none, and a test
    /// that depends on the developer's GnuPG setup must not break the suite.
    #[test]
    fn lists_whatever_the_local_agent_holds() {
        if !available() {
            eprintln!("no gpg-agent reachable; skipping");
            return;
        }

        let keys = keys().unwrap();
        for key in &keys {
            // A keygrip is a 40-character hex SHA-1 of the key parameters.
            assert_eq!(key.keygrip.len(), 40, "odd keygrip: {}", key.keygrip);
            assert!(key.keygrip.chars().all(|c| c.is_ascii_hexdigit()));
        }

        let on_card = card_keys().unwrap();
        assert!(on_card.iter().all(AgentKey::is_on_card));
        eprintln!(
            "agent holds {} key(s), {} on a smartcard",
            keys.len(),
            on_card.len()
        );
    }
}
