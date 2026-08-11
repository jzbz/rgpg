//! Message operations: encrypt, decrypt, sign, verify.

use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use sequoia_openpgp::crypto::{Password, SessionKey};
use sequoia_openpgp::packet::{PKESK, SKESK};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder, MessageLayer, MessageStructure,
    VerificationHelper, VerifierBuilder,
};
use sequoia_openpgp::serialize::stream::{
    Armorer, Encryptor, LiteralWriter, Message, Recipient, Signer,
};
use sequoia_openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp::{Cert, KeyHandle};

use crate::error::{Error, Result};
use crate::policy;
use crate::store::Store;
use zeroize::Zeroizing;

/// What a single signature in a message turned out to be.
#[derive(Debug, Clone)]
pub struct SignatureReport {
    pub good: bool,
    /// Signer's primary user ID when the certificate is known, otherwise the
    /// key handle from the signature packet.
    pub signer: String,
    pub fingerprint: Option<String>,
    /// Human-readable reason, filled in for bad and unverifiable signatures.
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub signatures: Vec<SignatureReport>,
    /// Fingerprint of the certificate whose subkey decrypted the message.
    pub decrypted_with: Option<String>,
}

impl VerifyResult {
    pub fn all_good(&self) -> bool {
        !self.signatures.is_empty() && self.signatures.iter().all(|s| s.good)
    }
}

/// Encrypt to `recipients` and/or to `passwords`, optionally signing.
///
/// Both may be given at once: the message then carries a session key wrapped
/// for every recipient *and* wrapped by each password, so either opens it.
/// That is what lets a file go to a colleague who has a key and to one who
/// only has a shared secret.
///
/// A password-only message is what `gpg -c` produces.
pub fn encrypt(
    recipients: &[Cert],
    passwords: &[String],
    signer: Option<(&Cert, Option<&str>)>,
    plaintext: &[u8],
    sink: impl Write + Send + Sync,
) -> Result<()> {
    let passwords: Vec<&String> = passwords.iter().filter(|p| !p.is_empty()).collect();
    if recipients.is_empty() && passwords.is_empty() {
        return Err(Error::invalid(
            "choose at least one recipient, or set a password",
        ));
    }
    let policy = policy();

    // Collect the encryption-capable subkeys of every recipient up front, so a
    // recipient without one fails the whole operation instead of silently
    // producing a message they cannot read.
    let mut recipient_keys: Vec<Recipient> = Vec::new();
    for cert in recipients {
        let valid = cert
            .with_policy(&policy, None)
            .map_err(|_| Error::NoEncryptionKey(cert.fingerprint().to_hex()))?;
        let before = recipient_keys.len();
        for ka in valid
            .keys()
            .alive()
            .revoked(false)
            .supported()
            .for_transport_encryption()
        {
            recipient_keys.push(Recipient::from(ka));
        }
        if recipient_keys.len() == before {
            return Err(Error::NoEncryptionKey(cert.fingerprint().to_hex()));
        }
    }

    let message = Message::new(sink);
    let message = Armorer::new(message).build()?;

    let message = Encryptor::for_recipients(message, recipient_keys)
        .add_passwords(passwords.into_iter().map(|p| Password::from(p.as_str())))
        .build()?;

    let message = match signer {
        Some((cert, password)) => {
            let keypair = signing_keypair(cert, password)?;
            Signer::new(message, keypair)?.build()?
        }
        None => message,
    };

    let mut message = LiteralWriter::new(message).build()?;
    message.write_all(plaintext)?;
    message.finalize()?;
    Ok(())
}

/// Decrypt a message, verifying any signatures against the store.
pub fn decrypt(
    store: &Store,
    ciphertext: &[u8],
    password: Option<&str>,
    mut sink: impl Write,
) -> Result<VerifyResult> {
    let policy = policy();
    let helper = Helper::new(store, password);

    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)?.with_policy(&policy, None, helper)?;
    std::io::copy(&mut decryptor, &mut sink).map_err(|e| Error::io("decrypting message", e))?;

    let helper = decryptor.into_helper();
    Ok(VerifyResult {
        signatures: helper.signatures,
        decrypted_with: helper.decrypted_with,
    })
}

/// Produce a detached, armored signature over `data`.
pub fn sign_detached(
    signer: &Cert,
    password: Option<&str>,
    data: &[u8],
    sink: impl Write + Send + Sync,
) -> Result<()> {
    let keypair = signing_keypair(signer, password)?;

    let message = Message::new(sink);
    let message = Armorer::new(message)
        .kind(sequoia_openpgp::armor::Kind::Signature)
        .build()?;
    let mut message = Signer::new(message, keypair)?.detached().build()?;
    message.write_all(data)?;
    message.finalize()?;
    Ok(())
}

/// Sign `data` so the text stays readable, with the signature appended.
///
/// This is the cleartext signature framework — what belongs in an e-mail or a
/// forum post, where a detached signature would be useless because there is
/// nowhere to put the second file.
pub fn sign_cleartext(
    signer: &Cert,
    password: Option<&str>,
    data: &[u8],
    sink: impl Write + Send + Sync,
) -> Result<()> {
    let keypair = signing_keypair(signer, password)?;
    let message = Message::new(sink);
    let mut message = Signer::new(message, keypair)?.cleartext().build()?;
    message.write_all(data)?;
    message.finalize()?;
    Ok(())
}

/// Verify a message that carries its own text: cleartext-signed, or signed and
/// wrapped. Returns the text alongside the verdict.
pub fn verify_inline(store: &Store, signed: &[u8]) -> Result<(Vec<u8>, VerifyResult)> {
    let policy = policy();
    let helper = Helper::new(store, None);

    let mut verifier = VerifierBuilder::from_bytes(signed)?.with_policy(&policy, None, helper)?;
    let mut text = Vec::new();
    std::io::copy(&mut verifier, &mut text).map_err(|e| Error::io("verifying message", e))?;

    let helper = verifier.into_helper();
    Ok((
        text,
        VerifyResult {
            signatures: helper.signatures,
            decrypted_with: None,
        },
    ))
}

/// Verify a detached signature over `data`.
pub fn verify_detached(store: &Store, signature: &[u8], data: &[u8]) -> Result<VerifyResult> {
    let policy = policy();
    let helper = Helper::new(store, None);

    let mut verifier =
        DetachedVerifierBuilder::from_bytes(signature)?.with_policy(&policy, None, helper)?;
    verifier.verify_bytes(data)?;

    let helper = verifier.into_helper();
    Ok(VerifyResult {
        signatures: helper.signatures,
        decrypted_with: None,
    })
}

/// Unlock a signing-capable secret key.
///
/// Local key material is used when the certificate carries it. Otherwise the
/// user's gpg-agent is asked, which is how a smartcard signs: the secret never
/// leaves the card, and the PIN prompt is the agent's own pinentry rather than
/// anything rgpg draws.
fn signing_keypair(
    cert: &Cert,
    password: Option<&str>,
) -> Result<Box<dyn sequoia_openpgp::crypto::Signer + Send + Sync>> {
    let policy = policy();
    let valid = cert
        .with_policy(&policy, None)
        .map_err(|_| Error::NoSecretKey(cert.fingerprint().to_hex()))?;

    let Some(ka) = valid
        .keys()
        .secret()
        .alive()
        .revoked(false)
        .supported()
        .for_signing()
        .next()
    else {
        return Ok(Box::new(crate::agent::signer_for(cert)?));
    };

    crate::secret::signer(ka.key().clone(), password)
}

/// Shared decryption/verification callbacks.
///
/// Sequoia drives verification through this trait pair rather than returning a
/// result: `get_certs` supplies the certificates it needs mid-stream, and
/// `check` is handed the message structure once the body has been read.
struct Helper<'a> {
    store: &'a Store,
    password: Option<Zeroizing<String>>,
    signatures: Vec<SignatureReport>,
    decrypted_with: Option<String>,
}

impl<'a> Helper<'a> {
    fn new(store: &'a Store, password: Option<&str>) -> Self {
        Helper {
            store,
            password: password.map(|p| Zeroizing::new(p.to_owned())),
            signatures: Vec::new(),
            decrypted_with: None,
        }
    }
}

impl VerificationHelper for Helper<'_> {
    fn get_certs(&mut self, ids: &[KeyHandle]) -> anyhow::Result<Vec<Cert>> {
        // A signer we do not have is not an error here: it surfaces as a
        // MissingKey verification error in `check`, which is a better message
        // than aborting the whole read.
        Ok(ids
            .iter()
            .filter_map(|id| self.store.lookup(&id.to_string()).ok())
            .collect())
    }

    fn check(&mut self, structure: MessageStructure) -> anyhow::Result<()> {
        for layer in structure {
            let MessageLayer::SignatureGroup { results } = layer else {
                continue;
            };
            for result in results {
                self.signatures.push(match result {
                    Ok(good) => {
                        let summary = crate::CertSummary::from_cert(good.ka.cert());
                        SignatureReport {
                            good: true,
                            signer: summary.primary_user_id.clone(),
                            fingerprint: Some(summary.fingerprint),
                            detail: String::new(),
                        }
                    }
                    Err(err) => SignatureReport {
                        good: false,
                        signer: "unknown".to_string(),
                        fingerprint: None,
                        detail: format!("{err}"),
                    },
                });
            }
        }
        Ok(())
    }
}

impl DecryptionHelper for Helper<'_> {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> anyhow::Result<Option<Cert>> {
        let policy = policy();

        // A PKESK names the *subkey* it was encrypted to, and a wildcard
        // recipient names nothing at all, so there is no lookup by primary
        // fingerprint to be done here: walk the secret keys we hold and match
        // on key handles.
        let secrets = self.store.secret_certs().unwrap_or_default();

        for pkesk in pkesks {
            for cert in &secrets {
                let Ok(valid) = cert.with_policy(&policy, None) else {
                    continue;
                };

                // Encryption keys only: a wildcard PKESK names no recipient,
                // so without this filter every signing and certification key
                // gets unlocked and tried as well.
                //
                // Deliberately *not* filtered by alive/revoked. Old mail must
                // stay readable after a subkey expires or is retired —
                // revoking a key withdraws it for future use, it does not
                // burn the archive.
                let usable = valid
                    .keys()
                    .secret()
                    .for_transport_encryption()
                    .chain(valid.keys().secret().for_storage_encryption());

                for ka in usable {
                    if let Some(handle) = pkesk.recipient()
                        && !handle.aliases(ka.key().key_handle())
                    {
                        continue;
                    }

                    // try_unlock, not unlock: this walks every key the message
                    // might be addressed to, so one that will not open is a
                    // reason to try the next rather than to fail the decrypt.
                    let password = self.password.as_deref().map(String::as_str);
                    let Some(key) = crate::secret::try_unlock(ka.key().clone(), password) else {
                        continue;
                    };
                    let Ok(mut pair) = key.into_keypair() else {
                        continue;
                    };
                    if pkesk
                        .decrypt(&mut pair, sym_algo)
                        .is_some_and(|(algo, session_key)| decrypt(algo, &session_key))
                    {
                        self.decrypted_with = Some(cert.fingerprint().to_hex());
                        return Ok(Some(cert.clone()));
                    }
                }
            }
        }

        // A password-encrypted message carries no recipient at all, so try the
        // supplied passphrase against the symmetric envelopes before deciding
        // this message was not meant for us.
        if let Some(password) = self.password.as_deref().filter(|p| !p.is_empty()) {
            let password = Password::from(password.as_str());
            for skesk in skesks {
                if let Ok((algo, session_key)) = skesk.decrypt(&password)
                    && decrypt(algo, &session_key)
                {
                    return Ok(None);
                }
            }
        }

        // Nothing local fits. The message may be for a card key, whose secret
        // half exists only on the card — ask the agent, which will raise its
        // own PIN prompt if the card needs one.
        // Read the store once, not once per recipient: certs() parses every
        // certificate it returns, and a message to several people would
        // otherwise re-parse the whole store for each of them.
        let candidates = self.store.certs().unwrap_or_default();

        for pkesk in pkesks {
            for cert in &candidates {
                let Ok(valid) = cert.with_policy(&policy, None) else {
                    continue;
                };
                // Same permissive rule as the local path above: a card key
                // that has since been revoked must still open what it
                // encrypted while it was current.
                let matches = valid
                    .keys()
                    .for_transport_encryption()
                    .chain(valid.keys().for_storage_encryption())
                    .any(|ka| {
                        pkesk
                            .recipient()
                            .is_none_or(|handle| handle.aliases(ka.key().key_handle()))
                    });
                if !matches {
                    continue;
                }

                let Ok(mut pair) = crate::agent::decryptor_for(cert) else {
                    continue;
                };
                if pkesk
                    .decrypt(&mut pair, sym_algo)
                    .is_some_and(|(algo, session_key)| decrypt(algo, &session_key))
                {
                    self.decrypted_with = Some(cert.fingerprint().to_hex());
                    return Ok(Some(cert.clone()));
                }
            }
        }

        Err(anyhow::anyhow!(
            "no secret key, and no password, opens this message"
        ))
    }
}

/// What a file handed to "Decrypt / Verify" turns out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// An OpenPGP message: encrypted, signed inline, or both.
    Message,
    /// A bare signature — the other half of a detached pair, useless without
    /// the file it signs.
    DetachedSignature,
    NotOpenPgp,
}

/// Decide what `data` is, so the UI knows whether to ask for a second file.
pub fn classify(data: &[u8]) -> InputKind {
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    // Armored input says what it is in the header line. Check bytes rather
    // than decoding: the file may be binary, and a UTF-8 error here would
    // wrongly rule out an armored file whose tail is not valid UTF-8.
    let head = &data[..data.len().min(1024)];
    // Cleartext first: a cleartext-signed message contains *both* markers —
    // its own header and the signature block that follows the text — so
    // testing for the signature first misreads it as a detached signature and
    // sends the reader off looking for a file that does not exist.
    if contains(head, b"-----BEGIN PGP SIGNED MESSAGE-----") {
        return InputKind::Message;
    }
    if contains(head, b"-----BEGIN PGP SIGNATURE-----") {
        return InputKind::DetachedSignature;
    }
    if contains(head, b"-----BEGIN PGP MESSAGE-----") {
        return InputKind::Message;
    }

    // Binary: the first packet is enough to tell the two apart.
    use sequoia_openpgp::Packet;
    use sequoia_openpgp::parse::{PacketParser, PacketParserResult};
    match PacketParser::from_bytes(data) {
        Ok(PacketParserResult::Some(pp)) => match pp.packet {
            Packet::Signature(_) => InputKind::DetachedSignature,
            Packet::PKESK(_)
            | Packet::SKESK(_)
            | Packet::SEIP(_)
            | Packet::OnePassSig(_)
            | Packet::CompressedData(_)
            | Packet::Literal(_) => InputKind::Message,
            _ => InputKind::NotOpenPgp,
        },
        _ => InputKind::NotOpenPgp,
    }
}

/// `notes.txt` -> `notes.txt.asc`.
pub fn encrypted_name(input: &Path) -> PathBuf {
    append_extension(input, "asc")
}

/// `notes.txt` -> `notes.txt.sig`.
pub fn signature_name(input: &Path) -> PathBuf {
    append_extension(input, "sig")
}

/// `notes.txt.asc` -> `notes.txt`. A name with no OpenPGP extension to strip
/// gets `.out` appended rather than being overwritten in place.
pub fn decrypted_name(input: &Path) -> PathBuf {
    let strippable = input
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| matches!(e, "asc" | "pgp" | "gpg"));
    if strippable {
        input.with_extension("")
    } else {
        append_extension(input, "out")
    }
}

fn append_extension(path: &Path, extension: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".");
    name.push(extension);
    PathBuf::from(name)
}

pub fn encrypt_file(
    recipients: &[Cert],
    passwords: &[String],
    signer: Option<(&Cert, Option<&str>)>,
    input: &Path,
    output: &Path,
) -> Result<()> {
    let plaintext = read(input)?;
    encrypt(recipients, passwords, signer, &plaintext, create(output)?)
}

pub fn sign_detached_file(
    signer: &Cert,
    password: Option<&str>,
    input: &Path,
    output: &Path,
) -> Result<()> {
    let data = read(input)?;
    sign_detached(signer, password, &data, create(output)?)
}

pub fn decrypt_file(
    store: &Store,
    input: &Path,
    password: Option<&str>,
    output: &Path,
) -> Result<VerifyResult> {
    let ciphertext = read(input)?;
    // The output file is created only once the message parses, so a failed
    // decryption does not leave an empty file behind.
    let mut plaintext = Vec::new();
    let result = decrypt(store, &ciphertext, password, &mut plaintext)?;
    fs::write(output, &plaintext)
        .map_err(|e| Error::io(format!("writing {}", output.display()), e))?;
    Ok(result)
}

/// Verify an armored or binary detached signature against the file it signs.
pub fn verify_detached_files(
    store: &Store,
    signature_path: &Path,
    data_path: &Path,
) -> Result<VerifyResult> {
    let signature = read(signature_path)?;
    let data = read(data_path)?;
    verify_detached(store, &signature, &data)
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| Error::io(format!("reading {}", path.display()), e))
}

fn create(path: &Path) -> Result<BufWriter<fs::File>> {
    let file =
        fs::File::create(path).map_err(|e| Error::io(format!("writing {}", path.display()), e))?;
    Ok(BufWriter::new(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{KeyGenRequest, generate};

    fn scratch_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        (dir, store)
    }

    #[test]
    fn encrypt_sign_decrypt_round_trip() {
        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert_secret(&bob).unwrap();

        let mut ciphertext = Vec::new();
        encrypt(std::slice::from_ref(&bob), &[], Some((&alice, None)), b"attack at dawn", &mut ciphertext)
            .unwrap();
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));

        let mut plaintext = Vec::new();
        let result = decrypt(&store, &ciphertext, None, &mut plaintext).unwrap();

        assert_eq!(plaintext, b"attack at dawn");
        assert!(result.all_good(), "signatures: {:?}", result.signatures);
        assert_eq!(result.signatures[0].signer, "Alice <alice@example.org>");
        assert_eq!(result.decrypted_with, Some(bob.fingerprint().to_hex()));
    }

    #[test]
    fn classifies_what_the_verify_dialog_will_be_handed() {
        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let mut message = Vec::new();
        encrypt(std::slice::from_ref(&alice), &[], None, b"hello", &mut message).unwrap();
        assert_eq!(classify(&message), InputKind::Message);

        let mut signature = Vec::new();
        sign_detached(&alice, None, b"hello", &mut signature).unwrap();
        assert_eq!(classify(&signature), InputKind::DetachedSignature);

        // A cleartext signature carries both markers; it is a message, not a
        // detached signature, whatever order they appear in.
        let mut cleartext = Vec::new();
        sign_cleartext(&alice, None, b"hello", &mut cleartext).unwrap();
        assert_eq!(classify(&cleartext), InputKind::Message);

        assert_eq!(classify(b"just a text file\n"), InputKind::NotOpenPgp);
        assert_eq!(classify(b""), InputKind::NotOpenPgp);
    }

    #[test]
    fn derives_output_names() {
        assert_eq!(encrypted_name(Path::new("notes.txt")), Path::new("notes.txt.asc"));
        assert_eq!(signature_name(Path::new("notes.txt")), Path::new("notes.txt.sig"));
        assert_eq!(decrypted_name(Path::new("notes.txt.asc")), Path::new("notes.txt"));
        assert_eq!(decrypted_name(Path::new("notes.txt.gpg")), Path::new("notes.txt"));
        // Nothing to strip: do not overwrite the input.
        assert_eq!(decrypted_name(Path::new("notes.txt")), Path::new("notes.txt.out"));
    }

    #[test]
    fn file_round_trip() {
        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let input = dir.path().join("notes.txt");
        std::fs::write(&input, b"the coordinates are in the second envelope").unwrap();

        let encrypted = encrypted_name(&input);
        encrypt_file(std::slice::from_ref(&alice), &[], Some((&alice, None)), &input, &encrypted).unwrap();

        let decrypted = dir.path().join("out.txt");
        let result = decrypt_file(&store, &encrypted, None, &decrypted).unwrap();

        assert!(result.all_good(), "signatures: {:?}", result.signatures);
        assert_eq!(
            std::fs::read(&decrypted).unwrap(),
            b"the coordinates are in the second envelope"
        );

        let signature = signature_name(&input);
        sign_detached_file(&alice, None, &input, &signature).unwrap();
        assert!(
            verify_detached_files(&store, &signature, &input)
                .unwrap()
                .all_good()
        );
    }

    #[test]
    fn failed_decryption_leaves_no_output_file() {
        let (dir, store) = scratch_store();
        let stranger = generate(&KeyGenRequest::new("Stranger <nobody@example.org>"))
            .unwrap()
            .cert;
        // The store never sees the secret key, so nothing can decrypt this.
        store.insert(&stranger).unwrap();

        let encrypted = dir.path().join("secret.asc");
        encrypt_file(&[stranger], &[], None, &{
            let p = dir.path().join("in.txt");
            std::fs::write(&p, b"x").unwrap();
            p
        }, &encrypted)
        .unwrap();

        let output = dir.path().join("out.txt");
        assert!(decrypt_file(&store, &encrypted, None, &output).is_err());
        assert!(!output.exists(), "a failed decryption must not create the output file");
    }

    #[test]
    fn a_revoked_key_still_opens_what_it_encrypted() {
        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let mut ciphertext = Vec::new();
        encrypt(
            std::slice::from_ref(&alice),
            &[],
            None,
            b"written while current",
            &mut ciphertext,
        )
        .unwrap();

        // Retire the whole certificate, as someone rotating keys would.
        let mut request = crate::revoke::RevokeRequest::new(alice.fingerprint().to_hex());
        request.reason = crate::revoke::Reason::Superseded;
        crate::revoke::revoke_cert(&store, &request).unwrap();
        assert_eq!(
            crate::CertSummary::from_cert(&store.lookup(&alice.fingerprint().to_hex()).unwrap())
                .validity,
            crate::Validity::Revoked
        );

        // The archive must stay readable. Revoking withdraws a key from future
        // use; it does not destroy what was already sent.
        let mut plaintext = Vec::new();
        decrypt(&store, &ciphertext, None, &mut plaintext).unwrap();
        assert_eq!(plaintext, b"written while current");
        let _ = dir;
    }

    #[test]
    fn encrypts_to_a_password_alone() {
        let (_dir, store) = scratch_store();

        let mut ciphertext = Vec::new();
        encrypt(&[], &["hunter2".to_string()], None, b"no keys involved", &mut ciphertext).unwrap();

        let mut plaintext = Vec::new();
        decrypt(&store, &ciphertext, Some("hunter2"), &mut plaintext).unwrap();
        assert_eq!(plaintext, b"no keys involved");

        // The wrong password must not open it, and neither must none.
        assert!(decrypt(&store, &ciphertext, Some("hunter3"), &mut Vec::new()).is_err());
        assert!(decrypt(&store, &ciphertext, None, &mut Vec::new()).is_err());
    }

    #[test]
    fn a_message_can_take_either_a_key_or_a_password() {
        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let mut ciphertext = Vec::new();
        encrypt(
            std::slice::from_ref(&alice),
            &["shared secret".to_string()],
            None,
            b"either way in",
            &mut ciphertext,
        )
        .unwrap();

        // Alice's key opens it with no password at all.
        let mut by_key = Vec::new();
        decrypt(&store, &ciphertext, None, &mut by_key).unwrap();
        assert_eq!(by_key, b"either way in");

        // And an empty store with only the password opens the same message.
        let (_other_dir, bare) = scratch_store();
        let mut by_password = Vec::new();
        decrypt(&bare, &ciphertext, Some("shared secret"), &mut by_password).unwrap();
        assert_eq!(by_password, b"either way in");
    }

    #[test]
    fn refuses_a_message_addressed_to_nobody() {
        assert!(encrypt(&[], &[], None, b"x", Vec::new()).is_err());
        assert!(encrypt(&[], &[String::new()], None, b"x", Vec::new()).is_err());
    }

    #[test]
    fn cleartext_signature_keeps_the_text_readable() {
        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let mut signed = Vec::new();
        sign_cleartext(&alice, None, b"the meeting is at noon", &mut signed).unwrap();

        // The point of cleartext: a reader who has no OpenPGP tools can still
        // read it.
        assert!(signed.starts_with(b"-----BEGIN PGP SIGNED MESSAGE-----"));
        assert!(
            String::from_utf8_lossy(&signed).contains("the meeting is at noon"),
            "the text should stay legible"
        );

        let (text, result) = verify_inline(&store, &signed).unwrap();
        assert_eq!(text, b"the meeting is at noon");
        assert!(result.all_good(), "signatures: {:?}", result.signatures);
        assert_eq!(result.signatures[0].signer, "Alice <alice@example.org>");
    }

    #[test]
    fn detached_signature_round_trip() {
        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let mut signature = Vec::new();
        sign_detached(&alice, None, b"minutes of the meeting", &mut signature).unwrap();

        let good = verify_detached(&store, &signature, b"minutes of the meeting").unwrap();
        assert!(good.all_good());

        let tampered = verify_detached(&store, &signature, b"minutes of the meating");
        assert!(tampered.is_err() || !tampered.unwrap().all_good());
    }
}
