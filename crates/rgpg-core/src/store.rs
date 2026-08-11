//! On-disk certificate storage.
//!
//! Public certificates live in a [pgp-cert-d] directory, the same layout `sq`
//! uses, so certificates are shared with other Sequoia tooling instead of being
//! locked inside this app. The default location is
//! `$XDG_DATA_HOME/pgp.cert.d`; set `RGPG_CERT_STORE` to override it.
//!
//! Secret keys are *not* stored there. cert-d is a store of public
//! certificates, and mixing transferable secret keys into it would leak them to
//! every tool that reads the directory. For now they go in a separate
//! `$XDG_DATA_HOME/rgpg/secrets` directory, one binary TSK per file.
//!
//! Those files are `0600` inside a `0700` directory, tightened on every open
//! rather than only on create. A key generated with a passphrase is encrypted
//! with it; a key generated without one is not, and then the permissions are
//! the only thing protecting it — the same trade GnuPG makes.
//!
//! In use, a key is decrypted for the span of a single operation and dropped.
//! Sequoia holds it sealed in RAM even while unlocked and zeroes it on drop,
//! and on Linux the GUI process refuses core dumps and debugger attach (see
//! `rgpg-gui`'s `hardening` module — macOS gets neither until the release is
//! codesigned with the hardened runtime). None of that is a privilege boundary:
//! key material does pass through this process, so root — or anything holding
//! `CAP_SYS_PTRACE` — can still read it.
//!
//! `sequoia-keystore` is not the fix it appears to be, which is why this is
//! still the design. Its default IPC policy silently degrades to a thread in
//! the caller's own address space, with no API to detect that it happened;
//! and forced into a real separate process it still runs as the same user,
//! authenticates over loopback with a cookie file that user can read, and
//! exposes an RPC that hands back the secret key. Smartcards go through
//! gpg-agent instead (see [`crate::agent`]), which is a boundary that means
//! something only because the key never leaves the card.
//!
//! [pgp-cert-d]: https://www.ietf.org/archive/id/draft-nwjw-openpgp-cert-d-02.html

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sequoia_cert_store::{CertStore, LazyCert, Store as _, StoreUpdate as _};
use sequoia_openpgp::Cert;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Serialize;

use crate::error::{Error, Result};

pub struct Store {
    certs: CertStore<'static>,
    secrets_dir: PathBuf,
    /// Fingerprints the user has explicitly designated as trust roots, one per
    /// line. Own keys are roots implicitly — see [`Store::effective_roots`].
    roots_path: PathBuf,
    /// Revocation certificates made at key-generation time, kept against the
    /// day the secret key or its passphrase is gone.
    revocations_dir: PathBuf,
}

impl Store {
    /// Open the default store, creating both directories if they are missing.
    pub fn open_default() -> Result<Self> {
        let cert_dir = match std::env::var_os("RGPG_CERT_STORE") {
            Some(dir) => PathBuf::from(dir),
            None => dirs::data_dir()
                .ok_or(Error::NoStoreDir)?
                .join("pgp.cert.d"),
        };
        let secrets_dir = dirs::data_dir()
            .ok_or(Error::NoStoreDir)?
            .join("rgpg")
            .join("secrets");
        Self::open(cert_dir, secrets_dir)
    }

    pub fn open(cert_dir: impl AsRef<Path>, secrets_dir: impl AsRef<Path>) -> Result<Self> {
        let cert_dir = cert_dir.as_ref();
        let secrets_dir = secrets_dir.as_ref();

        fs::create_dir_all(cert_dir)
            .map_err(|e| Error::io(format!("creating {}", cert_dir.display()), e))?;
        fs::create_dir_all(secrets_dir)
            .map_err(|e| Error::io(format!("creating {}", secrets_dir.display()), e))?;
        // Secret key material, and the revocation certificates that could
        // retire a key, must not be world-readable. Tighten on every open, not
        // only on create: a store made by an earlier version is already
        // exposed, and the user has no way to know it.
        restrict(secrets_dir, 0o700)?;
        for path in existing_files(secrets_dir) {
            restrict(&path, 0o600)?;
        }

        Ok(Store {
            certs: CertStore::open(cert_dir)?,
            secrets_dir: secrets_dir.to_path_buf(),
            roots_path: secrets_dir.with_file_name("trust-roots"),
            revocations_dir: secrets_dir.with_file_name("revocations"),
        })
    }

    // Deleting a certificate is not implemented. Unlinking the cert-d file is
    // not enough: sequoia-cert-store keeps a SQLite index beside it and that
    // index is authoritative, so a removed certificate is still listed even by
    // a freshly reopened store. Doing this properly needs removal support in
    // cert-d, or a different backing store.

    /// Where the revocation certificate for `fingerprint` lives.
    pub fn revocation_path(&self, fingerprint: &str) -> PathBuf {
        self.revocations_dir.join(format!("{fingerprint}.rev"))
    }

    pub fn has_revocation(&self, fingerprint: &str) -> bool {
        self.revocation_path(fingerprint).exists()
    }

    /// Keep a revocation certificate. Written once, at key generation.
    pub fn save_revocation(&self, fingerprint: &str, armored: &[u8]) -> Result<()> {
        fs::create_dir_all(&self.revocations_dir)
            .map_err(|e| Error::io(format!("creating {}", self.revocations_dir.display()), e))?;
        restrict(&self.revocations_dir, 0o700)?;

        // Anyone holding this file can retire the key it belongs to.
        let path = self.revocation_path(fingerprint);
        let mut file = create_private(&path)?;
        file.write_all(armored)
            .map_err(|e| Error::io(format!("writing {}", path.display()), e))
    }

    /// Fingerprints the user has explicitly marked as trust roots.
    pub fn trust_roots(&self) -> Result<BTreeSet<String>> {
        match fs::read_to_string(&self.roots_path) {
            Ok(text) => Ok(text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_uppercase)
                .collect()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(Error::io(
                format!("reading {}", self.roots_path.display()),
                e,
            )),
        }
    }

    pub fn set_trust_root(&self, fingerprint: &str, root: bool) -> Result<()> {
        let mut roots = self.trust_roots()?;
        if root {
            roots.insert(fingerprint.to_uppercase());
        } else {
            roots.remove(&fingerprint.to_uppercase());
        }

        let mut text = roots.into_iter().collect::<Vec<_>>().join("\n");
        text.push('\n');
        fs::write(&self.roots_path, text)
            .map_err(|e| Error::io(format!("writing {}", self.roots_path.display()), e))
    }

    /// The roots the web of trust is actually evaluated against: the explicit
    /// list plus every certificate whose secret key is here.
    ///
    /// Own keys are included automatically because the alternative — a fresh
    /// install where nothing authenticates until the user finds a checkbox — is
    /// the wrong default, and because a key you hold the secret half of is one
    /// you already trust by definition.
    pub fn effective_roots(&self) -> Result<BTreeSet<String>> {
        let mut roots = self.trust_roots()?;
        for cert in self.secret_certs()? {
            roots.insert(cert.fingerprint().to_hex().to_uppercase());
        }
        Ok(roots)
    }

    /// Every public certificate in the store, parsed.
    ///
    /// cert-d hands back `LazyCert`s that are only parsed on demand; the GUI
    /// needs every field of every row, so they are all resolved here.
    pub fn certs(&self) -> Result<Vec<Cert>> {
        let mut out = Vec::new();
        for lazy in self.certs.certs() {
            out.push(lazy.to_cert()?.clone());
        }
        Ok(out)
    }

    /// Look a certificate up by full fingerprint or key ID, as typed by a user.
    pub fn lookup(&self, handle: &str) -> Result<Cert> {
        let handle: sequoia_openpgp::KeyHandle = handle
            .parse()
            .map_err(|_| Error::invalid(format!("{handle} is not a fingerprint or key ID")))?;
        let found = self.certs.lookup_by_cert_or_subkey(&handle)?;
        let first = found
            .into_iter()
            .next()
            .ok_or_else(|| Error::NoSuchCert(handle.to_string()))?;
        Ok(first.to_cert()?.clone())
    }

    /// Insert or merge a public certificate.
    ///
    /// Secret key material is stripped first: `update` writes to cert-d, which
    /// is world-readable by design.
    pub fn insert(&self, cert: &Cert) -> Result<()> {
        self.certs.update(Arc::new(LazyCert::from(
            cert.clone().strip_secret_key_material(),
        )))?;
        Ok(())
    }

    /// Store a transferable secret key, and its public half in cert-d.
    pub fn insert_secret(&self, cert: &Cert) -> Result<()> {
        if !cert.is_tsk() {
            return Err(Error::invalid("certificate carries no secret key material"));
        }
        let path = self.secret_path(&cert.fingerprint().to_hex());
        let mut file = create_private(&path)?;
        cert.as_tsk().serialize(&mut file)?;
        self.insert(cert)
    }

    /// Every transferable secret key on disk.
    pub fn secret_certs(&self) -> Result<Vec<Cert>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.secrets_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => {
                return Err(Error::io(
                    format!("reading {}", self.secrets_dir.display()),
                    e,
                ));
            }
        };
        for entry in entries {
            let path = entry
                .map_err(|e| Error::io(format!("reading {}", self.secrets_dir.display()), e))?
                .path();
            if path.extension().is_some_and(|e| e == "pgp") {
                out.push(Cert::from_file(&path)?);
            }
        }
        Ok(out)
    }

    /// The secret key for `fingerprint`, if this store holds one.
    pub fn secret_cert(&self, fingerprint: &str) -> Result<Cert> {
        let path = self.secret_path(fingerprint);
        if !path.exists() {
            return Err(Error::NoSecretKey(fingerprint.to_string()));
        }
        Ok(Cert::from_file(&path)?)
    }

    pub fn has_secret(&self, fingerprint: &str) -> bool {
        self.secret_path(fingerprint).exists()
    }

    /// GnuPG's default public keyring, if there is one.
    pub fn gnupg_keybox() -> Option<PathBuf> {
        let home = std::env::var_os("GNUPGHOME")
            .map(PathBuf::from)
            .or_else(|| dirs::home_dir().map(|h| h.join(".gnupg")))?;
        let keybox = home.join("pubring.kbx");
        keybox.exists().then_some(keybox)
    }

    /// Import every certificate from a GnuPG Keybox.
    ///
    /// `pubring.kbx` is a container format of GnuPG's own, not an OpenPGP
    /// keyring, so `CertParser` cannot read it — which is why importing a
    /// GnuPG setup used to mean an export/import dance. A Keybox also holds
    /// X.509 certificates, and those are skipped.
    ///
    /// Only public certificates: GnuPG keeps secret keys separately, in
    /// gpg-agent's own format, and they are reached through the agent instead.
    pub fn import_keybox(&self, path: impl AsRef<Path>) -> Result<Vec<Cert>> {
        use sequoia_ipc::keybox::{Keybox, KeyboxRecord};

        let path = path.as_ref();
        let keybox = Keybox::from_file(path)
            .map_err(|e| Error::invalid(format!("{} is not a Keybox: {e}", path.display())))?;

        let mut imported = Vec::new();
        for record in keybox {
            let Ok(KeyboxRecord::OpenPGP(record)) = record else {
                continue;
            };
            // One unreadable record should not lose the rest of a keyring.
            let Ok(cert) = record.cert() else {
                continue;
            };
            self.insert(&cert)?;
            imported.push(cert);
        }

        if imported.is_empty() {
            return Err(Error::invalid(format!(
                "{} holds no OpenPGP certificates",
                path.display()
            )));
        }
        Ok(imported)
    }

    /// Import every certificate in a keyring or armored file.
    ///
    /// Returns the certificates that were imported, secret keys included: a
    /// backup restore and a public keyring import land in the same code path,
    /// which is what a user dropping a file on the window expects.
    pub fn import_file(&self, path: impl AsRef<Path>) -> Result<Vec<Cert>> {
        let path = path.as_ref();

        // A Keybox announces itself with "KBXf" eight bytes in. Sniffing beats
        // trusting the extension: people rename these files.
        let mut magic = [0u8; 12];
        if let Ok(mut file) = fs::File::open(path)
            && std::io::Read::read_exact(&mut file, &mut magic).is_ok()
            && &magic[8..12] == b"KBXf"
        {
            return self.import_keybox(path);
        }

        let parser = sequoia_openpgp::cert::CertParser::from_file(path)?;
        let mut imported = Vec::new();
        for cert in parser {
            let cert = cert?;
            if cert.is_tsk() {
                self.insert_secret(&cert)?;
            } else {
                self.insert(&cert)?;
            }
            imported.push(cert);
        }
        if imported.is_empty() {
            return Err(Error::invalid(format!(
                "{} contains no OpenPGP certificates",
                path.display()
            )));
        }
        Ok(imported)
    }

    /// Write certificates to an ASCII-armored file.
    ///
    /// Only public halves are written; exporting a secret key is a separate,
    /// deliberately louder operation.
    pub fn export_file(&self, fingerprints: &[String], path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let file = fs::File::create(path)
            .map_err(|e| Error::io(format!("writing {}", path.display()), e))?;
        let mut writer = sequoia_openpgp::armor::Writer::new(
            io::BufWriter::new(file),
            sequoia_openpgp::armor::Kind::PublicKey,
        )?;
        for fpr in fingerprints {
            let cert = self.lookup(fpr)?;
            cert.strip_secret_key_material().serialize(&mut writer)?;
        }
        writer.finalize()?;
        Ok(())
    }

    fn secret_path(&self, fingerprint: &str) -> PathBuf {
        self.secrets_dir.join(format!("{fingerprint}.pgp"))
    }
}

/// Files directly inside `dir`, ignoring anything unreadable.
fn existing_files(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect()
}

/// Create a file only the current user can read, with the mode set at the
/// moment of creation.
///
/// Creating it and then relaxing to `chmod` would leave a window in which
/// another user could open the file and keep that descriptor across every
/// later write.
fn create_private(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|e| Error::io(format!("writing {}", path.display()), e))
}

/// Restrict a path to the current user.
///
/// A no-op off Unix, where the permission model does not map: Windows would
/// need an ACL, and pretending otherwise would be worse than being explicit.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| Error::io(format!("restricting {}", path.display()), e))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        (dir, store)
    }

    /// Against the developer's own GnuPG keyring when there is one. Read-only:
    /// it imports into a scratch store and never touches ~/.gnupg.
    #[test]
    #[ignore = "reads the local GnuPG keyring"]
    fn imports_the_local_gnupg_keybox() {
        let Some(keybox) = Store::gnupg_keybox() else {
            eprintln!("no pubring.kbx; skipping");
            return;
        };
        let (_dir, store) = scratch();

        // Through import_file, so the magic-byte sniffing is exercised too.
        let imported = store.import_file(&keybox).unwrap();
        eprintln!(
            "imported {} certificate(s) from {}",
            imported.len(),
            keybox.display()
        );
        for cert in imported.iter().take(3) {
            eprintln!("  {}", crate::CertSummary::from_cert(cert).primary_user_id);
        }

        assert!(!imported.is_empty());
        assert_eq!(store.certs().unwrap().len(), imported.len());
        // A Keybox holds only public certificates.
        assert!(imported.iter().all(|c| !c.is_tsk()));
    }

    /// Secret key material and revocation certificates must not be readable
    /// by other users on the machine. Asserted on the bytes on disk, because
    /// the default umask makes 0644 the thing that happens by accident.
    #[test]
    #[cfg(unix)]
    fn private_files_are_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        fn mode(path: &Path) -> u32 {
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        }

        let (dir, store) = scratch();
        let secrets = dir.path().join("secrets");

        let request = crate::keygen::KeyGenRequest::new("Alice <alice@example.org>");
        let generated = crate::keygen::generate(&request).unwrap();
        store.insert_secret(&generated.cert).unwrap();
        let fingerprint = generated.cert.fingerprint().to_hex();
        store
            .save_revocation(
                &fingerprint,
                &crate::revoke::armor(&generated.revocation).unwrap(),
            )
            .unwrap();

        assert_eq!(mode(&secrets), 0o700, "secrets directory");
        assert_eq!(mode(&store.secret_path(&fingerprint)), 0o600, "secret key");
        assert_eq!(mode(&store.revocations_dir), 0o700, "revocations directory");
        assert_eq!(
            mode(&store.revocation_path(&fingerprint)),
            0o600,
            "revocation certificate",
        );

        // A store written by an earlier version is already exposed; reopening
        // it has to repair that rather than leave it.
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            store.secret_path(&fingerprint),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let reopened = Store::open(dir.path().join("certs.d"), &secrets).unwrap();
        assert_eq!(mode(&secrets), 0o700, "secrets directory after reopen");
        assert_eq!(
            mode(&reopened.secret_path(&fingerprint)),
            0o600,
            "secret key after reopen",
        );
    }

    #[test]
    fn store_is_shareable_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Store>();
    }

    #[test]
    fn round_trips_a_generated_key() {
        let (_dir, store) = scratch();
        assert!(store.certs().unwrap().is_empty());

        let request = crate::keygen::KeyGenRequest::new("Alice <alice@example.org>");
        let cert = crate::keygen::generate(&request).unwrap().cert;
        store.insert_secret(&cert).unwrap();

        let certs = store.certs().unwrap();
        assert_eq!(certs.len(), 1);
        // The public store must not have picked up the secret half.
        assert!(!certs[0].is_tsk());
        assert!(store.has_secret(&cert.fingerprint().to_hex()));
        assert!(
            store
                .secret_cert(&cert.fingerprint().to_hex())
                .unwrap()
                .is_tsk()
        );
    }
}
