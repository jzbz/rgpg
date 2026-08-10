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
//! That secret store is scaffold-grade: the keys sit on disk with only their
//! own passphrase protection, and every operation that needs one loads it into
//! this process. A real replacement is `sequoia-keystore`, which keeps key
//! material in a separate daemon and is the only route to smartcard support.
//!
//! [pgp-cert-d]: https://www.ietf.org/archive/id/draft-nwjw-openpgp-cert-d-02.html

use std::collections::BTreeSet;
use std::fs;
use std::io;
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
}

impl Store {
    /// Open the default store, creating both directories if they are missing.
    pub fn open_default() -> Result<Self> {
        let cert_dir = match std::env::var_os("RGPG_CERT_STORE") {
            Some(dir) => PathBuf::from(dir),
            None => dirs::data_dir().ok_or(Error::NoStoreDir)?.join("pgp.cert.d"),
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

        Ok(Store {
            certs: CertStore::open(cert_dir)?,
            secrets_dir: secrets_dir.to_path_buf(),
            roots_path: secrets_dir.with_file_name("trust-roots"),
        })
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
        self.certs
            .update(Arc::new(LazyCert::from(cert.clone().strip_secret_key_material())))?;
        Ok(())
    }

    /// Store a transferable secret key, and its public half in cert-d.
    pub fn insert_secret(&self, cert: &Cert) -> Result<()> {
        if !cert.is_tsk() {
            return Err(Error::invalid("certificate carries no secret key material"));
        }
        let path = self.secret_path(&cert.fingerprint().to_hex());
        let mut file = fs::File::create(&path)
            .map_err(|e| Error::io(format!("writing {}", path.display()), e))?;
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

    /// Import every certificate in a keyring or armored file.
    ///
    /// Returns the certificates that were imported, secret keys included: a
    /// backup restore and a public keyring import land in the same code path,
    /// which is what a user dropping a file on the window expects.
    pub fn import_file(&self, path: impl AsRef<Path>) -> Result<Vec<Cert>> {
        let path = path.as_ref();
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        (dir, store)
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
