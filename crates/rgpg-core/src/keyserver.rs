//! Finding certificates that are not in the store yet: Web Key Directory and
//! HKPS keyservers.
//!
//! Both protocols are plain HTTPS GETs returning an OpenPGP certificate, which
//! is why this is hand-rolled rather than delegated to `sequoia-net`: that
//! crate hardcodes `hyper-tls` and a `dnssec-openssl` resolver with no feature
//! to opt out, and OpenSSL is precisely what this build has avoided
//! everywhere else. `reqwest` with `rustls-tls` keeps it pure Rust.
//!
//! WKD is tried before a keyserver. A certificate served from the domain of
//! the address itself carries more weight than one anybody could upload.

use std::time::Duration;

use sequoia_openpgp::Cert;
use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::parse::Parse;

use crate::error::{Error, Result};

/// Where a certificate was found, so the UI can say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Served by the domain of the address itself.
    WebKeyDirectory,
    Keyserver,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::WebKeyDirectory => "web key directory",
            Source::Keyserver => "keyserver",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Found {
    pub cert: Cert,
    pub source: Source,
}

const TIMEOUT: Duration = Duration::from_secs(10);
/// Verifying keyserver: it only serves addresses whose owner confirmed them.
const KEYSERVER: &str = "https://keys.openpgp.org";

/// Look `query` up, preferring the Web Key Directory.
///
/// `query` is an e-mail address, a fingerprint or a key ID. Only an address can
/// be looked up over WKD, since the protocol is defined in terms of one.
pub fn lookup(query: &str) -> Result<Vec<Found>> {
    let query = query.trim();
    if query.is_empty() {
        return Err(Error::invalid("nothing to look up"));
    }

    if query.contains('@') {
        if let Ok(found) = lookup_wkd(query)
            && !found.is_empty()
        {
            return Ok(found);
        }
    }
    lookup_keyserver(query)
}

/// Fetch from the address's own domain.
pub fn lookup_wkd(address: &str) -> Result<Vec<Found>> {
    let (local, domain) = address
        .rsplit_once('@')
        .ok_or_else(|| Error::invalid(format!("{address} is not an e-mail address")))?;
    if local.is_empty() || domain.is_empty() {
        return Err(Error::invalid(format!("{address} is not an e-mail address")));
    }

    let domain = domain.to_lowercase();
    let hash = wkd_hash(local);
    let encoded = percent_encode(local);

    // The advanced method is tried first, as the specification requires: a
    // domain that delegates to openpgpkey.<domain> should win over the direct
    // URL, which may be served by unrelated web hosting.
    let urls = [
        format!(
            "https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hash}?l={encoded}"
        ),
        format!("https://{domain}/.well-known/openpgpkey/hu/{hash}?l={encoded}"),
    ];

    for url in urls {
        if let Ok(bytes) = get(&url)
            && let Ok(certs) = parse(&bytes)
            && !certs.is_empty()
        {
            return Ok(certs
                .into_iter()
                .map(|cert| Found {
                    cert,
                    source: Source::WebKeyDirectory,
                })
                .collect());
        }
    }
    Ok(Vec::new())
}

/// Fetch from a HKPS keyserver.
pub fn lookup_keyserver(query: &str) -> Result<Vec<Found>> {
    let url = format!(
        "{KEYSERVER}/pks/lookup?op=get&options=mr&search={}",
        percent_encode(query)
    );
    let bytes = get(&url)?;
    Ok(parse(&bytes)?
        .into_iter()
        .map(|cert| Found {
            cert,
            source: Source::Keyserver,
        })
        .collect())
}

/// The local part hashed and z-base-32 encoded, as WKD defines it: lowercased,
/// SHA-1, then 32 characters of z-base-32.
fn wkd_hash(local: &str) -> String {
    use sha1::{Digest, Sha1};
    let digest = Sha1::digest(local.to_lowercase().as_bytes());
    zbase32::encode(digest)
}

/// Escape the characters that would otherwise end the query parameter. Kept
/// deliberately small rather than pulling a dependency for it.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn get(url: &str) -> Result<Vec<u8>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::invalid(format!("cannot start the network runtime: {e}")))?;

    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent(concat!("rgpg/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::invalid(format!("cannot build an HTTP client: {e}")))?;

        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::invalid(format!("lookup failed: {e}")))?;

        if !response.status().is_success() {
            return Err(Error::invalid(format!(
                "lookup returned {}",
                response.status()
            )));
        }
        Ok(response
            .bytes()
            .await
            .map_err(|e| Error::invalid(format!("reading the reply failed: {e}")))?
            .to_vec())
    })
}

fn parse(bytes: &[u8]) -> Result<Vec<Cert>> {
    let mut out = Vec::new();
    for cert in CertParser::from_bytes(bytes)? {
        // A keyserver can serve several certificates; a broken one among them
        // should not lose the rest.
        if let Ok(cert) = cert {
            out.push(cert);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_wkd_hash_from_the_specification() {
        // The example from the WKD draft: Joe.Doe@example.org hashes to this.
        assert_eq!(wkd_hash("Joe.Doe"), "iy9q119eutrkn8s1mk4r39qejnbu3n5q");
    }

    #[test]
    fn escapes_the_query() {
        assert_eq!(percent_encode("a b+c@d"), "a%20b%2Bc%40d");
        assert_eq!(percent_encode("plain-name.1_x~"), "plain-name.1_x~");
    }

    #[test]
    fn rejects_input_that_is_not_an_address() {
        assert!(lookup_wkd("not-an-address").is_err());
        assert!(lookup_wkd("@example.org").is_err());
        assert!(lookup("   ").is_err());
    }
}
