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

/// What a keyserver did with an upload.
#[derive(Debug, Clone)]
pub struct Published {
    /// Fingerprint the server says it stored.
    pub fingerprint: String,
    /// Addresses the server will publish once their owner confirms, and the
    /// state it reports for each.
    pub addresses: Vec<(String, String)>,
    /// Handed back so verification mails can be requested for the addresses.
    pub token: Option<String>,
}

/// Upload a certificate to the keyserver.
///
/// This cannot be undone. A keyserver has no delete: once a certificate is
/// uploaded it is public, permanently, and so is every user ID on it. Callers
/// must make that clear before getting here.
///
/// Only the public half is ever sent — the secret key material is stripped
/// first, so a caller that hands over a certificate carrying secrets does not
/// publish them by accident.
pub fn publish(cert: &Cert) -> Result<Published> {
    use sequoia_openpgp::serialize::SerializeInto;

    let public = cert.clone().strip_secret_key_material();
    let armored = String::from_utf8(public.armored().to_vec()?)
        .map_err(|_| Error::invalid("the certificate did not armor as text"))?;

    let body = serde_json::json!({ "keytext": armored });
    let reply = post(&format!("{KEYSERVER}/vks/v1/upload"), body)?;

    Ok(Published {
        fingerprint: reply
            .get("key_fpr")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_uppercase(),
        addresses: reply
            .get("status")
            .and_then(|v| v.as_object())
            .map(|statuses| {
                statuses
                    .iter()
                    .map(|(address, state)| {
                        (
                            address.clone(),
                            state.as_str().unwrap_or("unknown").to_lowercase(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        token: reply
            .get("token")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
    })
}

/// Ask the keyserver to mail each address a confirmation link.
///
/// Until an address is confirmed the keyserver stores the certificate but will
/// not serve it by that address, which is the whole point of a verifying
/// keyserver: nobody can publish an identity they do not control.
pub fn request_verification(token: &str, addresses: &[String]) -> Result<()> {
    if addresses.is_empty() {
        return Err(Error::invalid("no addresses to verify"));
    }
    let body = serde_json::json!({ "token": token, "addresses": addresses });
    post(&format!("{KEYSERVER}/vks/v1/request-verify"), body)?;
    Ok(())
}

fn post(url: &str, body: serde_json::Value) -> Result<serde_json::Value> {
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
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::invalid(format!("upload failed: {e}")))?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            // The server explains refusals in the body; passing it through
            // beats reporting a bare status code.
            return Err(Error::invalid(format!(
                "the keyserver refused the upload ({status}): {}",
                text.trim()
            )));
        }
        serde_json::from_str(&text)
            .map_err(|e| Error::invalid(format!("the keyserver replied with unexpected data: {e}")))
    })
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

    /// Against the real network, so `#[ignore]`d: it needs an internet
    /// connection and depends on other people's servers staying up.
    #[test]
    #[ignore = "hits the network"]
    fn finds_a_certificate_on_the_live_network() {
        // A long-standing WKD deployment, used as the example in several
        // OpenPGP tutorials.
        match lookup_wkd("wiktor@metacode.biz") {
            Ok(found) if !found.is_empty() => {
                let summary = crate::CertSummary::from_cert(&found[0].cert);
                eprintln!(
                    "WKD: {} {} via {}",
                    summary.fingerprint, summary.primary_user_id, found[0].source.as_str()
                );
                assert_eq!(found[0].source, Source::WebKeyDirectory);
            }
            Ok(_) => eprintln!("WKD: nothing served for that address"),
            Err(e) => eprintln!("WKD: {e}"),
        }

        // keys.openpgp.org serves by fingerprint without verification.
        let fingerprint = "653909A2F0E37C106F5FAF546C8857E0D8E8F074";
        match lookup_keyserver(fingerprint) {
            Ok(found) if !found.is_empty() => {
                let summary = crate::CertSummary::from_cert(&found[0].cert);
                eprintln!("keyserver: {} {}", summary.fingerprint, summary.primary_user_id);
                assert_eq!(found[0].source, Source::Keyserver);
                assert_eq!(summary.fingerprint, fingerprint);
            }
            Ok(_) => eprintln!("keyserver: nothing served"),
            Err(e) => eprintln!("keyserver: {e}"),
        }
    }

    #[test]
    fn rejects_input_that_is_not_an_address() {
        assert!(lookup_wkd("not-an-address").is_err());
        assert!(lookup_wkd("@example.org").is_err());
        assert!(lookup("   ").is_err());
    }
}
