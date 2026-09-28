//! The certificates Skein trusts, for every TLS connection it makes: to
//! PostgreSQL, to the bucket, to an npm upstream, to the licence
//! endpoint.
//!
//! Three sources, together:
//!
//! 1. the public roots Mozilla curates, compiled in — so a bucket on AWS
//!    works in an image with no CA store at all;
//! 2. the operating system's store, which honours `SSL_CERT_FILE` and
//!    `SSL_CERT_DIR` the way OpenSSL does;
//! 3. **`SKEIN_CA_FILE`**, a PEM bundle of the operator's own CAs.
//!
//! The third is the one an enterprise install needs. Its database, its
//! bucket and its package mirror are behind certificates its own CA
//! issued, and until this existed Skein trusted only the compiled-in
//! public roots: a MinIO or Ceph under a corporate CA failed every
//! request with `UnknownIssuer`, and there was no setting that could fix
//! it — stratum-core's "the image shipped without ca-certificates" in a
//! new shape.

use std::path::Path;
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};

/// The operator's own CAs: a PEM file of one or more certificates.
pub const CA_FILE_ENV: &str = "SKEIN_CA_FILE";

/// The one crypto provider: ring, which ureq already uses and which keeps
/// the release's static musl build free of cmake.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Every certificate in a PEM file. A file that holds none is an error:
/// an operator who named it meant it to hold one.
pub fn load_pem(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{} is not a PEM certificate bundle: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{} holds no PEM certificate", path.display()));
    }
    Ok(certs)
}

/// Exactly the certificates in `path` — what libpq's `sslrootcert`
/// means, where the file replaces the system's store rather than adding
/// to it.
pub fn roots_only(path: &Path) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    for cert in load_pem(path)? {
        roots
            .add(cert)
            .map_err(|e| format!("{}: a certificate rustls cannot use: {e}", path.display()))?;
    }
    Ok(roots)
}

/// The public roots, the OS store, and `extra` if given.
pub fn roots_with(extra: Option<&Path>) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // A store that partly fails to load still loads the rest; an image
    // with no store at all is not an error, the public roots are here.
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    if let Some(path) = extra {
        for cert in load_pem(path)? {
            roots
                .add(cert)
                .map_err(|e| format!("{}: a certificate rustls cannot use: {e}", path.display()))?;
        }
    }
    Ok(roots)
}

fn env_ca_file() -> Option<String> {
    std::env::var(CA_FILE_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The roots this process trusts, from the environment. An unreadable or
/// empty `SKEIN_CA_FILE` is an error: the operator's CA silently not
/// being trusted is the failure this exists to end.
pub fn roots_from_env() -> Result<RootCertStore, String> {
    let file = env_ca_file();
    roots_with(file.as_deref().map(Path::new)).map_err(|e| format!("{CA_FILE_ENV}: {e}"))
}

/// Checks the environment's trust settings — for a server to refuse to
/// start on a broken `SKEIN_CA_FILE` rather than fail every request.
pub fn check() -> Result<(), String> {
    roots_from_env().map(|_| ())
}

/// A client configuration verifying against `roots`. With `verify_host`
/// false the chain is checked and the host name is not — libpq's
/// `verify-ca`, for a database reached by an address its certificate
/// does not name.
pub fn client_config(roots: RootCertStore, verify_host: bool) -> Result<ClientConfig, String> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS configuration: {e}"))?;
    let roots = Arc::new(roots);
    Ok(if verify_host {
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        let inner = WebPkiServerVerifier::builder_with_provider(roots, provider)
            .build()
            .map_err(|e| format!("TLS configuration: {e}"))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ChainOnly(inner)))
            .with_no_client_auth()
    })
}

/// The configuration for every HTTPS call: the environment's roots, and
/// the host name always checked. Built once. If `SKEIN_CA_FILE` is broken
/// this falls back to the other two sources — the server has already
/// refused to start over it through [`check`].
pub fn config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = roots_from_env().unwrap_or_else(|e| {
                eprintln!("skein: {e}; trusting the public and system roots only");
                roots_with(None).unwrap_or_else(|_| RootCertStore::empty())
            });
            Arc::new(client_config(roots, true).expect("the default TLS configuration builds"))
        })
        .clone()
}

/// A ureq agent builder that trusts what [`config`] trusts. Every HTTPS
/// client in Skein starts here.
pub fn agent() -> ureq::AgentBuilder {
    ureq::AgentBuilder::new().tls_config(config())
}

/// What a TLS failure should tell the person reading it, appended to the
/// error: a certificate Skein cannot trust is almost always from an
/// operator's own CA that nothing told Skein about.
pub fn hint(error: &str) -> String {
    hint_to(error, &format!("{CA_FILE_ENV}=/path/to/ca.pem"))
}

/// [`hint`], naming where the CA goes for this connection — `sslrootcert`
/// for a database URL that carries one, which trusts that file and not
/// `SKEIN_CA_FILE`.
pub fn hint_to(error: &str, remedy: &str) -> String {
    if error.contains("UnknownIssuer") || error.contains("unknown issuer") {
        format!(
            "{error} — if this server's certificate comes from your own CA, give Skein that CA \
             with {remedy}"
        )
    } else if error.contains("BadSignature") {
        // The issuer's *name* matched a CA Skein trusts and its key did
        // not: a CA re-issued under the same name, with the old one still
        // configured.
        format!(
            "{error} — the certificate names a CA Skein trusts, but a different key signed it: \
             usually that CA was re-issued under the same name; give Skein the current one with \
             {remedy}"
        )
    } else {
        error.to_string()
    }
}

/// Verifies the chain and not the host name.
#[derive(Debug)]
struct ChainOnly(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for ChainOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self
            .0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
        {
            Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForName))
            | Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForNameContext {
                ..
            })) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("skein-tls-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_ca_file_adds_to_the_public_and_system_roots() {
        let base = roots_with(None).unwrap();
        assert!(
            base.len() > 50,
            "the public roots are compiled in: {}",
            base.len()
        );
        let dir = tmp("adds");
        let ca = rcgen::generate_simple_self_signed(vec!["ca.acme.test".into()]).unwrap();
        let path = dir.join("ca.pem");
        std::fs::write(&path, ca.cert.pem()).unwrap();
        assert_eq!(roots_with(Some(&path)).unwrap().len(), base.len() + 1);
        assert_eq!(
            roots_only(&path).unwrap().len(),
            1,
            "sslrootcert replaces, not adds"
        );
    }

    #[test]
    fn a_ca_file_that_is_not_one_is_an_error_that_names_it() {
        let dir = tmp("bad");
        let empty = dir.join("empty.pem");
        std::fs::write(&empty, "").unwrap();
        let err = roots_with(Some(&empty)).unwrap_err();
        assert!(err.contains("empty.pem") && err.contains("no PEM"), "{err}");
        let missing = dir.join("missing.pem");
        let err = roots_with(Some(&missing)).unwrap_err();
        assert!(err.contains("missing.pem"), "{err}");
        let junk = dir.join("junk.pem");
        std::fs::write(
            &junk,
            "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(roots_with(Some(&junk)).is_err());
    }

    #[test]
    fn an_unknown_issuer_says_where_the_ca_goes() {
        let h = hint("invalid peer certificate: UnknownIssuer");
        assert!(h.contains(CA_FILE_ENV), "{h}");
        assert_eq!(hint("connection refused"), "connection refused");
        let h = hint("invalid peer certificate: BadSignature");
        assert!(h.contains("re-issued") && h.contains(CA_FILE_ENV), "{h}");
        let h = hint_to("invalid peer certificate: UnknownIssuer", "sslrootcert=…");
        assert!(h.contains("sslrootcert") && !h.contains(CA_FILE_ENV), "{h}");
    }
}
