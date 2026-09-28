//! A private CA and the server certificates it issues — the shape of an
//! enterprise network, where the database, the bucket and the package
//! mirror all present certificates from the company's own CA and nothing
//! in any public root store vouches for them.
//!
//! Generated per test run with rcgen (ECDSA P-256), written to a scratch
//! directory, and gone when the [`Pki`] is dropped.

use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

use crate::tempdir::TempDir;

pub struct Pki {
    dir: TempDir,
    issuer: Issuer<'static, KeyPair>,
    /// The CA certificate, PEM — what `SKEIN_CA_FILE` or `sslrootcert`
    /// is pointed at.
    pub ca_pem: PathBuf,
}

/// A server's certificate and key, PEM, signed by the [`Pki`]'s CA.
pub struct ServerCert {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl Pki {
    pub fn new() -> Pki {
        let dir = TempDir::new("skein-pki").expect("a scratch directory");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params
            .distinguished_name
            .push(DnType::CommonName, "Skein Test Internal Root CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let key = KeyPair::generate().expect("a CA key");
        let cert = params.self_signed(&key).expect("a CA certificate");
        let ca_pem = dir.path().join("ca.pem");
        std::fs::write(&ca_pem, cert.pem()).expect("write the CA");
        Pki {
            dir,
            issuer: Issuer::new(params, key),
            ca_pem,
        }
    }

    /// A certificate for `names` — host names or IP addresses, as the
    /// server will be addressed.
    pub fn server(&self, file: &str, names: &[&str]) -> ServerCert {
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let mut params = CertificateParams::new(names.clone()).expect("server params");
        params.distinguished_name.push(
            DnType::CommonName,
            names.first().cloned().unwrap_or_default(),
        );
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().expect("a server key");
        let cert = params
            .signed_by(&key, &self.issuer)
            .expect("a server certificate");
        let out = ServerCert {
            cert: self.dir.path().join(format!("{file}.crt")),
            key: self.dir.path().join(format!("{file}.key")),
        };
        std::fs::write(&out.cert, cert.pem()).expect("write the certificate");
        std::fs::write(&out.key, key.serialize_pem()).expect("write the key");
        out
    }

    pub fn dir(&self) -> &Path {
        self.dir.path()
    }
}

impl Default for Pki {
    fn default() -> Pki {
        Pki::new()
    }
}
