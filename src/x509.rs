use std::{path::Path, sync::Arc};

use anyhow::Context;
use no_verification_derive::NoCertVerification;
use rustls_pemfile::Item as PemItem;
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer},
};

pub struct X509 {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl X509 {
    pub async fn from_env() -> anyhow::Result<Self> {
        let key_path = std::env::var("KEY_PATH")?;
        let cert_path = std::env::var("CERT_PATH")?;

        let key_task = tokio::task::spawn_blocking(move || load_pem_key(key_path));
        let cert_task = tokio::task::spawn_blocking(move || load_pem_cert(cert_path));

        let (key, cert) = tokio::join!(key_task, cert_task);

        Ok(Self {
            key: key??,
            cert: cert??,
        })
    }
}

impl TryFrom<X509> for rustls::ClientConfig {
    type Error = anyhow::Error;

    fn try_from(x509: X509) -> Result<Self, Self::Error> {
        Self::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {}))
            .with_client_auth_cert(vec![x509.cert], x509.key)
            .map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Debug, NoCertVerification)]
pub struct NoCertificateVerification {}

pub fn load_pem_key(filepath: impl AsRef<Path>) -> anyhow::Result<PrivateKeyDer<'static>> {
    let res = match read_pem_file(&filepath)? {
        PemItem::Pkcs1Key(key) => Ok(PrivateKeyDer::Pkcs1(key)),
        PemItem::Pkcs8Key(key) => Ok(PrivateKeyDer::Pkcs8(key)),
        PemItem::Sec1Key(key) => Ok(PrivateKeyDer::Sec1(key)),
        PemItem::X509Certificate(_) => Err(anyhow::anyhow!("key path contains a certificate")),
        PemItem::Crl(_) => Err(anyhow::anyhow!("key path contains a CRL")),
        PemItem::Csr(_) => Err(anyhow::anyhow!("key path contains a CSR")),
        _ => Err(anyhow::anyhow!("unsupported pem item")),
    };

    if let Err(e) = res {
        tracing::error!("{e}");
        anyhow::bail!("invalid pem key: {}", filepath.as_ref().display());
    }

    res
}

pub fn load_pem_cert(filepath: impl AsRef<Path>) -> anyhow::Result<CertificateDer<'static>> {
    let res = match read_pem_file(&filepath)? {
        PemItem::X509Certificate(cert) => Ok(cert),
        PemItem::Pkcs1Key(_) | PemItem::Pkcs8Key(_) | PemItem::Sec1Key(_) => {
            Err(anyhow::anyhow!("cert path contains a key"))
        }
        PemItem::Crl(_) => Err(anyhow::anyhow!("cert path contains a CRL")),
        PemItem::Csr(_) => Err(anyhow::anyhow!("cert path contains a CSR")),
        _ => Err(anyhow::anyhow!("unsupported pem item")),
    };

    if let Err(e) = res {
        tracing::error!("{e}");
        anyhow::bail!("invalid pem cert: {}", filepath.as_ref().display());
    }

    res
}

fn read_pem_file(filepath: &impl AsRef<Path>) -> anyhow::Result<PemItem> {
    let path: &Path = filepath.as_ref();

    anyhow::ensure!(path.exists(), "filepath {} does not exist", path.display());

    let file = std::fs::File::open(filepath)?;
    let mut reader = std::io::BufReader::new(file);

    let pem_file = rustls_pemfile::read_one(&mut reader)?;
    pem_file.with_context(|| "pem file is none")
}
