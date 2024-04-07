//! Utilities to manage TLS certificates.
use anyhow::{Context, Result};
use log::debug;
use rcgen::{Certificate, KeyPair};
use std::path::Path;

/// Just a wrapper around a certificate and an associated keypair.
#[derive(Clone, Debug)]
pub(crate) struct Identity {
    key: Vec<u8>,
    certificate: Vec<u8>,
}

impl Identity {
    fn to_key(&self) -> Result<KeyPair> {
        let keystr = String::from_utf8_lossy(&self.key);
        let key = KeyPair::from_pem(&keystr)?;
        Ok(key)
    }

    fn to_certificate(&self) -> Result<Certificate> {
        let certstr = String::from_utf8_lossy(&self.certificate);
        let params = rcgen::CertificateParams::from_ca_cert_pem(&certstr)?;
        let cert = params.self_signed(&self.to_key()?)?;
        Ok(cert)
    }

    pub fn to_tonic_identity(&self) -> tonic::transport::Identity {
        tonic::transport::Identity::from_pem(&self.certificate, &self.key)
    }
}

/// Ensure that we have a certificate authority, and child keypairs
/// and certificates for the server and the client. It'll generate
/// them in the provided `directory`. The following files are
/// included:
///
/// - `ca.pem`: The self-signed certificate of the CA
/// - `ca-key.pem`: The key used by the CA to sign certificates
/// - `server.pem`: The server certificate, signed by the CA
/// - `server-key.pem`: The server private key
/// - `client.pem`: The client certificate, signed by the CA
/// - `client-key.pem`: The client private key
///
/// The `grpc-plugin` will use the `server.pem` certificate, while a
/// client is supposed to use the `client.pem` and associated
/// keys. Notice that this isn't strictly necessary since the server
/// will accept any client that is signed by the CA. In the future, we
/// might add runes, making the distinction more important.
///
/// Returns the server identity and the root CA certificate.
pub(crate) fn init(directory: &Path) -> Result<(Identity, Vec<u8>)> {
    let ca = generate_or_load_identity("cln Root CA", directory, "ca", None)?;
    let server = generate_or_load_identity("cln grpc Server", directory, "server", Some(&ca))?;
    let _client = generate_or_load_identity("cln grpc Client", directory, "client", Some(&ca))?;
    Ok((server, ca.certificate))
}

/// Generate a given identity
fn generate_or_load_identity(
    name: &str,
    directory: &Path,
    filename: &str,
    parent: Option<&Identity>,
) -> Result<Identity> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    // Just our naming convention here.
    let cert_path = directory.join(format!("{}.pem", filename));
    let key_path = directory.join(format!("{}-key.pem", filename));
    // Did we have to generate a new key? In that case we also need to
    // regenerate the certificate
    if !key_path.exists() || !cert_path.exists() {
        debug!(
            "Generating a new keypair in {:?}, it didn't exist",
            &key_path
        );
        let keypair = KeyPair::generate()?;

        // Create the file but make it user-readable only:
        let mut file = std::fs::File::create(&key_path)?;
        let mut perms = std::fs::metadata(&key_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&key_path, perms)?;

        // Only after changing the permissions we can write the
        // private key
        file.write_all(keypair.serialize_pem().as_bytes())?;
        drop(file);

        debug!(
            "Generating a new certificate for key {:?} at {:?}",
            &key_path, &cert_path
        );

        // Configure the certificate we want.
        let subject_alt_names = vec!["cln".to_string(), "localhost".to_string()];
        let mut params = rcgen::CertificateParams::new(subject_alt_names)?;
        params.is_ca = if parent.is_none() {
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        } else {
            rcgen::IsCa::NoCa
        };
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);

        let cert = match parent {
            None => params.self_signed(&keypair),
            Some(parent) => {
                params.signed_by(&keypair, &parent.to_certificate()?, &parent.to_key()?)
            }
        }?;
        std::fs::write(&cert_path, cert.pem().as_bytes()).context("writing certificate to file")?;
    }

    let key = std::fs::read(&key_path)?;
    let certificate = std::fs::read(cert_path)?;
    Ok(Identity { certificate, key })
}
