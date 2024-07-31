use anyhow::Error;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub fn generate_certificates(certs_path: &PathBuf, rest_host: &str) -> Result<(), Error> {
    /* Generate the CA certificate */
    let mut ca_params = CertificateParams::new(vec![
        "cln Root REST CA".to_string(),
        "cln".to_string(),
        "localhost".to_string(),
    ])?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    fs::create_dir_all(certs_path)?;

    fs::write(certs_path.join("ca.pem"), ca_cert.pem())?;
    fs::write(
        certs_path.join("ca-key.pem"),
        ca_key.serialize_pem().as_bytes(),
    )?;

    /* Generate the server certificate signed by the CA */
    let mut server_params = CertificateParams::new(vec![
        format!("cln rest server"),
        "cln".to_string(),
        "localhost".to_string(),
    ])?;
    server_params.is_ca = rcgen::IsCa::NoCa;
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "cln rest server");
    if let Ok(ip) = rest_host.parse::<IpAddr>() {
        server_params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(ip));
    }
    let server_key = KeyPair::generate()?;
    let server_pem = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)?
        .pem();

    fs::write(certs_path.join("server.pem"), server_pem)?;
    fs::write(
        certs_path.join("server-key.pem"),
        server_key.serialize_pem().as_bytes(),
    )?;

    /* Generate the client certificate signed by the CA */
    let mut client_params = CertificateParams::new(vec![
        format!("cln rest client"),
        "cln".to_string(),
        "localhost".to_string(),
    ])?;
    client_params.is_ca = rcgen::IsCa::NoCa;
    client_params.distinguished_name = DistinguishedName::new();
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "cln rest client");
    let client_key = KeyPair::generate()?;
    let client_pem = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)?
        .pem();

    fs::write(certs_path.join("client.pem"), client_pem)?;
    fs::write(
        certs_path.join("client-key.pem"),
        client_key.serialize_pem().as_bytes(),
    )?;

    Ok(())
}

pub fn do_certificates_exist(cert_dir: &Path) -> bool {
    let required_files = [
        "server.pem",
        "server-key.pem",
        "client.pem",
        "client-key.pem",
        "ca.pem",
        "ca-key.pem",
    ];

    required_files.iter().all(|file| {
        let path = cert_dir.join(file);
        path.exists() && path.metadata().map(|m| m.len() > 0).unwrap_or(false)
    })
}
