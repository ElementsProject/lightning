use anyhow::{anyhow, Error};
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DistinguishedName, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::options::WssproxyOptions;

pub fn generate_certificates(certs_path: &PathBuf, wss_host: &[String]) -> Result<(), Error> {
    /* Generate the CA certificate */
    let mut ca_params = CertificateParams::new(vec![
        "cln Root wss-proxy CA".to_string(),
        "cln".to_string(),
        "localhost".to_string(),
    ])?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    ca_params.use_authority_key_identifier_extension = true;
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca = Issuer::from_params(&ca_params, &ca_key);

    fs::create_dir_all(certs_path)?;

    fs::write(certs_path.join("ca.pem"), ca_cert.pem())?;
    fs::write(
        certs_path.join("ca-key.pem"),
        ca_key.serialize_pem().as_bytes(),
    )?;

    /* Generate the server certificate signed by the CA */
    let mut server_params = CertificateParams::new(vec![
        format!("cln wss-proxy server"),
        "cln".to_string(),
        "localhost".to_string(),
    ])?;
    server_params.is_ca = rcgen::IsCa::NoCa;
    server_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    server_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyEncipherment);
    server_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyAgreement);
    server_params.use_authority_key_identifier_extension = true;
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "cln wss-proxy server");

    /* It is convention to not include [] for ipv6 addresses in certificate SAN's */
    for host in wss_host.iter() {
        let host_stripped = if host.starts_with('[') && host.ends_with(']') {
            host[1..host.len() - 1].to_string()
        } else {
            host.to_owned()
        };
        if let Ok(ip) = host_stripped.parse::<IpAddr>() {
            server_params
                .subject_alt_names
                .push(rcgen::SanType::IpAddress(ip));
        } else if let Ok(dns) = Ia5String::try_from(host.to_owned()) {
            server_params
                .subject_alt_names
                .push(rcgen::SanType::DnsName(dns));
        }
    }

    let server_key = KeyPair::generate()?;
    let server_pem = server_params.signed_by(&server_key, &ca)?.pem();

    fs::write(certs_path.join("server.pem"), server_pem)?;
    fs::write(
        certs_path.join("server-key.pem"),
        server_key.serialize_pem().as_bytes(),
    )?;

    /* Generate the client certificate signed by the CA */
    let mut client_params = CertificateParams::new(vec![
        format!("cln wss-proxy client"),
        "cln".to_string(),
        "localhost".to_string(),
    ])?;
    client_params.is_ca = rcgen::IsCa::NoCa;
    client_params.distinguished_name = DistinguishedName::new();
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "cln wss-proxy client");
    let client_key = KeyPair::generate()?;
    let client_pem = client_params.signed_by(&client_key, &ca)?.pem();

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

pub async fn get_tls_config(wss_proxy_options: &WssproxyOptions) -> Result<ServerConfig, Error> {
    let max_retries = 20;
    let mut retries = 0;
    while retries < max_retries && !do_certificates_exist(&wss_proxy_options.certs_dir) {
        log::debug!("Certificates incomplete. Retrying...");
        tokio::time::sleep(Duration::from_millis(500)).await;
        retries += 1;
    }

    if !do_certificates_exist(&wss_proxy_options.certs_dir) {
        log::debug!("Certificates still not existing after retries. Generating...");
        generate_certificates(&wss_proxy_options.certs_dir, &wss_proxy_options.wss_domains)?;
    }

    let certs = CertificateDer::pem_file_iter(wss_proxy_options.certs_dir.join("server.pem"))
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();
    let private_key =
        PrivateKeyDer::from_pem_file(wss_proxy_options.certs_dir.join("server-key.pem")).unwrap();

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(|e| anyhow!("{}", e))
}
