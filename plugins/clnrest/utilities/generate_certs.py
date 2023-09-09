import os
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import datetime


def generate_ca_cert(certs_path):
    # Generate CA Private Key
    ca_private_key = ec.generate_private_key(ec.SECP256R1())

    # Generate CA Public Key
    ca_public_key = ca_private_key.public_key()

    # Generate CA Certificate
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"cln Root REST CA")])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10 * 365))  # Ten years validity
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"cln"), x509.DNSName(u'localhost'), x509.IPAddress(ipaddress.IPv4Address(u'127.0.0.1'))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )

    # Create the certs directory if it does not exist
    os.makedirs(certs_path, exist_ok=True)

    # Serialize CA certificate and write to disk
    with open(os.path.join(certs_path, "ca.pem"), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    # Serialize and save the private key to a PEM file (CA)
    with open(os.path.join(certs_path, "ca-key.pem"), "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return ca_subject, ca_private_key


def generate_client_server_certs(certs_path, ca_subject, ca_private_key):
    # Generate Server and Client Private Keys
    server_private_key = ec.generate_private_key(ec.SECP256R1())
    client_private_key = ec.generate_private_key(ec.SECP256R1())

    # Generate Server and Client Public Keys
    server_public_key = server_private_key.public_key()
    client_public_key = client_private_key.public_key()

    # Generate Server and Client Certificates
    for entity_type in ["server", "client"]:
        public_key = server_public_key if entity_type == "server" else client_public_key

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"cln rest {entity_type}")])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10 * 365))  # Ten years validity
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"cln"), x509.DNSName(u'localhost'), x509.IPAddress(ipaddress.IPv4Address(u'127.0.0.1'))]), critical=False)
            .sign(ca_private_key, hashes.SHA256())
        )

        # Serialize Server and Client certificates and write to disk
        with open(os.path.join(certs_path, f"{entity_type}.pem"), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Serialize Private Keys (Server)
    with open(os.path.join(certs_path, "server-key.pem"), "wb") as f:
        f.write(server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Serialize Private Keys (Client)
    with open(os.path.join(certs_path, "client-key.pem"), "wb") as f:
        f.write(client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))


def generate_certs(plugin, certs_path):
    ca_subject, ca_private_key = generate_ca_cert(certs_path)
    generate_client_server_certs(certs_path, ca_subject, ca_private_key)
    plugin.log(f"Certificates Generated!", "debug")
