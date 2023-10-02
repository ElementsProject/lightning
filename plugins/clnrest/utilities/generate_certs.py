import os
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import datetime
from utilities.shared import validate_ip4


def save_cert(entity_type, cert, private_key, certs_path):
    """Serialize and save certificates and keys.
    `entity_type` is either "ca", "client" or "server"."""
    with open(os.path.join(certs_path, f"{entity_type}.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(certs_path, f"{entity_type}-key.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))


def create_cert_builder(subject_name, issuer_name, public_key, rest_host):
    list_sans = [x509.DNSName("cln"), x509.DNSName("localhost")]
    if validate_ip4(rest_host) is True:
        list_sans.append(x509.IPAddress(ipaddress.IPv4Address(rest_host)))

    return (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10 * 365))  # Ten years validity
        .add_extension(x509.SubjectAlternativeName(list_sans), critical=False)
    )


def generate_cert(entity_type, ca_subject, ca_private_key, rest_host, certs_path):
    # Generate Key pair
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Generate Certificates
    if isinstance(ca_subject, x509.Name):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"cln rest {entity_type}")])
        cert_builder = create_cert_builder(subject, ca_subject, public_key, rest_host)
        cert = cert_builder.sign(ca_private_key, hashes.SHA256())
    else:
        ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"cln Root REST CA")])
        ca_private_key, ca_public_key = private_key, public_key
        cert_builder = create_cert_builder(ca_subject, ca_subject, ca_public_key, rest_host)
        cert = (
            cert_builder
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_private_key, hashes.SHA256())
        )

    os.makedirs(certs_path, exist_ok=True)
    save_cert(entity_type, cert, private_key, certs_path)
    return ca_subject, ca_private_key


def generate_certs(plugin, rest_host, certs_path):
    ca_subject, ca_private_key = generate_cert("ca", None, None, rest_host, certs_path)
    generate_cert("client", ca_subject, ca_private_key, rest_host, certs_path)
    generate_cert("server", ca_subject, ca_private_key, rest_host, certs_path)
    plugin.log(f"Certificates Generated!", "debug")
