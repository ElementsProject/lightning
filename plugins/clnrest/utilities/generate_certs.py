import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
import datetime


def generate_certs(plugin, certs_path):
    # Generate key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Create the certs directory if it does not exist
    os.makedirs(certs_path, exist_ok=True)
    # Write key
    with open(os.path.join(certs_path, "client-key.pem"), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Core Lightning")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10 * 365))  # Ten years validity
        .sign(key, hashes.SHA256())
    )
    with open(os.path.join(certs_path, "client.pem"), "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    plugin.log(f"Certificate Generated!", "debug")
