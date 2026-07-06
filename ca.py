import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class CertificateAuthority:
    """Generates and manages an in-memory Root CA and signs dynamic leaf certificates."""
    def __init__(self):
        # Generate CA Private Key
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Generate self-signed CA Certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"nv Local CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"nv Protocol Security Initiative"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Local Sandbox Protection"),
        ])
        
        now = datetime.datetime.now(datetime.timezone.utc)
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

    def get_ca_cert_pem(self) -> bytes:
        """Returns the CA certificate in PEM format."""
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)

    def get_ca_key_pem(self) -> bytes:
        """Returns the CA private key in PEM format."""
        return self.ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    def generate_leaf_cert(self, domain: str) -> tuple[bytes, bytes]:
        """Generates a private key and signed certificate for a given domain, returning both as PEM bytes."""
        leaf_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        leaf_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])
        
        now = datetime.datetime.now(datetime.timezone.utc)
        
        # Build Subject Alternative Name extension
        san = x509.SubjectAlternativeName([
            x509.DNSName(domain),
            x509.DNSName(f"*.{domain}")
        ])
        
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(san, critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        
        cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
        key_pem = leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return cert_pem, key_pem
