import datetime
import os
import subprocess
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class CertificateAuthority:
    """Generates, manages, and persists a Root CA, and signs compliant dynamic leaf certificates."""
    def __init__(self, ca_dir=None):
        if ca_dir is None:
            home_dir = os.path.expanduser("~")
            ca_dir = os.path.join(home_dir, ".nv")
        
        self.ca_dir = ca_dir
        os.makedirs(ca_dir, exist_ok=True)
        
        self.key_path = os.path.join(ca_dir, "ca.key")
        self.cert_path = os.path.join(ca_dir, "ca.crt")
        
        if os.path.exists(self.key_path) and os.path.exists(self.cert_path):
            try:
                # Load existing persistent Root CA
                with open(self.key_path, "rb") as f:
                    self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
                with open(self.cert_path, "rb") as f:
                    self.ca_cert = x509.load_pem_x509_certificate(f.read())
                return
            except Exception as e:
                # Fallback to regeneration if files are corrupt or unreadable
                print(f"Warning: Corrupt or unreadable CA files found, regenerating: {e}", file=sys.stderr)
                
        # Generate a new persistent Root CA
        self._generate_new_ca()
        self._save_ca()
        self._install_ca_trust()

    def _generate_new_ca(self):
        # Generate Root CA Private Key
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Generate self-signed Root CA Certificate (10 years validity)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"nv Local CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"nv Protocol Security Initiative"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Local Sandbox Protection"),
        ])
        
        now = datetime.datetime.now(datetime.timezone.utc)
        public_key = self.ca_key.public_key()
        
        # Build Root CA certificate with all required modern extensions
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
                critical=False
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    key_encipherment=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .sign(self.ca_key, hashes.SHA256())
        )

    def _save_ca(self):
        # Save private key securely
        key_pem = self.get_ca_key_pem()
        if sys.platform == "win32":
            with open(self.key_path, "wb") as f:
                f.write(key_pem)
        else:
            # Write with owner-only (0600) permission ring on UNIX
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(key_pem)
                
        # Save CA certificate
        with open(self.cert_path, "wb") as f:
            f.write(self.get_ca_cert_pem())

    def _install_ca_trust(self):
        """Attempts to register the Root CA cert in the user's OS trust store (user space, no sudo required)."""
        try:
            if sys.platform == "win32":
                # Add to User Root store (doesn't require admin privileges)
                subprocess.run(
                    ["certutil", "-user", "-addstore", "-f", "Root", self.cert_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            elif sys.platform == "darwin":
                # Add to login keychain (doesn't require admin privileges, standard user confirmation prompt may appear)
                login_keychain = os.path.expanduser("~/Library/Keychains/login.keychain-db")
                if not os.path.exists(login_keychain):
                    login_keychain = os.path.expanduser("~/Library/Keychains/login.keychain")
                subprocess.run(
                    ["security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", login_keychain, self.cert_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            else:
                # Linux generally requires sudo (update-ca-certificates), so we skip automatic install
                # and rely on the CA bundle environment injections implemented in runner.py
                pass
        except Exception:
            pass

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
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"nv Local Sandbox"),
        ])
        
        now = datetime.datetime.now(datetime.timezone.utc)
        
        # Build Subject Alternative Name extension
        san = x509.SubjectAlternativeName([
            x509.DNSName(domain),
            x509.DNSName(f"*.{domain}")
        ])
        
        public_key = leaf_key.public_key()
        
        # Build leaf certificate with complete X.509 extensions for modern TLS client compliance
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(san, critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_cert.public_key()),
                critical=False
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False
            )
            .sign(self.ca_key, hashes.SHA256())
        )
        
        cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
        key_pem = leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return cert_pem, key_pem
