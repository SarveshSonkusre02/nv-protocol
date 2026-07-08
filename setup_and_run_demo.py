import os
import sys
import subprocess

# Add py_wrapper to path to access vault
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(current_dir, "py_wrapper"))

from vault import Vault

print("Initializing Vault database with test secrets...")
vault = Vault()
vault.set("DATABASE_URL", "postgresql://postgres:my-super-secret-db-password@localhost:5432")
vault.set("SSH_PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0y6...\n-----END RSA PRIVATE KEY-----")
vault.set("STRIPE_LIVE_KEY", "sk_live_stripe_512345abcdef")
vault.set("MONGO_PASSWORD", "mongo-auth-pass-999")
vault.set("JWT_SIGNING_KEY", "jwt-secret-signing-passphrase")
print("Vault successfully populated with test credentials.")

# Inject virtual placeholders into the active environment variables
os.environ["DATABASE_URL"] = "nv://DATABASE_URL"

print("\nLaunching demo application through nvenv virtualization runner...\n")
# Execute nvenv run command wrapper
cli_path = os.path.join(current_dir, "nv.py")
subprocess.run([sys.executable, cli_path, "run", "--", sys.executable, "run_demo.py"])
