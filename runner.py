import os
import sys
import subprocess
import tempfile
from vault import Vault
from ca import CertificateAuthority
from proxy import NoViewEnvProxy

def run_command(args, db_path=None):
    """Starts the proxy, populates secret cache, injects proxy/CA environment, and runs target command."""
    if not args:
        print("Error: No command specified to run.", file=sys.stderr)
        return 1

    # 1. Initialize vault and load secrets to cache
    vault = Vault(db_path)
    keys = vault.list_keys()
    vault_cache = {}
    for k in keys:
        val = vault.get(k)
        if val is not None:
            vault_cache[k] = val

    # 2. Instantiate CA and Proxy
    ca = CertificateAuthority()
    proxy = NoViewEnvProxy(vault_cache, ca)
    
    proxy_port = proxy.start()
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    
    # 3. Write CA certificate to a temporary file
    # We use delete=False because other processes will need to open it by path.
    temp_ca = tempfile.NamedTemporaryFile(delete=False, suffix=".crt", mode='wb')
    temp_ca.write(ca.get_ca_cert_pem())
    temp_ca.close()
    ca_path = os.path.abspath(temp_ca.name)
    
    # 4. Prepare Child Process Environment Variables
    env = os.environ.copy()
    
    # Proxy redirection
    env["HTTP_PROXY"] = proxy_url
    env["HTTPS_PROXY"] = proxy_url
    
    # SSL trust injection for various runtimes
    env["NODE_EXTRA_CA_CERTS"] = ca_path
    env["REQUESTS_CA_BUNDLE"] = ca_path
    env["SSL_CERT_FILE"] = ca_path
    env["CURL_CA_BUNDLE"] = ca_path
    env["AWS_CA_BUNDLE"] = ca_path
    
    # Also override uppercase versions to be thorough
    env["http_proxy"] = proxy_url
    env["https_proxy"] = proxy_url

    # 5. Spawn Child Process
    # Under Windows, if args is a list, subprocess.Popen automatically quotes elements correctly
    # Support running through shell if necessary, but direct execution is cleaner.
    # We do a direct execution by default.
    p = None
    try:
        p = subprocess.Popen(args, env=env)
        p.wait()
        return p.returncode
    except KeyboardInterrupt:
        if p:
            p.terminate()
            p.wait()
        return 130
    except Exception as e:
        print(f"Error executing command: {e}", file=sys.stderr)
        return 1
    finally:
        # 6. Shutdown Proxy & Cleanup CA File
        proxy.stop()
        try:
            if os.path.exists(ca_path):
                os.remove(ca_path)
        except Exception:
            pass
