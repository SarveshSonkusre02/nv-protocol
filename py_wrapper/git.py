import sys
from vault import Vault

def run_git_helper(args):
    """Git credential helper protocol implementation."""
    if not args or args[0] != "get":
        # We only handle credential retrieval ('get')
        # 'store' and 'erase' are ignored because credentials are set via the nv CLI
        return 0
        
    try:
        # Git sends request lines on standard input, e.g.:
        # protocol=https
        # host=github.com
        lines = sys.stdin.read().splitlines()
        params = {}
        for line in lines:
            if '=' in line:
                k, v = line.split('=', 1)
                params[k.strip()] = v.strip()
                
        host = params.get('host')
        if not host:
            return 0
            
        vault = Vault()
        
        # Search patterns for keys in vault:
        # 1. Custom normalized host key: GIT_CREDENTIAL_github_com
        normalized_host = host.lower().replace('.', '_').replace('-', '_')
        key_candidates = [f"GIT_CREDENTIAL_{normalized_host}"]
        
        # 2. Shorthands for popular services
        if "github.com" in host.lower():
            key_candidates.append("GITHUB_TOKEN")
            key_candidates.append("GITHUB_PAT")
        elif "gitlab.com" in host.lower():
            key_candidates.append("GITLAB_TOKEN")
            
        token = None
        for k in key_candidates:
            token = vault.get(k)
            if token:
                break
                
        if token:
            # Output credentials back to Git stdout
            username = params.get('username', 'oauth2')
            sys.stdout.write(f"username={username}\n")
            sys.stdout.write(f"password={token}\n")
            sys.stdout.flush()
            
    except Exception as e:
        # Failure should fail silently so standard git authentication fallback can run
        pass
        
    return 0
