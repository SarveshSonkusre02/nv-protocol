import sys
import getpass
from vault import Vault
from runner import run_command

def print_usage():
    print("""
nvenv (No-View Env) - Context-Isolated Secret Management CLI

Usage:
  nvenv init                  Initialize the secure vault database.
  nvenv set <KEY>             Encrypt and store a secret key.
  nvenv delete <KEY>          Delete a secret key from the vault.
  nvenv list                  List stored keys (hiding values).
  nvenv get <KEY>             Retrieve/Decrypt a secret key (debug use).
  nvenv run -- <command>      Run a command with proxy interception.
  nvenv git-helper <action>   Internal Git credential helper proxy.
  nvenv policy <subcommand>   Manage request policies for secret keys.

Policy Subcommands:
  nvenv policy list           List all configured policies.
  nvenv policy set-default <action>
                              Set default fallback action (allow, warn, deny).
  nvenv policy add <KEY>      Add or modify a policy for a key.
                              Options: --hosts, --processes, --methods, --paths, --limit
  nvenv policy delete <KEY>   Delete policy configuration for a key.
""")

def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
        
    cmd = sys.argv[1]
    
    if cmd == "init":
        try:
            Vault()
            print("Vault initialized successfully at ~/.nv/vault.db")
        except Exception as e:
            print(f"Error initializing vault: {e}", file=sys.stderr)
            sys.exit(1)
            
    elif cmd == "set":
        if len(sys.argv) < 3:
            print("Usage: python nv.py set <KEY>")
            sys.exit(1)
        key = sys.argv[2]
        val = getpass.getpass(prompt=f"Enter value for '{key}': ")
        if not val:
            print("Error: Value cannot be empty.")
            sys.exit(1)
        try:
            vault = Vault()
            vault.set(key, val)
            print(f"Secret '{key}' stored successfully in Windows DPAPI vault.")
            print(f"\n[ENV INTERFACE] Copy and paste this line into your .env file:")
            print(f"{key}=nv://{key}\n")
        except Exception as e:
            print(f"Error storing secret: {e}", file=sys.stderr)
            sys.exit(1)
            
    elif cmd == "list":
        try:
            vault = Vault()
            keys = vault.list_keys()
            if not keys:
                print("Vault is empty.")
            else:
                print("Stored secrets:")
                for k in keys:
                    print(f"  - {k}")
        except Exception as e:
            print(f"Error listing secrets: {e}", file=sys.stderr)
            sys.exit(1)
            
    elif cmd == "delete":
        if len(sys.argv) < 3:
            print("Usage: python nv.py delete <KEY>")
            sys.exit(1)
        key = sys.argv[2]
        try:
            vault = Vault()
            if vault.delete(key):
                print(f"Secret '{key}' deleted successfully.")
            else:
                print(f"Secret '{key}' not found in vault.")
        except Exception as e:
            print(f"Error deleting secret: {e}", file=sys.stderr)
            sys.exit(1)
            
    elif cmd == "get":
        if len(sys.argv) < 3:
            print("Usage: nvenv get <KEY>")
            sys.exit(1)
        key = sys.argv[2]
        
        # Security Gate: Require human presence verification
        # 1. Check if input/output streams are redirected or piped
        if not sys.stdout.isatty() or not sys.stdin.isatty():
            print("Security Error: Secret decryption blocked in non-interactive or redirected terminals to prevent AI telemetry leaks.", file=sys.stderr)
            sys.exit(1)
            
        # 2. Require interactive keyboard confirmation (bypassing standard stdin streams)
        print(f"WARNING: Requesting plaintext decryption for secret '{key}'.")
        sys.stdout.write("Are you a human developer? Press 'Y' to print the secret, or any other key to abort: ")
        sys.stdout.flush()
        
        try:
            if sys.platform == "win32":
                import msvcrt
                char = msvcrt.getch()
                confirmed = char.lower() in (b'y', 'y'.encode('utf-8'))
            else:
                import tty
                import termios
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                try:
                    tty.setraw(fd)
                    char = sys.stdin.read(1)
                    confirmed = char.lower() == 'y'
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            print() # Print newline
        except Exception:
            # Strict fallback: if keyboard buffer manipulation fails, abort
            print("\nError: Could not verify interactive session. Aborting.", file=sys.stderr)
            sys.exit(1)
            
        if not confirmed:
            print("Decryption aborted by user.")
            sys.exit(1)
            
        try:
            vault = Vault()
            val = vault.get(key)
            if val is None:
                print(f"Secret '{key}' not found in vault.")
                sys.exit(1)
            print(val)
        except Exception as e:
            print(f"Error getting secret: {e}", file=sys.stderr)
            sys.exit(1)
            
    elif cmd == "run":
        run_args = []
        start_idx = 2
        if len(sys.argv) > 2 and sys.argv[2] == "--":
            start_idx = 3
        run_args = sys.argv[start_idx:]
        
        if not run_args:
            print("Usage: python nv.py run -- <command>")
            sys.exit(1)
            
        sys.exit(run_command(run_args))
        
    elif cmd == "git-helper":
        from git import run_git_helper
        sys.exit(run_git_helper(sys.argv[2:]))
        
    elif cmd == "policy":
        if len(sys.argv) < 3:
            print("Usage:")
            print("  nvenv policy list")
            print("  nvenv policy set-default <allow|warn|deny>")
            print("  nvenv policy add <KEY> [--hosts H1,H2] [--processes P1,P2] [--methods M1,M2] [--paths T1,T2] [--limit N]")
            print("  nvenv policy delete <KEY>")
            sys.exit(1)
            
        from policy import PolicyEngine
        engine = PolicyEngine()
        subcmd = sys.argv[2]
        
        if subcmd == "list":
            print(f"Default Action: {engine.config.get('default_action', 'warn')}")
            policies = engine.config.get("policies", {})
            if not policies:
                print("No policies configured.")
            else:
                print("\nConfigured Policies:")
                for k, p in policies.items():
                    print(f"  Secret: {k}")
                    if p.get("allowed_hosts"):
                        print(f"    Allowed Hosts: {', '.join(p['allowed_hosts'])}")
                    if p.get("allowed_processes"):
                        print(f"    Allowed Processes: {', '.join(p['allowed_processes'])}")
                    if p.get("allowed_methods"):
                        print(f"    Allowed Methods: {', '.join(p['allowed_methods'])}")
                    if p.get("allowed_paths"):
                        print(f"    Allowed Paths: {', '.join(p['allowed_paths'])}")
                    if p.get("max_requests_per_minute") is not None:
                        print(f"    Max Requests/Min: {p['max_requests_per_minute']}")
                        
        elif subcmd == "set-default":
            if len(sys.argv) < 4:
                print("Usage: nvenv policy set-default <allow|warn|deny>")
                sys.exit(1)
            action = sys.argv[3].lower()
            if action not in ["allow", "warn", "deny"]:
                print("Error: Default action must be 'allow', 'warn', or 'deny'.")
                sys.exit(1)
            engine.config["default_action"] = action
            if engine.save_config():
                print(f"Default action set to '{action}' and config saved.")
            else:
                sys.exit(1)
                
        elif subcmd == "delete":
            if len(sys.argv) < 4:
                print("Usage: nvenv policy delete <KEY>")
                sys.exit(1)
            key = sys.argv[3]
            policies = engine.config.get("policies", {})
            if key in policies:
                del policies[key]
                engine.config["policies"] = policies
                if engine.save_config():
                    print(f"Policy for secret '{key}' deleted successfully.")
                else:
                    sys.exit(1)
            else:
                print(f"No policy found for secret '{key}'.")
                
        elif subcmd == "add":
            if len(sys.argv) < 4:
                print("Usage: nvenv policy add <KEY> [--hosts H1,H2] [--processes P1,P2] [--methods M1,M2] [--paths T1,T2] [--limit N]")
                sys.exit(1)
            key = sys.argv[3]
            
            # Simple custom CLI parser
            args_list = sys.argv[4:]
            hosts = None
            processes = None
            methods = None
            paths = None
            limit = None
            
            i = 0
            while i < len(args_list):
                arg = args_list[i]
                if arg == "--hosts" and i + 1 < len(args_list):
                    hosts = [h.strip() for h in args_list[i+1].split(",")]
                    i += 2
                elif arg == "--processes" and i + 1 < len(args_list):
                    processes = [p.strip() for p in args_list[i+1].split(",")]
                    i += 2
                elif arg == "--methods" and i + 1 < len(args_list):
                    methods = [m.strip().upper() for m in args_list[i+1].split(",")]
                    i += 2
                elif arg == "--paths" and i + 1 < len(args_list):
                    paths = [p.strip() for p in args_list[i+1].split(",")]
                    i += 2
                elif arg == "--limit" and i + 1 < len(args_list):
                    try:
                        limit = int(args_list[i+1])
                    except ValueError:
                        print("Error: Limit must be an integer.")
                        sys.exit(1)
                    i += 2
                else:
                    print(f"Error: Unknown option or missing value for '{arg}'")
                    sys.exit(1)
            
            # Interactive prompt if no flags are provided
            if hosts is None and processes is None and methods is None and paths is None and limit is None:
                print(f"Interactive Policy Builder for Secret '{key}':")
                h_in = input("Enter allowed hosts (comma-separated, press enter for all): ").strip()
                if h_in:
                    hosts = [h.strip() for h in h_in.split(",")]
                p_in = input("Enter allowed processes (comma-separated, press enter for all): ").strip()
                if p_in:
                    processes = [p.strip() for p in p_in.split(",")]
                m_in = input("Enter allowed HTTP methods (comma-separated, e.g., POST, GET, press enter for all): ").strip()
                if m_in:
                    methods = [m.strip().upper() for m in m_in.split(",")]
                t_in = input("Enter allowed HTTP paths (comma-separated, e.g., /v1/*, press enter for all): ").strip()
                if t_in:
                    paths = [p.strip() for p in t_in.split(",")]
                l_in = input("Enter max requests per minute (press enter for no limit): ").strip()
                if l_in:
                    try:
                        limit = int(l_in)
                    except ValueError:
                        print("Error: Limit must be an integer.")
                        sys.exit(1)
            
            policy = {}
            if hosts is not None:
                policy["allowed_hosts"] = hosts
            if processes is not None:
                policy["allowed_processes"] = processes
            if methods is not None:
                policy["allowed_methods"] = methods
            if paths is not None:
                policy["allowed_paths"] = paths
            if limit is not None:
                policy["max_requests_per_minute"] = limit
                
            policies = engine.config.setdefault("policies", {})
            policies[key] = policy
            
            if engine.save_config():
                print(f"Policy for secret '{key}' successfully saved.")
            else:
                sys.exit(1)
        else:
            print(f"Error: Unknown policy subcommand '{subcmd}'.")
            sys.exit(1)
            
    else:
        print_usage()
        sys.exit(1)

if __name__ == "__main__":
    main()
