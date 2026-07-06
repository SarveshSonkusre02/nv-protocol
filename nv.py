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
        
    else:
        print_usage()
        sys.exit(1)

if __name__ == "__main__":
    main()
