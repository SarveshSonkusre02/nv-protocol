import os
import sys
import subprocess

def main():
    # Locates the bin_redirect.js file relative to the installed package
    current_dir = os.path.dirname(os.path.abspath(__file__))
    js_path = os.path.abspath(os.path.join(current_dir, "..", "bin_redirect.js"))
    
    if not os.path.exists(js_path):
        # Fallback if installed differently
        js_path = "bin_redirect.js"

    try:
        # Executes node bin_redirect.js passing down all CLI arguments
        result = subprocess.run(["node", js_path] + sys.argv[1:])
        sys.exit(result.returncode)
    except FileNotFoundError:
        print("Error: Node.js is required to run nv-protocol. Please install Node.js.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()