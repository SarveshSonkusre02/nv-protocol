import os
import sys
import subprocess

def main():
    # 1. Find exactly where this cli.py file lives inside site-packages
    current_dir = os.path.dirname(os.path.abspath(__file__))
    js_path = os.path.join(current_dir, "bin_redirect.js")
    if not os.path.exists(js_path):
        js_path = os.path.join(current_dir, "bin_redirect.js")

    try:
        # 3. Pass the absolute calculated path down to Node execution layer
        result = subprocess.run(["node", js_path] + sys.argv[1:])
        sys.exit(result.returncode)
    except FileNotFoundError:
        print("Error: Node.js is required to run nv-protocol. Please install Node.js.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()