import sys
import os
import shutil
import subprocess

def main():
    print("Initializing PyInstaller compilation process...")
    
    # 1. Detect platform and setup target folder
    platform = sys.platform
    target_dir = os.path.join("bin", platform)
    os.makedirs(target_dir, exist_ok=True)
    
    # Clean up root-level packaging stubs if they conflict with py_wrapper imports
    conflicting_stubs = ["ca.py", "git.py", "policy.py", "proxy.py", "runner.py", "vault.py"]
    for stub in conflicting_stubs:
        if os.path.exists(stub):
            try:
                with open(stub, 'r') as f:
                    content = f.read()
                if "Relocated to py_wrapper" in content:
                    os.remove(stub)
                    print(f"Removed conflicting root-level stub: {stub}")
            except Exception as e:
                print(f"Warning: Could not check/remove stub {stub}: {e}")
    
    # 2. Assert/Install PyInstaller dependencies
    try:
        import PyInstaller.__main__
    except ImportError:
        print("PyInstaller is not installed. Attempting installation...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
            import PyInstaller.__main__
        except Exception as e:
            print(f"Failed to install PyInstaller: {e}", file=sys.stderr)
            sys.exit(1)

    # 3. Execute PyInstaller execution pipeline
    # --onefile: Packages everything into a single executable binary
    # --name=nvenv: Set binary name to 'nvenv' (or 'nvenv.exe')
    # --clean: Cleans PyInstaller cache before building
    print("Compiling code structure into zero-dependency native binary...")
    try:
        PyInstaller.__main__.run([
            os.path.join('py_wrapper', 'nv.py'),
            '--onefile',
            '--name=nvenv',
            '--clean',
            '--paths=py_wrapper',
        ])
    except Exception as e:
        print(f"Compilation pipeline failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    # 4. Locate and move the output binary
    binary_name = "nvenv.exe" if platform == "win32" else "nvenv"
    source_path = os.path.join("dist", binary_name)
    target_path = os.path.join(target_dir, binary_name)
    
    if os.path.exists(source_path):
        # Move output to destination
        print(f"Binary generated successfully. Relocating to: {target_path}")
        if os.path.exists(target_path):
            os.remove(target_path)
        shutil.move(source_path, target_path)
        
        # 5. Clean up temporary build artifacts
        print("Cleaning up temporary compilation artifacts...")
        for folder in ["build", "dist"]:
            if os.path.exists(folder):
                shutil.rmtree(folder)
        spec_file = "nvenv.spec"
        if os.path.exists(spec_file):
            os.remove(spec_file)
            
        print(f"\nCompilation Complete! Standalone executable ready at: {target_path}")
    else:
        print("Compilation failed: Output executable could not be found.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
