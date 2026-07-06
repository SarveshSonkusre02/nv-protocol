import os

def main():
    # Target files that must use UNIX line endings (LF) for binary execution
    files = ["bin_redirect.js", "install.sh"]
    for file_name in files:
        if os.path.exists(file_name):
            with open(file_name, 'rb') as f:
                content = f.read()
            
            # Replace CRLF (\r\n) with LF (\n)
            fixed_content = content.replace(b'\r\n', b'\n')
            
            with open(file_name, 'wb') as f:
                f.write(fixed_content)
            print(f"Converted {file_name} to LF line endings successfully.")

if __name__ == "__main__":
    main()
