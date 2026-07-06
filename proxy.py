import socket
import threading
import ssl
import os
import re
import traceback
from ca import CertificateAuthority

def replace_placeholders(data: bytes, cache: dict) -> bytes:
    """Finds all nv://PLACEHOLDER patterns in bytes and replaces them with vault secrets."""
    def repl(match):
        key = match.group(1).decode('utf-8', errors='ignore')
        val = cache.get(key)
        if val is not None:
            return val.encode('utf-8')
        return match.group(0)
    
    return re.sub(b'nv://([A-Za-z0-9_]+)', repl, data)


class NoViewEnvProxy:
    """MITM TLS Interception Proxy Server."""
    def __init__(self, vault_cache: dict, ca: CertificateAuthority):
        self.vault_cache = vault_cache
        self.ca = ca
        self.server_socket = None
        self.port = None
        self.running = False
        self.threads = []
        
        # Setup cert cache dir
        home_dir = os.path.expanduser("~")
        self.cert_dir = os.path.join(home_dir, ".nv", "certs")
        os.makedirs(self.cert_dir, exist_ok=True)

    def start(self):
        """Starts the proxy on a random available port on 127.0.0.1."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('127.0.0.1', 0))
        self.port = self.server_socket.getsockname()[1]
        self.server_socket.listen(100)
        self.running = True
        
        # Run acceptor loop in background thread
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self.threads.append(t)
        return self.port

    def stop(self):
        """Stops the proxy and closes all sockets."""
        self.running = False
        if self.server_socket:
            try:
                # Force close listener socket
                self.server_socket.close()
            except:
                pass
        
        # Clean up temporary certificate files
        if os.path.exists(self.cert_dir):
            for file in os.listdir(self.cert_dir):
                try:
                    os.remove(os.path.join(self.cert_dir, file))
                except:
                    pass

    def _accept_loop(self):
        while self.running:
            try:
                client_conn, addr = self.server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(client_conn,), daemon=True)
                t.start()
            except Exception:
                if not self.running:
                    break

    def _handle_client(self, client_conn):
        try:
            # Read request line and headers
            header_data = b""
            while b"\r\n\r\n" not in header_data:
                chunk = client_conn.recv(4096)
                if not chunk:
                    break
                header_data += chunk
            
            if not header_data:
                client_conn.close()
                return
                
            parts = header_data.split(b"\r\n\r\n", 1)
            headers_chunk = parts[0]
            body_chunk = parts[1] if len(parts) > 1 else b""
            
            # Parse target host and method
            req_lines = headers_chunk.split(b"\r\n")
            req_line = req_lines[0].decode('utf-8', errors='ignore')
            words = req_line.split()
            if len(words) < 2:
                client_conn.close()
                return
                
            method, url = words[0], words[1]
            
            if method == "CONNECT":
                # HTTPS Tunnel request
                self._handle_https(client_conn, url)
            else:
                # HTTP Direct request
                self._handle_http(client_conn, url, headers_chunk, body_chunk)
                
        except Exception as e:
            pass
        finally:
            try:
                client_conn.close()
            except:
                pass

    def _get_or_create_cert(self, domain: str) -> tuple[str, str]:
        """Gets cert/key file path for a domain, creating it if not cached."""
        cert_file = os.path.join(self.cert_dir, f"{domain}.crt")
        key_file = os.path.join(self.cert_dir, f"{domain}.key")
        
        if os.path.exists(cert_file) and os.path.exists(key_file):
            return cert_file, key_file
            
        cert_pem, key_pem = self.ca.generate_leaf_cert(domain)
        
        with open(cert_file, 'wb') as f:
            f.write(cert_pem)
        with open(key_file, 'wb') as f:
            f.write(key_pem)
            
        return cert_file, key_file

    def _handle_https(self, client_conn, target_host_port):
        # target_host_port is like "api.stripe.com:443" or "github.com:443"
        host, port_str = target_host_port.split(":", 1) if ":" in target_host_port else (target_host_port, "443")
        port = int(port_str)
        
        # Respond 200 Connection Established to client
        client_conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        
        # Get/generate leaf certificate for this host
        cert_file, key_file = self._get_or_create_cert(host)
        
        # Wrap client socket in SSL
        client_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        
        client_ssl = None
        remote_ssl = None
        try:
            client_ssl = client_ssl_context.wrap_socket(client_conn, server_side=True)
            
            # Connect to remote target
            remote_conn = socket.create_connection((host, port), timeout=10)
            remote_ssl_context = ssl.create_default_context()
            remote_ssl = remote_ssl_context.wrap_socket(remote_conn, server_hostname=host)
            
            # Start full TLS proxying tunnels
            self._tunnel_traffic(client_ssl, remote_ssl)
        except Exception as e:
            pass
        finally:
            for s in [client_ssl, remote_ssl]:
                if s:
                    try:
                        s.close()
                    except:
                        pass

    def _handle_http(self, client_conn, url, headers_chunk, body_chunk):
        # HTTP is simpler, parse Host from headers
        host = None
        port = 80
        
        req_lines = headers_chunk.split(b"\r\n")
        for line in req_lines[1:]:
            if line.lower().startswith(b"host:"):
                host_val = line.split(b":", 1)[1].strip().decode('utf-8', errors='ignore')
                if ":" in host_val:
                    host, port_str = host_val.split(":", 1)
                    port = int(port_str)
                else:
                    host = host_val
                break
                
        if not host:
            return
            
        try:
            remote_conn = socket.create_connection((host, port), timeout=10)
            
            # Reconstruct request and replace placeholders
            full_request = headers_chunk + b"\r\n\r\n" + body_chunk
            modified_request = replace_placeholders(full_request, self.vault_cache)
            
            remote_conn.sendall(modified_request)
            
            # Pipe response back
            while True:
                chunk = remote_conn.recv(4096)
                if not chunk:
                    break
                client_conn.sendall(chunk)
        except Exception:
            pass
        finally:
            try:
                remote_conn.close()
            except:
                pass

    def _tunnel_traffic(self, client_ssl, remote_ssl):
        """Intercepts client HTTPS requests, swaps placeholders, and returns server responses."""
        # We process client requests in a loop to handle persistent HTTP Keep-Alive connections
        client_ssl.settimeout(15.0)
        remote_ssl.settimeout(15.0)
        
        try:
            while True:
                # 1. Read request headers from client
                req_data = b""
                while b"\r\n\r\n" not in req_data:
                    chunk = client_ssl.recv(4096)
                    if not chunk:
                        return
                    req_data += chunk
                    
                header_part, body_part = req_data.split(b"\r\n\r\n", 1)
                
                # 2. Check for Content-Length or Chunked Transfer
                content_length = 0
                is_chunked = False
                for line in header_part.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        content_length = int(line.split(b":", 1)[1].strip())
                    elif line.lower().startswith(b"transfer-encoding:") and b"chunked" in line.lower():
                        is_chunked = True
                
                # 3. Read request body
                if is_chunked:
                    # Request body is chunked
                    body_part = self._read_chunked_body(client_ssl, body_part)
                elif content_length > 0:
                    while len(body_part) < content_length:
                        chunk = client_ssl.recv(4096)
                        if not chunk:
                            return
                        body_part += chunk
                
                # 4. Perform dynamic secret substitution
                full_request = header_part + b"\r\n\r\n" + body_part
                modified_request = replace_placeholders(full_request, self.vault_cache)
                
                # 5. Forward request to remote API
                remote_ssl.sendall(modified_request)
                
                # 6. Read response headers from remote API
                resp_data = b""
                while b"\r\n\r\n" not in resp_data:
                    chunk = remote_ssl.recv(4096)
                    if not chunk:
                        return
                    resp_data += chunk
                    
                resp_header, resp_body = resp_data.split(b"\r\n\r\n", 1)
                
                # Send headers and first body chunk to client
                client_ssl.sendall(resp_data)
                
                # Check response content packaging
                resp_content_length = -1
                resp_chunked = False
                for line in resp_header.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        resp_content_length = int(line.split(b":", 1)[1].strip())
                    elif line.lower().startswith(b"transfer-encoding:") and b"chunked" in line.lower():
                        resp_chunked = True
                
                # 7. Read and forward response body
                if resp_chunked:
                    self._pipe_chunked_data(remote_ssl, client_ssl, resp_body)
                elif resp_content_length >= 0:
                    remaining = resp_content_length - len(resp_body)
                    while remaining > 0:
                        chunk = remote_ssl.recv(min(4096, remaining))
                        if not chunk:
                            break
                        client_ssl.sendall(chunk)
                        remaining -= len(chunk)
                else:
                    # Connection close response
                    self._pipe_until_close(remote_ssl, client_ssl)
                    break
        except (socket.timeout, socket.error):
            pass

    def _read_chunked_body(self, sock, initial_buffer) -> bytes:
        body = initial_buffer
        while b"0\r\n\r\n" not in body:
            chunk = sock.recv(4096)
            if not chunk:
                break
            body += chunk
        return body

    def _pipe_chunked_data(self, src, dest, initial_buffer):
        buffer = initial_buffer
        while True:
            if b"0\r\n\r\n" in buffer or buffer.endswith(b"0\r\n\r\n"):
                break
            chunk = src.recv(4096)
            if not chunk:
                break
            dest.sendall(chunk)
            buffer = chunk

    def _pipe_until_close(self, src, dest):
        src.settimeout(2.0)
        try:
            while True:
                chunk = src.recv(4096)
                if not chunk:
                    break
                dest.sendall(chunk)
        except socket.timeout:
            pass
