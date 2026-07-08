import socket
import threading
import ssl
import os
import re
import sys
import subprocess
import traceback
import time

from py_wrapper.ca import CertificateAuthority
from py_wrapper.policy import PolicyEngine
from py_wrapper.nv_audit import AuditLogger
from py_wrapper.vault import Vault, wipe_bytes

# Conditional Windows Imports & Structures
if sys.platform == "win32":
    from ctypes import wintypes
    import ctypes

    class MIB_TCPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwState", wintypes.DWORD),
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwRemoteAddr", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD)
        ]

    class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwNumEntries", wintypes.DWORD),
            ("table", MIB_TCPROW_OWNER_PID * 1)
        ]
else:
    MIB_TCPROW_OWNER_PID = None
    MIB_TCPTABLE_OWNER_PID = None

# Thread-safe caching structures
_cache_lock = threading.Lock()
_pid_descendant_cache = {}    # (pid, target_parent_pid) -> (is_descendant, timestamp)
_pid_process_name_cache = {}  # pid -> (process_name, timestamp)
_pid_parent_cache = {}        # pid -> (parent_pid, timestamp)
CACHE_TTL = 10.0              # cache entries expire after 10 seconds

def get_pid_by_local_port_windows(port):
    import socket as py_socket
    iphlpapi = ctypes.windll.iphlpapi
    AF_INET = 2
    TCP_TABLE_OWNER_PID_ALL = 5
    
    size = wintypes.DWORD(0)
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    
    buf = ctypes.create_string_buffer(size.value)
    res = iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if res != 0:
        return None
        
    table_data = ctypes.cast(buf, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
    num_entries = table_data.dwNumEntries
    
    class MIB_TCPTABLE_OWNER_PID_ACTUAL(ctypes.Structure):
        _fields_ = [
            ("dwNumEntries", wintypes.DWORD),
            ("table", MIB_TCPROW_OWNER_PID * num_entries)
        ]
    
    actual_table = ctypes.cast(buf, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID_ACTUAL)).contents
    for i in range(num_entries):
        row = actual_table.table[i]
        local_port = py_socket.ntohs(row.dwLocalPort & 0xFFFF)
        if local_port == port:
            return row.dwOwningPid
    return None

def get_pid_by_local_port(port):
    if sys.platform == "win32":
        try:
            return get_pid_by_local_port_windows(port)
        except Exception:
            try:
                out = subprocess.check_output("netstat -ano", shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
                for line in out.splitlines():
                    if f"127.0.0.1:{port}" in line or f"[::1]:{port}" in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            return int(parts[-1])
            except Exception:
                pass
    else:
        try:
            out = subprocess.check_output(["lsof", "-t", f"-iTCP:{port}"], stderr=subprocess.DEVNULL)
            pids = out.decode('utf-8').strip().split()
            if pids:
                return int(pids[0])
        except Exception:
            try:
                out = subprocess.check_output(f"ss -Htp sport = :{port}", shell=True, stderr=subprocess.DEVNULL)
                match = re.search(r'pid=(\d+)', out.decode('utf-8'))
                if match:
                    return int(match.group(1))
            except Exception:
                pass
    return None

def get_process_name_by_pid(pid):
    if not pid:
        return "unknown"
    
    now = time.time()
    with _cache_lock:
        if pid in _pid_process_name_cache:
            name, ts = _pid_process_name_cache[pid]
            if now - ts < CACHE_TTL:
                return name

    name = "unknown"
    if sys.platform == "win32":
        try:
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            kernel32 = ctypes.windll.kernel32
            hProcess = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if hProcess:
                buf = ctypes.create_unicode_buffer(260)
                size = wintypes.DWORD(260)
                if kernel32.QueryFullProcessImageNameW(hProcess, 0, buf, ctypes.byref(size)):
                    name = os.path.basename(buf.value)
                    kernel32.CloseHandle(hProcess)
                else:
                    kernel32.CloseHandle(hProcess)
        except Exception:
            pass
        if name == "unknown":
            try:
                out = subprocess.check_output(f'tasklist /FI "PID eq {pid}" /NH /FO CSV', shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
                parts = out.strip().split(',')
                if len(parts) > 0:
                    name = parts[0].strip('"')
            except Exception:
                pass
    else:
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                name = f.read().strip()
        except Exception:
            try:
                out = subprocess.check_output(["ps", "-p", str(pid), "-o", "comm="], stderr=subprocess.DEVNULL)
                name = out.decode('utf-8').strip()
            except Exception:
                pass
                
    if not name:
        name = "unknown"
        
    with _cache_lock:
        _pid_process_name_cache[pid] = (name, now)
    return name

def get_parent_pid(pid):
    if not pid:
        return None
        
    now = time.time()
    with _cache_lock:
        if pid in _pid_parent_cache:
            parent, ts = _pid_parent_cache[pid]
            if now - ts < CACHE_TTL:
                return parent

    parent = None
    if sys.platform == "win32":
        try:
            TH32CS_SNAPPROCESS = 0x00000002
            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_char * 260)
                ]
            
            kernel32 = ctypes.windll.kernel32
            hSnapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if hSnapshot != -1:
                pe = PROCESSENTRY32()
                pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
                
                if kernel32.Process32First(hSnapshot, ctypes.byref(pe)):
                    while True:
                        if pe.th32ProcessID == pid:
                            parent = pe.th32ParentProcessID
                            break
                        if not kernel32.Process32Next(hSnapshot, ctypes.byref(pe)):
                            break
                kernel32.CloseHandle(hSnapshot)
        except Exception:
            pass
        if parent is None:
            try:
                out = subprocess.check_output(f'wmic process where "ProcessID={pid}" get ParentProcessID /value', shell=True, stderr=subprocess.DEVNULL).decode('utf-8')
                for line in out.splitlines():
                    if "ParentProcessID" in line:
                        parent = int(line.split("=")[1].strip())
                        break
            except Exception:
                pass
    else:
        try:
            out = subprocess.check_output(["ps", "-o", "ppid=", "-p", str(pid)], stderr=subprocess.DEVNULL)
            parent = int(out.decode('utf-8').strip())
        except Exception:
            pass
            
    with _cache_lock:
        _pid_parent_cache[pid] = (parent, now)
    return parent

def is_descendant_of(pid, target_parent_pid):
    if not pid or not target_parent_pid:
        return False
    if pid == target_parent_pid:
        return True
    
    cache_key = (pid, target_parent_pid)
    now = time.time()
    with _cache_lock:
        if cache_key in _pid_descendant_cache:
            is_desc, ts = _pid_descendant_cache[cache_key]
            if now - ts < CACHE_TTL:
                return is_desc
                
    visited = set()
    current = pid
    is_desc = False
    while current and current not in visited:
        visited.add(current)
        parent = get_parent_pid(current)
        if parent == target_parent_pid:
            is_desc = True
            break
        current = parent
        
    with _cache_lock:
        _pid_descendant_cache[cache_key] = (is_desc, now)
    return is_desc


class NoViewEnvProxy:
    """MITM TLS Interception Proxy Server."""
    def __init__(self, db_path: str, ca: CertificateAuthority, allowed_pid: int = None, proxy_token: str = None, policy_config_path=None, audit_log_path=None):
        self.db_path = db_path
        self.vault = Vault(db_path)
        self.ca = ca
        self.allowed_pid = allowed_pid
        self.proxy_token = proxy_token
        self.server_socket = None
        self.port = None
        self.running = False
        self.threads = []
        
        self.policy_engine = PolicyEngine(policy_config_path)
        self.audit_logger = AuditLogger(audit_log_path)
        
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

    def authenticate_connection(self, client_conn, headers_chunk):
        try:
            client_ip, client_port = client_conn.getpeername()
            client_pid = get_pid_by_local_port(client_port)
            client_process_name = get_process_name_by_pid(client_pid) if client_pid else "unknown"
        except Exception:
            client_pid = 0
            client_process_name = "unknown"
            
        token_header = None
        req_lines = headers_chunk.split(b"\r\n")
        for line in req_lines[1:]:
            if b":" in line:
                parts = line.split(b":", 1)
                key = parts[0].strip().lower()
                if key == b"x-nv-proxy-token" or key == b"nv-proxy-token":
                    token_header = parts[1].strip().decode('utf-8', errors='ignore')
                    break
                    
        # If neither allowed_pid nor proxy_token is set, allow (compatibility)
        if not self.allowed_pid and not self.proxy_token:
            return True, client_pid or 0, client_process_name, "Bypassed (no constraints)"
            
        if self.proxy_token and token_header == self.proxy_token:
            return True, client_pid or 0, client_process_name, "Authenticated via Token"
            
        if self.allowed_pid and client_pid:
            if is_descendant_of(client_pid, self.allowed_pid):
                return True, client_pid, client_process_name, "Authenticated via Process Tree"
                
        reason = "Forbidden: Process is not in allowed process tree and valid token is missing."
        return False, client_pid or 0, client_process_name, reason

    def _send_error_response(self, conn, err_msg):
        status_code = "429 Too Many Requests" if "rate limit" in err_msg.lower() else "403 Forbidden"
        html = f"<html><body><h1>nvenv Security Block</h1><p>{err_msg}</p></body></html>"
        resp = f"HTTP/1.1 {status_code}\r\nContent-Type: text/html\r\nContent-Length: {len(html)}\r\nConnection: close\r\n\r\n{html}".encode('utf-8')
        try:
            conn.sendall(resp)
        except Exception:
            pass

    def _replace_placeholders_lazy(self, data: bytes, target_host: str, method: str, path: str, client_pid: int, client_process_name: str) -> bytes:
        """
        Scans for nv://KEY patterns in bytes, validates access via PolicyEngine,
        decrypts keys on-the-fly, replaces them, and securely wipes the memory.
        Supports both raw and URL-encoded (nv%3A%2F%2F) placeholders.
        """
        chunks = []
        last_pos = 0
        
        # Match both raw nv:// and URL-encoded nv%3A%2F%2F (case-insensitive for hex codes)
        pattern = re.compile(b'(nv://|nv%3[Aa]%2[Ff]%2[Ff])([A-Za-z0-9_/\\-]+)')
        
        for match in pattern.finditer(data):
            chunks.append(data[last_pos:match.start()])
            
            prefix = match.group(1)
            key_bytes = match.group(2)
            key = key_bytes.decode('utf-8', errors='ignore')
            
            status, reason = self.policy_engine.validate(key, target_host, method, path, client_process_name)
            self.audit_logger.log(key, target_host, method, path, client_pid, client_process_name, status, reason)
            
            if status == "deny" or status == "rate_limited":
                raise PermissionError(f"Access to secret '{key}' blocked by policy: {reason}")
            
            if status == "warn":
                print(f"\n⚠️  [nvenv WARNING] {reason}", file=sys.stderr)
                print(f"👉 Recommend defining a policy for '{key}' in ~/.nv/config.json\n", file=sys.stderr)
            
            secret_bytes = self.vault.get_bytes(key)
            if secret_bytes is not None:
                # If the matched placeholder was URL-encoded, URL-encode the replaced secret too
                if b'%' in prefix:
                    import urllib.parse
                    secret_str = secret_bytes.decode('utf-8', errors='ignore')
                    encoded_secret = urllib.parse.quote(secret_str).encode('utf-8')
                    chunks.append(encoded_secret)
                else:
                    chunks.append(secret_bytes)
            else:
                chunks.append(match.group(0))
                
            last_pos = match.end()
            
        chunks.append(data[last_pos:])
        
        modified_data = b"".join(chunks)
        
        for chunk in chunks:
            if isinstance(chunk, bytearray):
                wipe_bytes(chunk)
                
        return modified_data

    def _handle_client(self, client_conn):
        try:
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
            
            auth_ok, client_pid, client_process_name, auth_reason = self.authenticate_connection(client_conn, headers_chunk)
            if not auth_ok:
                self._send_error_response(client_conn, auth_reason)
                client_conn.close()
                return
            
            req_lines = headers_chunk.split(b"\r\n")
            req_line = req_lines[0].decode('utf-8', errors='ignore')
            words = req_line.split()
            if len(words) < 2:
                client_conn.close()
                return
                
            method, url = words[0], words[1]
            
            if method == "CONNECT":
                self._handle_https(client_conn, url, client_pid, client_process_name)
            else:
                self._handle_http(client_conn, url, headers_chunk, body_chunk, client_pid, client_process_name)
                
        except Exception as e:
            pass
        finally:
            try:
                client_conn.close()
            except:
                pass

    def _get_or_create_cert(self, domain: str) -> tuple[str, str]:
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

    def _handle_https(self, client_conn, target_host_port, client_pid, client_process_name):
        host, port_str = target_host_port.split(":", 1) if ":" in target_host_port else (target_host_port, "443")
        port = int(port_str)
        
        client_conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        
        cert_file, key_file = self._get_or_create_cert(host)
        
        client_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            client_ssl_context.set_alpn_protocols(["http/1.1"])
        except (AttributeError, NotImplementedError):
            pass
        client_ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        
        client_ssl = None
        remote_ssl = None
        try:
            client_ssl = client_ssl_context.wrap_socket(client_conn, server_side=True)
            
            remote_conn = socket.create_connection((host, port), timeout=10)
            remote_ssl_context = ssl.create_default_context()
            try:
                remote_ssl_context.set_alpn_protocols(["http/1.1"])
            except (AttributeError, NotImplementedError):
                pass
            remote_ssl = remote_ssl_context.wrap_socket(remote_conn, server_hostname=host)
            
            self._tunnel_traffic(client_ssl, remote_ssl, host, client_pid, client_process_name)
        except Exception as e:
            pass
        finally:
            for s in [client_ssl, remote_ssl]:
                if s:
                    try:
                        s.close()
                    except:
                        pass

    def _handle_http(self, client_conn, url, headers_chunk, body_chunk, client_pid, client_process_name):
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
                
        words = req_lines[0].split()
        method = words[0].decode('utf-8', errors='ignore') if len(words) > 0 else "UNKNOWN"
        path = words[1].decode('utf-8', errors='ignore') if len(words) > 1 else "UNKNOWN"

        import urllib.parse
        parsed_url = urllib.parse.urlparse(path)
        if parsed_url.path == "/nvenv/resolve" or path.startswith("/nvenv/resolve"):
            query_params = urllib.parse.parse_qs(parsed_url.query)
            key_list = query_params.get("key", [])
            if not key_list:
                resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 15\r\nConnection: close\r\n\r\nMissing key param"
                client_conn.sendall(resp)
                return
            
            key = key_list[0]
            host_param = query_params.get("host", ["unknown"])[0]
            method_param = query_params.get("method", ["CONNECT"])[0]
            path_param = query_params.get("path", ["/"])[0]
            
            status, reason = self.policy_engine.validate(key, host_param, method_param, path_param, client_process_name)
            self.audit_logger.log(key, host_param, method_param, path_param, client_pid, client_process_name, status, reason)
            
            if status == "deny" or status == "rate_limited":
                resp_body = f"Access denied: {reason}".encode('utf-8')
                resp = f"HTTP/1.1 403 Forbidden\r\nContent-Length: {len(resp_body)}\r\nConnection: close\r\n\r\n".encode('utf-8') + resp_body
                client_conn.sendall(resp)
                return
                
            if status == "warn":
                print(f"\n\u26a0\ufe0f  [nvenv WARNING] {reason}", file=sys.stderr)
                print(f"\ud83d\udc49 Recommend defining a policy for '{key}' in ~/.nv/config.json\n", file=sys.stderr)
                
            secret_val = self.vault.get(key)
            if secret_val is None:
                resp = b"HTTP/1.1 444 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                client_conn.sendall(resp)
                return
                
            resp_body = secret_val.encode('utf-8')
            resp = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(resp_body)}\r\nConnection: close\r\n\r\n".encode('utf-8') + resp_body
            client_conn.sendall(resp)
            return

        if not host:
            return

        try:
            remote_conn = socket.create_connection((host, port), timeout=10)
            
            full_request = headers_chunk + b"\r\n\r\n" + body_chunk
            try:
                modified_request = self._replace_placeholders_lazy(
                    full_request, host, method, path, client_pid, client_process_name
                )
            except PermissionError as e:
                self._send_error_response(client_conn, str(e))
                return
            
            remote_conn.sendall(modified_request)
            
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

    def _tunnel_traffic(self, client_ssl, remote_ssl, target_host, client_pid, client_process_name):
        client_ssl.settimeout(15.0)
        remote_ssl.settimeout(15.0)
        
        try:
            while True:
                req_data = b""
                while b"\r\n\r\n" not in req_data:
                    chunk = client_ssl.recv(4096)
                    if not chunk:
                        return
                    req_data += chunk
                    
                header_part, body_part = req_data.split(b"\r\n\r\n", 1)
                
                req_lines = header_part.split(b"\r\n")
                words = req_lines[0].split()
                method = words[0].decode('utf-8', errors='ignore') if len(words) > 0 else "UNKNOWN"
                path = words[1].decode('utf-8', errors='ignore') if len(words) > 1 else "UNKNOWN"
                
                content_length = 0
                is_chunked = False
                for line in req_lines[1:]:
                    if line.lower().startswith(b"content-length:"):
                        content_length = int(line.split(b":", 1)[1].strip())
                    elif line.lower().startswith(b"transfer-encoding:") and b"chunked" in line.lower():
                        is_chunked = True
                
                if is_chunked:
                    body_part = self._read_chunked_body(client_ssl, body_part)
                elif content_length > 0:
                    while len(body_part) < content_length:
                        chunk = client_ssl.recv(4096)
                        if not chunk:
                            return
                        body_part += chunk
                
                full_request = header_part + b"\r\n\r\n" + body_part
                try:
                    modified_request = self._replace_placeholders_lazy(
                        full_request, target_host, method, path, client_pid, client_process_name
                    )
                except PermissionError as e:
                    self._send_error_response(client_ssl, str(e))
                    return
                
                remote_ssl.sendall(modified_request)
                
                resp_data = b""
                while b"\r\n\r\n" not in resp_data:
                    chunk = remote_ssl.recv(4096)
                    if not chunk:
                        return
                    resp_data += chunk
                    
                resp_header, resp_body = resp_data.split(b"\r\n\r\n", 1)
                
                client_ssl.sendall(resp_data)
                
                resp_content_length = -1
                resp_chunked = False
                for line in resp_header.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        resp_content_length = int(line.split(b":", 1)[1].strip())
                    elif line.lower().startswith(b"transfer-encoding:") and b"chunked" in line.lower():
                        resp_chunked = True
                
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
