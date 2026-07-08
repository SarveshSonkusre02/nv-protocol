import os
import sys
import unittest
import tempfile
import json
import time
import threading
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler

# Add current path and py_wrapper path to imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "py_wrapper"))

from py_wrapper.vault import Vault, encrypt_dpapi, decrypt_dpapi, wipe_bytes
from py_wrapper.ca import CertificateAuthority
from py_wrapper.proxy import NoViewEnvProxy, get_pid_by_local_port, get_process_name_by_pid, is_descendant_of
from py_wrapper.policy import PolicyEngine
from py_wrapper.nv_audit import AuditLogger
from py_wrapper import runner

class MockHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth_header = self.headers.get('Authorization', '')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(f"Received Auth: {auth_header}".encode('utf-8'))

    def log_message(self, format, *args):
        return

class TestNVProtocol(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for config/vault/logs
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "vault.db")
        self.config_path = os.path.join(self.temp_dir.name, "config.json")
        self.log_path = os.path.join(self.temp_dir.name, "audit.log")
        
        self.vault = Vault(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI is only supported on Windows")
    def test_dpapi_encryption_decryption(self):
        """Test Windows DPAPI encryption and decryption directly."""
        test_secret = b"stripe-live-secret-token-12345"
        encrypted = encrypt_dpapi(test_secret)
        self.assertNotEqual(test_secret, encrypted)
        
        decrypted = decrypt_dpapi(encrypted)
        self.assertEqual(test_secret, decrypted)

    def test_vault_crud_and_wipe(self):
        """Test Vault set, get, get_bytes, list, delete, and memory wiping."""
        self.vault.set("TEST_KEY_1", "value_1")
        self.vault.set("TEST_KEY_2", "value_2")
        
        self.assertEqual(self.vault.get("TEST_KEY_1"), "value_1")
        self.assertEqual(self.vault.get("TEST_KEY_2"), "value_2")
        
        # Test get_bytes
        val_bytes = self.vault.get_bytes("TEST_KEY_1")
        self.assertIsInstance(val_bytes, bytearray)
        self.assertEqual(val_bytes, bytearray(b"value_1"))
        
        # Test memory wiping
        wipe_bytes(val_bytes)
        self.assertEqual(val_bytes, bytearray(len("value_1"))) # Should be all zeros
        
        self.assertIsNone(self.vault.get("NON_EXISTENT"))
        
        keys = self.vault.list_keys()
        self.assertIn("TEST_KEY_1", keys)
        self.assertIn("TEST_KEY_2", keys)
        
        self.assertTrue(self.vault.delete("TEST_KEY_1"))
        self.assertIsNone(self.vault.get("TEST_KEY_1"))

    def test_policy_engine(self):
        """Test PolicyEngine config parsing, default actions, validation and rate limits."""
        # 1. Test missing file uses default_action: warn
        policy = PolicyEngine(self.config_path)
        self.assertEqual(policy.config.get("default_action"), "warn")
        
        status, reason = policy.validate("SOME_KEY", "api.openai.com", "POST", "/v1/chat", "python.exe")
        self.assertEqual(status, "warn")
        
        # 2. Test deny policy configuration
        config_data = {
            "default_action": "deny",
            "policies": {
                "OPENAI_KEY": {
                    "allowed_hosts": ["api.openai.com"],
                    "allowed_methods": ["POST"],
                    "allowed_paths": ["/v1/chat/*"],
                    "allowed_processes": ["python.exe"],
                    "max_requests_per_minute": 2
                }
            }
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f)
            
        policy.load_config()
        self.assertEqual(policy.config.get("default_action"), "deny")
        
        # 2a. Valid request
        status, reason = policy.validate("OPENAI_KEY", "api.openai.com", "POST", "/v1/chat/completions", "python.exe")
        self.assertEqual(status, "allow")
        
        # 2b. Blocked process
        status, reason = policy.validate("OPENAI_KEY", "api.openai.com", "POST", "/v1/chat/completions", "node.exe")
        self.assertEqual(status, "deny")
        self.assertIn("Process", reason)
        
        # 2c. Blocked host
        status, reason = policy.validate("OPENAI_KEY", "malicious-host.com", "POST", "/v1/chat/completions", "python.exe")
        self.assertEqual(status, "deny")
        self.assertIn("Host", reason)
        
        # 2d. Blocked path
        status, reason = policy.validate("OPENAI_KEY", "api.openai.com", "POST", "/v1/files", "python.exe")
        self.assertEqual(status, "deny")
        self.assertIn("Path", reason)

        # 2e. Blocked method
        status, reason = policy.validate("OPENAI_KEY", "api.openai.com", "GET", "/v1/chat/completions", "python.exe")
        self.assertEqual(status, "deny")
        self.assertIn("Method", reason)

        # 2f. Rate limiting
        status, reason = policy.validate("OPENAI_KEY", "api.openai.com", "POST", "/v1/chat/completions", "python.exe") # 2nd request
        self.assertEqual(status, "allow")
        status, reason = policy.validate("OPENAI_KEY", "api.openai.com", "POST", "/v1/chat/completions", "python.exe") # 3rd request (exceeds 2/min)
        self.assertEqual(status, "rate_limited")

    def test_audit_logger(self):
        """Test AuditLogger writes events correctly to file."""
        logger = AuditLogger(self.log_path)
        logger.log("MY_KEY", "api.stripe.com", "POST", "/v1/charges", 1234, "node.exe", "allow", "Validated ok")
        
        self.assertTrue(os.path.exists(self.log_path))
        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)
        event = json.loads(lines[0])
        self.assertEqual(event["key"], "MY_KEY")
        self.assertEqual(event["host"], "api.stripe.com")
        self.assertEqual(event["status"], "allow")
        self.assertEqual(event["process_name"], "node.exe")

    def test_pid_and_descendant_matching(self):
        """Test parent process tree matching logic."""
        current_pid = os.getpid()
        self.assertTrue(is_descendant_of(current_pid, current_pid))
        
        # Create a dummy child process and verify descendant matching
        import subprocess
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1)"])
        try:
            self.assertTrue(is_descendant_of(p.pid, current_pid))
            self.assertFalse(is_descendant_of(current_pid, p.pid))
        finally:
            p.terminate()
            p.wait()

    def test_proxy_redirection_and_replacement(self):
        """Test that the local proxy intercepts traffic and replaces placeholders in real HTTP calls."""
        # 1. Start a mock target HTTP server on a random port
        mock_server = HTTPServer(('127.0.0.1', 0), MockHTTPHandler)
        mock_port = mock_server.server_port
        
        server_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
        server_thread.start()
        
        # 2. Store mock credential in vault
        self.vault.set("MOCK_API_KEY", "super-secret-production-token")
        
        # 3. Setup CA and Interception Proxy with Token Handshake
        ca = CertificateAuthority()
        token = "test-handshake-token-xyz"
        
        # Write temporary allow policy config
        config_data = {
            "default_action": "allow",
            "policies": {}
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f)
            
        proxy = NoViewEnvProxy(
            db_path=self.db_path,
            ca=ca,
            proxy_token=token,
            policy_config_path=self.config_path,
            audit_log_path=self.log_path
        )
        proxy_port = proxy.start()
        
        try:
            # 4a. Perform an HTTP request through the local proxy WITHOUT the auth token (should fail)
            proxy_handler = urllib.request.ProxyHandler({
                'http': f'http://127.0.0.1:{proxy_port}',
            })
            opener = urllib.request.build_opener(proxy_handler)
            
            url = f"http://127.0.0.1:{mock_port}/"
            req = urllib.request.Request(
                url, 
                headers={'Authorization': 'Bearer nv://MOCK_API_KEY'}
            )
            
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                opener.open(req, timeout=5)
            self.assertEqual(ctx.exception.code, 403)
            
            # 4b. Perform HTTP request WITH the auth token (should succeed)
            req_with_token = urllib.request.Request(
                url,
                headers={
                    'Authorization': 'Bearer nv://MOCK_API_KEY',
                    'X-NV-Proxy-Token': token
                }
            )
            response = opener.open(req_with_token, timeout=5)
            response_body = response.read().decode('utf-8')
            
            self.assertEqual(response_body, "Received Auth: Bearer super-secret-production-token")
            
        finally:
            proxy.stop()
            mock_server.shutdown()
            mock_server.server_close()

    def test_cross_platform_vault_encryption(self):
        """Test the general cross-platform encryption/decryption routines."""
        from py_wrapper.vault import encrypt_data, decrypt_data
        test_secret = b"test-cross-platform-secret-999"
        encrypted = encrypt_data(test_secret)
        self.assertNotEqual(test_secret, encrypted)
        
        decrypted = decrypt_data(encrypted)
        self.assertEqual(test_secret, decrypted)

    def test_proxy_alpn_negotiation(self):
        """Test that the SSLContext for both server and client allows setting ALPN protocols."""
        import ssl
        client_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            client_ssl_context.set_alpn_protocols(["http/1.1"])
            self.assertEqual(client_ssl_context.get_alpn_protocols(), ["http/1.1"])
        except (AttributeError, NotImplementedError):
            pass

    def test_policy_engine_save_config(self):
        """Test PolicyEngine config serialization and deserialization via policy.py changes."""
        from py_wrapper.policy import PolicyEngine
        policy_path = os.path.join(self.temp_dir.name, "custom_policy.json")
        engine = PolicyEngine(policy_path)
        engine.config["default_action"] = "deny"
        engine.config["policies"] = {
            "DB_PASS": {
                "allowed_hosts": ["db.example.com"],
                "allowed_processes": ["pg_dump"]
            }
        }
        
        self.assertTrue(engine.save_config())
        self.assertTrue(os.path.exists(policy_path))
        
        new_engine = PolicyEngine(policy_path)
        self.assertEqual(new_engine.config["default_action"], "deny")
        self.assertEqual(new_engine.config["policies"]["DB_PASS"]["allowed_hosts"], ["db.example.com"])

    def test_database_shimming_and_resolver_api(self):
        """Test database driver shimming and the proxy resolution endpoint."""
        import secrets
        import types
        token = secrets.token_hex(32)
        ca = CertificateAuthority()
        proxy = NoViewEnvProxy(
            db_path=self.db_path,
            ca=ca,
            proxy_token=token,
            policy_config_path=self.config_path,
            audit_log_path=self.log_path
        )
        proxy_port = proxy.start()
        
        self.vault.set("MONGO_PASSWORD", "super-secret-mongo-pwd")
        self.vault.set("redis/prod-key", "secure-redis-token")
        
        os.environ["HTTP_PROXY"] = f"http://127.0.0.1:{proxy_port}"
        os.environ["NV_PROXY_TOKEN"] = token
        
        try:
            # Test /nvenv/resolve endpoint directly
            import urllib.request
            import urllib.parse
            
            url = f"http://127.0.0.1:{proxy_port}/nvenv/resolve?key=MONGO_PASSWORD&host=localhost&method=CONNECT&path=mongodb"
            req = urllib.request.Request(url, headers={"x-nv-proxy-token": token})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=3) as resp:
                self.assertEqual(resp.status, 200)
                body = resp.read().decode('utf-8')
                self.assertEqual(body, "super-secret-mongo-pwd")
                
            # Request hierarchical key
            url = f"http://127.0.0.1:{proxy_port}/nvenv/resolve?key=redis/prod-key&host=localhost&method=CONNECT&path=redis"
            req = urllib.request.Request(url, headers={"x-nv-proxy-token": token})
            with opener.open(req, timeout=3) as resp:
                self.assertEqual(resp.status, 200)
                body = resp.read().decode('utf-8')
                self.assertEqual(body, "secure-redis-token")

            # Test Python Import Shim Hooking
            class DummyMongoClient:
                def __init__(self, host=None, *args, **kwargs):
                    self.host = host
                    self.args = args
                    self.kwargs = kwargs
            
            class DummyConnectionPool:
                @classmethod
                def from_url(cls, url, *args, **kwargs):
                    return url
                    
            class DummyRedis:
                def __init__(self, host=None, password=None, *args, **kwargs):
                    self.host = host
                    self.password = password

            class DummyPsycopg2:
                @staticmethod
                def connect(dsn=None, *args, **kwargs):
                    return dsn or kwargs.get("password")

            mock_pymongo = types.ModuleType("pymongo")
            mock_pymongo.MongoClient = DummyMongoClient
            sys.modules["pymongo"] = mock_pymongo

            mock_redis = types.ModuleType("redis")
            mock_redis.ConnectionPool = DummyConnectionPool
            mock_redis.Redis = DummyRedis
            sys.modules["redis"] = mock_redis
            
            mock_psycopg2 = types.ModuleType("psycopg2")
            mock_psycopg2.connect = DummyPsycopg2.connect
            sys.modules["psycopg2"] = mock_psycopg2

            # Execute shim definitions
            from py_wrapper.runner import PYTHON_SHIM_CONTENT
            local_vars = {}
            exec(PYTHON_SHIM_CONTENT, globals(), local_vars)
            
            # Connect & Verify Mongo Shim
            client = mock_pymongo.MongoClient("mongodb://admin:nv://MONGO_PASSWORD@localhost:27017")
            self.assertEqual(client.host, "mongodb://admin:super-secret-mongo-pwd@localhost:27017")
            
            # Connect & Verify Redis URL Shim
            resolved_redis_url = mock_redis.ConnectionPool.from_url("redis://:nv://redis/prod-key@localhost:6379")
            self.assertEqual(resolved_redis_url, "redis://:secure-redis-token@localhost:6379")

            # Connect & Verify Psycopg2 Shim
            resolved_pg_pass = mock_psycopg2.connect(password="nv://MONGO_PASSWORD")
            self.assertEqual(resolved_pg_pass, "super-secret-mongo-pwd")
            
        finally:
            proxy.stop()
            for m in ("pymongo", "redis", "psycopg2"):
                if m in sys.modules:
                    del sys.modules[m]

    def test_env_var_shimming(self):
        """Test that environment variables containing nv:// placeholders are transparently decrypted."""
        import secrets
        token = secrets.token_hex(32)
        ca = CertificateAuthority()
        proxy = NoViewEnvProxy(
            db_path=self.db_path,
            ca=ca,
            proxy_token=token,
            policy_config_path=self.config_path,
            audit_log_path=self.log_path
        )
        proxy_port = proxy.start()
        
        self.vault.set("AWS_SECRET_KEY", "aws-safe-secret-key-12345")
        
        os.environ["HTTP_PROXY"] = f"http://127.0.0.1:{proxy_port}"
        os.environ["NV_PROXY_TOKEN"] = token
        
        try:
            from py_wrapper.runner import PYTHON_SHIM_CONTENT
            local_vars = {}
            exec(PYTHON_SHIM_CONTENT, globals(), local_vars)
            
            os.environ["MY_AWS_KEY"] = "nv://AWS_SECRET_KEY"
            
            resolved_val = os.environ.get("MY_AWS_KEY")
            self.assertEqual(resolved_val, "aws-safe-secret-key-12345")
            
            self.assertEqual(os.environ["MY_AWS_KEY"], "aws-safe-secret-key-12345")
        finally:
            proxy.stop()
            if "MY_AWS_KEY" in os.environ:
                del os.environ["MY_AWS_KEY"]

    def test_file_interception_shimming(self):
        """Test builtins.open interception for files containing nv:// placeholders or paths."""
        import secrets
        token = secrets.token_hex(32)
        ca = CertificateAuthority()
        proxy = NoViewEnvProxy(
            db_path=self.db_path,
            ca=ca,
            proxy_token=token,
            policy_config_path=self.config_path,
            audit_log_path=self.log_path
        )
        proxy_port = proxy.start()
        
        self.vault.set("SSH_PRIVATE_KEY", "ssh-rsa-private-content-here")
        self.vault.set("DB_PASSWORD", "db-secret-password")
        
        os.environ["HTTP_PROXY"] = f"http://127.0.0.1:{proxy_port}"
        os.environ["NV_PROXY_TOKEN"] = token
        
        try:
            from py_wrapper.runner import PYTHON_SHIM_CONTENT
            local_vars = {}
            exec(PYTHON_SHIM_CONTENT, globals(), local_vars)
            
            with open("nv://SSH_PRIVATE_KEY", "r") as f:
                content = f.read()
            self.assertEqual(content, "ssh-rsa-private-content-here")
            
            temp_config = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode='w')
            temp_config.write('{"password": "nv://DB_PASSWORD"}')
            temp_config.close()
            
            with open(temp_config.name, "r") as f:
                content = f.read()
            self.assertEqual(content, '{"password": "db-secret-password"}')
            
            with open(temp_config.name, "rb") as f:
                content_bytes = f.read()
            self.assertEqual(content_bytes, b'{"password": "db-secret-password"}')
            
            os.remove(temp_config.name)
        finally:
            proxy.stop()

    def test_crypto_shimming(self):
        """Test cryptographic signing shimming (jwt)."""
        import secrets
        import types
        token = secrets.token_hex(32)
        ca = CertificateAuthority()
        proxy = NoViewEnvProxy(
            db_path=self.db_path,
            ca=ca,
            proxy_token=token,
            policy_config_path=self.config_path,
            audit_log_path=self.log_path
        )
        proxy_port = proxy.start()
        
        self.vault.set("JWT_SIGNING_KEY", "super-secret-jwt-key")
        
        os.environ["HTTP_PROXY"] = f"http://127.0.0.1:{proxy_port}"
        os.environ["NV_PROXY_TOKEN"] = token
        
        try:
            class DummyJWT:
                def encode(self, payload, key, algorithm="HS256"):
                    return f"signed-with-{key}"
                def decode(self, token, key, algorithms=["HS256"]):
                    return f"verified-with-{key}"
                    
            mock_jwt = types.ModuleType("jwt")
            mock_jwt.encode = DummyJWT().encode
            mock_jwt.decode = DummyJWT().decode
            sys.modules["jwt"] = mock_jwt
            
            from py_wrapper.runner import PYTHON_SHIM_CONTENT
            local_vars = {}
            exec(PYTHON_SHIM_CONTENT, globals(), local_vars)
            
            res_encode = mock_jwt.encode({"user": "admin"}, "nv://JWT_SIGNING_KEY")
            self.assertEqual(res_encode, "signed-with-super-secret-jwt-key")
            
            res_decode = mock_jwt.decode("token123", "nv://JWT_SIGNING_KEY")
            self.assertEqual(res_decode, "verified-with-super-secret-jwt-key")
        finally:
            proxy.stop()
            if "jwt" in sys.modules:
                del sys.modules["jwt"]


if __name__ == '__main__':
    unittest.main()
