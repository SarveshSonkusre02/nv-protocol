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

from vault import Vault, encrypt_dpapi, decrypt_dpapi, wipe_bytes
from ca import CertificateAuthority
from proxy import NoViewEnvProxy, get_pid_by_local_port, get_process_name_by_pid, is_descendant_of
from policy import PolicyEngine
from audit import AuditLogger
import runner

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

if __name__ == '__main__':
    unittest.main()
