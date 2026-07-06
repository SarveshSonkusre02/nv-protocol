import os
import sys
import unittest
import tempfile
import sqlite3
import threading
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler

# Add current path to imports so we can resolve vault, ca, proxy, etc.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from vault import Vault, encrypt_dpapi, decrypt_dpapi
from ca import CertificateAuthority
from proxy import NoViewEnvProxy, replace_placeholders
import runner

class MockHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Read request headers
        auth_header = self.headers.get('Authorization', '')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        # Respond back with the received Authorization header
        self.wfile.write(f"Received Auth: {auth_header}".encode('utf-8'))

    def log_message(self, format, *args):
        # Silence server logging in test outputs
        return


class TestNVProtocol(unittest.TestCase):
    def setUp(self):
        # Create a temporary database for testing
        self.temp_db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db_file.close()
        self.db_path = self.temp_db_file.name
        self.vault = Vault(self.db_path)

    def tearDown(self):
        # Remove temporary database
        try:
            os.remove(self.db_path)
        except:
            pass

    def test_dpapi_encryption_decryption(self):
        """Test Windows DPAPI encryption and decryption directly."""
        test_secret = b"stripe-live-secret-token-12345"
        encrypted = encrypt_dpapi(test_secret)
        self.assertNotEqual(test_secret, encrypted)
        
        decrypted = decrypt_dpapi(encrypted)
        self.assertEqual(test_secret, decrypted)

    def test_vault_crud(self):
        """Test Vault set, get, list, and delete operations."""
        self.vault.set("TEST_KEY_1", "value_1")
        self.vault.set("TEST_KEY_2", "value_2")
        
        self.assertEqual(self.vault.get("TEST_KEY_1"), "value_1")
        self.assertEqual(self.vault.get("TEST_KEY_2"), "value_2")
        self.assertIsNone(self.vault.get("NON_EXISTENT"))
        
        keys = self.vault.list_keys()
        self.assertIn("TEST_KEY_1", keys)
        self.assertIn("TEST_KEY_2", keys)
        
        self.assertTrue(self.vault.delete("TEST_KEY_1"))
        self.assertIsNone(self.vault.get("TEST_KEY_1"))
        self.assertFalse(self.vault.delete("TEST_KEY_1")) # Already deleted

    def test_placeholder_replacement(self):
        """Test placeholder replacement utility function."""
        cache = {
            "STRIPE_KEY": "sk_real_999",
            "DB_PASS": "admin_pass_123"
        }
        
        data = b"Authorization: Bearer nv://STRIPE_KEY\r\nConnection: keep-alive\r\nPassword: nv://DB_PASS"
        expected = b"Authorization: Bearer sk_real_999\r\nConnection: keep-alive\r\nPassword: admin_pass_123"
        
        result = replace_placeholders(data, cache)
        self.assertEqual(result, expected)
        
        # Test missing key behaves as a fallback (keeps original string)
        data_missing = b"Key: nv://MISSING_KEY"
        self.assertEqual(replace_placeholders(data_missing, cache), data_missing)

    def test_proxy_redirection_and_replacement(self):
        """Test that the local proxy intercepts traffic and replaces placeholders in real HTTP calls."""
        # 1. Start a mock target HTTP server on a random port
        mock_server = HTTPServer(('127.0.0.1', 0), MockHTTPHandler)
        mock_port = mock_server.server_port
        
        server_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
        server_thread.start()
        
        # 2. Store mock credential in vault
        self.vault.set("MOCK_API_KEY", "super-secret-production-token")
        
        # 3. Setup CA and Interception Proxy
        ca = CertificateAuthority()
        vault_cache = {"MOCK_API_KEY": "super-secret-production-token"}
        proxy = NoViewEnvProxy(vault_cache, ca)
        
        proxy_port = proxy.start()
        
        try:
            # 4. Perform an HTTP request through the local proxy
            # In urllib, we specify the proxy by configuring a proxy handler
            proxy_handler = urllib.request.ProxyHandler({
                'http': f'http://127.0.0.1:{proxy_port}',
                'https': f'http://127.0.0.1:{proxy_port}'
            })
            opener = urllib.request.build_opener(proxy_handler)
            
            # Request to the mock server using the placeholder URI
            url = f"http://127.0.0.1:{mock_port}/"
            req = urllib.request.Request(
                url, 
                headers={'Authorization': 'Bearer nv://MOCK_API_KEY'}
            )
            
            # Send request
            response = opener.open(req, timeout=5)
            response_body = response.read().decode('utf-8')
            
            # Assert that the remote server received the DECRYPTED real secret
            self.assertEqual(response_body, "Received Auth: Bearer super-secret-production-token")
            
        finally:
            proxy.stop()
            mock_server.shutdown()
            mock_server.server_close()


if __name__ == '__main__':
    unittest.main()
