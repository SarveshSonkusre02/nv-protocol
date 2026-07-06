import os
import sqlite3
import ctypes
from ctypes import wintypes

# Windows DPAPI structure definitions
class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', ctypes.POINTER(ctypes.c_byte))
    ]

def encrypt_dpapi(data: bytes) -> bytes:
    """Encrypts bytes using Windows DPAPI (CryptProtectData)."""
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    
    data_in = DATA_BLOB()
    data_in.cbData = len(data)
    data_in.pbData = ctypes.cast(
        ctypes.create_string_buffer(data, len(data)), 
        ctypes.POINTER(ctypes.c_byte)
    )
    
    data_out = DATA_BLOB()
    
    # CryptProtectData(pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut)
    # 0x01 = CRYPTPROTECT_UI_FORBIDDEN (prevent popups)
    result = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(data_in),
        None,  # Description
        None,  # Optional entropy
        None,  # Reserved
        None,  # Prompt structure
        0x01,  # dwFlags
        ctypes.byref(data_out)
    )
    
    if not result:
        raise OSError("Windows DPAPI: CryptProtectData failed to encrypt.")
        
    try:
        encrypted_bytes = ctypes.string_at(data_out.pbData, data_out.cbData)
        return encrypted_bytes
    finally:
        if data_out.pbData:
            ctypes.windll.kernel32.LocalFree(data_out.pbData)

def decrypt_dpapi(encrypted_data: bytes) -> bytes:
    """Decrypts bytes using Windows DPAPI (CryptUnprotectData)."""
    data_in = DATA_BLOB()
    data_in.cbData = len(encrypted_data)
    data_in.pbData = ctypes.cast(
        ctypes.create_string_buffer(encrypted_data, len(encrypted_data)), 
        ctypes.POINTER(ctypes.c_byte)
    )
    
    data_out = DATA_BLOB()
    
    # CryptUnprotectData(pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut)
    # 0x01 = CRYPTPROTECT_UI_FORBIDDEN
    result = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(data_in),
        None,  # Description
        None,  # Optional entropy
        None,  # Reserved
        None,  # Prompt structure
        0x01,  # dwFlags
        ctypes.byref(data_out)
    )
    
    if not result:
        raise OSError("Windows DPAPI: CryptUnprotectData failed to decrypt.")
        
    try:
        decrypted_bytes = ctypes.string_at(data_out.pbData, data_out.cbData)
        return decrypted_bytes
    finally:
        if data_out.pbData:
            ctypes.windll.kernel32.LocalFree(data_out.pbData)


class Vault:
    """SQLite-backed encrypted vault utilizing Windows DPAPI."""
    def __init__(self, db_path=None):
        if db_path is None:
            home_dir = os.path.expanduser("~")
            nv_dir = os.path.join(home_dir, ".nv")
            if not os.path.exists(nv_dir):
                os.makedirs(nv_dir, exist_ok=True)
            db_path = os.path.join(nv_dir, "vault.db")
        
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initializes the database schema."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    key TEXT PRIMARY KEY,
                    ciphertext BLOB
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def set(self, key: str, value: str):
        """Encrypts and stores a secret in the vault."""
        encrypted_val = encrypt_dpapi(value.encode('utf-8'))
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO secrets (key, ciphertext) VALUES (?, ?)",
                (key, encrypted_val)
            )
            conn.commit()
        finally:
            conn.close()

    def get(self, key: str) -> str:
        """Retrieves and decrypts a secret from the vault. Returns None if key doesn't exist."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT ciphertext FROM secrets WHERE key = ?", (key,))
            row = cursor.fetchone()
            if not row:
                return None
            decrypted_bytes = decrypt_dpapi(row[0])
            return decrypted_bytes.decode('utf-8')
        finally:
            conn.close()

    def list_keys(self):
        """Lists all keys stored in the database."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT key FROM secrets")
            rows = cursor.fetchall()
            return [row[0] for row in rows]
        finally:
            conn.close()

    def delete(self, key: str) -> bool:
        """Deletes a key from the vault. Returns True if deleted, False if key not found."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM secrets WHERE key = ?", (key,))
            changes = conn.total_changes
            conn.commit()
            return changes > 0
        finally:
            conn.close()
