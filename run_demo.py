import os
import sys

# Ensure py_wrapper is in path so we load the active module instead of root stub
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "py_wrapper"))

print("====================================================")
print("   nvenv Universal Secret Virtualization Demo        ")
print("====================================================")

# 1. Environment Variable Virtualization (Phase 2)
print("\n--- 1. Environment Variable Virtualization ---")
db_url = os.environ.get("DATABASE_URL")
print(f"DATABASE_URL (Virtual URI in env): {os.getenv('DATABASE_URL')}")
print(f"DATABASE_URL (Resolved value in memory): {db_url}")

# 2. File-Based Interception (Phase 3)
print("\n--- 2. File-Based Interception ---")
# Direct Virtual file read
try:
    with open("nv://SSH_PRIVATE_KEY", "r") as f:
        key_content = f.read()
    print(f"Read from virtual file 'nv://SSH_PRIVATE_KEY':\n{key_content}")
except Exception as e:
    print(f"Error reading virtual file: {e}")

# Configuration file containing placeholder
try:
    import tempfile
    temp_config = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode='w')
    temp_config.write('{"api_key": "nv://STRIPE_LIVE_KEY"}')
    temp_config.close()
    
    # Read the file normally: the read hook intercepts the contents and replaces placeholders
    with open(temp_config.name, "r") as f:
        config_data = f.read()
    print(f"Config file content read via open(): {config_data}")
    
    os.remove(temp_config.name)
except Exception as e:
    print(f"Error checking config file: {e}")

# 3. Database Connection Shimming (Phase 1)
print("\n--- 3. Database Connection Shimming ---")
try:
    import pymongo
    print("Testing PyMongo MongoClient (auto-detected and shimmed):")
    client = pymongo.MongoClient("mongodb://admin:nv://MONGO_PASSWORD@localhost:27017/?serverSelectionTimeoutMS=100")
    # Check if host argument was resolved
    print(f"  [pymongo] Client initialized successfully.")
except ImportError:
    print("pymongo is not installed. Registering a mock package to show the import shim hook in action:")
    class MockMongoClient:
        def __init__(self, host=None, **kwargs):
            print(f"  [MockMongoClient] Connecting to: {host}")
    sys.modules["pymongo"] = type(sys)("pymongo")
    sys.modules["pymongo"].MongoClient = MockMongoClient
    
    # Reload/inject the shimming engine from the preloaded environment
    from runner import PYTHON_SHIM_CONTENT
    exec(PYTHON_SHIM_CONTENT, globals(), locals())
    
    import pymongo
    client = pymongo.MongoClient("mongodb://admin:nv://MONGO_PASSWORD@localhost:27017")

# 4. Cryptographic Signing (Phase 4)
print("\n--- 4. Cryptographic / Token Signing ---")
try:
    import jwt
    print("Testing PyJWT Signing (auto-detected and shimmed):")
    token = jwt.encode({"user": "developer"}, "nv://JWT_SIGNING_KEY", algorithm="HS256")
    print(f"  [jwt] Encoded Token successfully.")
except ImportError:
    print("jwt is not installed. Registering a mock package to show the shim in action:")
    class MockJWT:
        def encode(self, payload, key, algorithm="HS256"):
            print(f"  [MockJWT] Encoding payload using key: {key}")
            return "mock-jwt-token"
    sys.modules["jwt"] = type(sys)("jwt")
    sys.modules["jwt"].encode = MockJWT().encode
    
    from runner import PYTHON_SHIM_CONTENT
    exec(PYTHON_SHIM_CONTENT, globals(), locals())
    
    import jwt
    jwt.encode({"user": "developer"}, "nv://JWT_SIGNING_KEY")
