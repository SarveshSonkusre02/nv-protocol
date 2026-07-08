import os
import sys
import subprocess
import tempfile
import secrets
import shutil
from vault import Vault
from ca import CertificateAuthority
from proxy import NoViewEnvProxy

PYTHON_SHIM_CONTENT = r"""import os
import sys
import urllib.request
import urllib.parse
import re
import builtins
import io
from importlib.abc import MetaPathFinder, Loader

def decrypt_string(val, host="unknown", method="CONNECT", path="/"):
    if not isinstance(val, str) or ("nv://" not in val and "nv%3" not in val.lower()):
        return val
        
    proxy_url = os.environ.get("HTTP_PROXY")
    proxy_token = os.environ.get("NV_PROXY_TOKEN")
    if not proxy_url or not proxy_token:
        return val
        
    def replace_match(match):
        prefix = match.group(1)
        key = match.group(2)
        try:
            parsed_proxy = urllib.parse.urlparse(proxy_url)
            proxy_host = parsed_proxy.hostname
            proxy_port = parsed_proxy.port
            
            params = {
                "key": key,
                "host": host,
                "method": method,
                "path": path
            }
            resolve_url = f"http://{proxy_host}:{proxy_port}/nvenv/resolve?{urllib.parse.urlencode(params)}"
            
            req = urllib.request.Request(resolve_url)
            req.add_header("x-nv-proxy-token", proxy_token)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=3) as response:
                if response.status == 200:
                    secret = response.read().decode('utf-8')
                    if b'%' in prefix.encode('utf-8'):
                        return urllib.parse.quote(secret)
                    return secret
        except Exception:
            pass
        return match.group(0)

    return re.sub(r'(nv://|nv%3[Aa]%2[Ff]%2[Ff])([A-Za-z0-9_/\\-]+)', replace_match, val)

# 1. Environment Variable Trapping
original_environ_get = os.environ.__class__.get
original_environ_getitem = os.environ.__class__.__getitem__

def shimmed_environ_getitem(self, key):
    val = original_environ_getitem(self, key)
    if isinstance(val, str) and ("nv://" in val or "nv%3" in val.lower()):
        return decrypt_string(val, host="env", method="GET", path=key)
    return val
    
def shimmed_environ_get(self, key, default=None):
    val = original_environ_get(self, key, default)
    if isinstance(val, str) and ("nv://" in val or "nv%3" in val.lower()):
        return decrypt_string(val, host="env", method="GET", path=key)
    return val

os.environ.__class__.__getitem__ = shimmed_environ_getitem
os.environ.__class__.get = shimmed_environ_get

# 2. File Interception (builtins.open)
original_open = builtins.open

def shimmed_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    is_read = any(char in mode for char in ('r', '+'))
    if not is_read:
        return original_open(file, mode, buffering, encoding, errors, newline, closefd, opener)
        
    if isinstance(file, str) and (file.startswith("nv://") or file.lower().startswith("nv%3")):
        resolved = decrypt_string(file, host="file", method="READ", path=file)
        if 'b' in mode:
            return io.BytesIO(resolved.encode('utf-8'))
        else:
            return io.StringIO(resolved)
            
    try:
        if isinstance(file, str) and os.path.exists(file) and os.path.isfile(file):
            size = os.path.getsize(file)
            if size < 5 * 1024 * 1024:
                with original_open(file, 'rb') as f:
                    content_bytes = f.read()
                if b"nv://" in content_bytes or b"nv%" in content_bytes.lower():
                    enc = encoding or 'utf-8'
                    content_str = content_bytes.decode(enc, errors='ignore')
                    decrypted = decrypt_string(content_str, host="file", method="READ", path=file)
                    if 'b' in mode:
                        return io.BytesIO(decrypted.encode(enc))
                    else:
                        return io.StringIO(decrypted)
    except Exception:
        pass
        
    return original_open(file, mode, buffering, encoding, errors, newline, closefd, opener)

builtins.open = shimmed_open

# 3. Dynamic Module Shimming (sys.meta_path finder/loader wrapper)
def apply_shim_to_module(name, module):
    if name == "pymongo":
        original_init = module.MongoClient.__init__
        def shimmed_mongo_init(self, *args, **kwargs):
            new_args = list(args)
            host = "unknown"
            if len(new_args) > 0 and isinstance(new_args[0], str):
                host = new_args[0]
                new_args[0] = decrypt_string(new_args[0], host=host, method="CONNECT", path="mongodb")
            if "host" in kwargs and isinstance(kwargs["host"], str):
                host = kwargs["host"]
                kwargs["host"] = decrypt_string(kwargs["host"], host=host, method="CONNECT", path="mongodb")
            if "host" in kwargs and isinstance(kwargs["host"], list):
                kwargs["host"] = [decrypt_string(h, host=h, method="CONNECT", path="mongodb") for h in kwargs["host"]]
            original_init(self, *new_args, **kwargs)
        module.MongoClient.__init__ = shimmed_mongo_init
        
    elif name == "redis":
        original_from_url = module.ConnectionPool.from_url
        @classmethod
        def shimmed_from_url(cls, url, *args, **kwargs):
            decrypted_url = decrypt_string(url, host=url, method="CONNECT", path="redis")
            return original_from_url(decrypted_url, *args, **kwargs)
        module.ConnectionPool.from_url = shimmed_from_url
        
        original_redis_init = module.Redis.__init__
        def shimmed_redis_init(self, *args, **kwargs):
            if "host" in kwargs and isinstance(kwargs["host"], str):
                kwargs["host"] = decrypt_string(kwargs["host"], host=kwargs["host"], method="CONNECT", path="redis")
            if "password" in kwargs and isinstance(kwargs["password"], str):
                kwargs["password"] = decrypt_string(kwargs["password"], host="redis-password", method="CONNECT", path="redis")
            original_redis_init(self, *args, **kwargs)
        module.Redis.__init__ = shimmed_redis_init
        
    elif name in ("psycopg2", "psycopg"):
        original_connect = module.connect
        def shimmed_pg_connect(*args, **kwargs):
            new_args = list(args)
            host = "unknown"
            if len(new_args) > 0 and isinstance(new_args[0], str):
                host = new_args[0]
                new_args[0] = decrypt_string(new_args[0], host=host, method="CONNECT", path="postgres")
            for k in ("dsn", "password", "host"):
                if k in kwargs and isinstance(kwargs[k], str):
                    host = kwargs.get("host", "postgres")
                    kwargs[k] = decrypt_string(kwargs[k], host=host, method="CONNECT", path="postgres")
            return original_connect(*new_args, **kwargs)
        module.connect = shimmed_pg_connect

    elif name == "jwt":
        original_encode = module.encode
        def shimmed_encode(payload, key, *args, **kwargs):
            decrypted_key = decrypt_string(key, host="jwt", method="SIGN", path="encode")
            return original_encode(payload, decrypted_key, *args, **kwargs)
        module.encode = shimmed_encode
        
        original_decode = module.decode
        def shimmed_decode(jwt, key, *args, **kwargs):
            decrypted_key = decrypt_string(key, host="jwt", method="VERIFY", path="decode")
            return original_decode(jwt, decrypted_key, *args, **kwargs)
        module.decode = shimmed_decode

    elif name == "cryptography.hazmat.primitives.serialization":
        original_load_pem_private_key = module.load_pem_private_key
        def shimmed_load_pem_private_key(data, password, *args, **kwargs):
            if isinstance(data, bytes) and (b"nv://" in data or b"nv%" in data.lower()):
                decrypted_data = decrypt_string(data.decode('utf-8', errors='ignore'), host="crypto", method="LOAD", path="private_key").encode('utf-8')
                return original_load_pem_private_key(decrypted_data, password, *args, **kwargs)
            return original_load_pem_private_key(data, password, *args, **kwargs)
        module.load_pem_private_key = shimmed_load_pem_private_key

class NVImportHook(MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname in ("pymongo", "redis", "psycopg2", "psycopg", "jwt", "cryptography.hazmat.primitives.serialization"):
            sys.meta_path.remove(self)
            try:
                import importlib.util
                spec = importlib.util.find_spec(fullname, path)
                if spec is not None:
                    spec.loader = NVLoaderWrapper(spec.loader, fullname)
                    return spec
            finally:
                sys.meta_path.insert(0, self)
        return None

class NVLoaderWrapper(Loader):
    def __init__(self, original_loader, name):
        self.original_loader = original_loader
        self.name = name
        
    def create_module(self, spec):
        return self.original_loader.create_module(spec)
        
    def exec_module(self, module):
        self.original_loader.exec_module(module)
        try:
            apply_shim_to_module(self.name, module)
        except Exception:
            pass

sys.meta_path.insert(0, NVImportHook())

# Apply shims to modules that have already been imported
for name in list(sys.modules.keys()):
    if name in ("pymongo", "redis", "psycopg2", "psycopg", "jwt", "cryptography.hazmat.primitives.serialization"):
        try:
            apply_shim_to_module(name, sys.modules[name])
        except Exception:
            pass
"""

NODE_SHIM_CONTENT = r"""const Module = require('module');
const fs = require('fs');
const { execSync } = require('child_process');
const url = require('url');

function decryptString(val, host = 'unknown', method = 'CONNECT', path = '/') {
  if (typeof val !== 'string' || (!val.includes('nv://') && !val.toLowerCase().includes('nv%3'))) return val;
  const proxyUrl = process.env.HTTP_PROXY;
  const proxyToken = process.env.NV_PROXY_TOKEN;
  if (!proxyUrl || !proxyToken) return val;

  return val.replace(/(nv:\/\/|nv%3[Aa]%2[Ff]%2[Ff])([A-Za-z0-9_/\-]+)/g, (match, prefix, key) => {
    try {
      const parsedProxy = url.parse(proxyUrl);
      const proxyHost = parsedProxy.hostname;
      const proxyPort = parsedProxy.port;
      const params = `key=${encodeURIComponent(key)}&host=${encodeURIComponent(host)}&method=${encodeURIComponent(method)}&path=${encodeURIComponent(path)}`;
      const resolveUrl = `http://${proxyHost}:${proxyPort}/nvenv/resolve?${params}`;

      let cmd;
      if (process.platform === 'win32') {
        cmd = `powershell -NoProfile -Command "(Invoke-WebRequest -Uri '${resolveUrl}' -Headers @{'x-nv-proxy-token'='${proxyToken}'} -UseBasicParsing).Content"`;
      } else {
        cmd = `curl -s -H "x-nv-proxy-token: ${proxyToken}" "${resolveUrl}"`;
      }

      const output = execSync(cmd, { stdio: ['ignore', 'pipe', 'ignore'], timeout: 3000 });
      const secret = output.toString('utf8').trim();
      if (!secret) return match;

      if (prefix.includes('%')) {
        return encodeURIComponent(secret);
      }
      return secret;
    } catch (e) {
      return match;
    }
  });
}

// 1. Trap process.env using Proxy
process.env = new Proxy(process.env, {
  get(target, prop) {
    const val = Reflect.get(target, prop);
    if (typeof val === 'string' && (val.includes('nv://') || val.toLowerCase().includes('nv%3'))) {
      return decryptString(val, 'env', 'GET', String(prop));
    }
    return val;
  }
});

// 2. Hook Filesystem Read API
const originalReadFileSync = fs.readFileSync;
fs.readFileSync = function (path, options) {
  if (typeof path === 'string' && (path.startsWith('nv://') || path.toLowerCase().startsWith('nv%3'))) {
    const resolved = decryptString(path, 'file', 'READ', path);
    return options ? resolved : Buffer.from(resolved);
  }
  
  try {
    if (typeof path === 'string' && fs.existsSync(path) && fs.statSync(path).isFile()) {
      const size = fs.statSync(path).size;
      if (size < 5 * 1024 * 1024) {
        const content = originalReadFileSync(path, 'utf8');
        if (content.includes('nv://') || content.toLowerCase().includes('nv%3')) {
          const decrypted = decryptString(content, 'file', 'READ', path);
          return options ? decrypted : Buffer.from(decrypted);
        }
      }
    }
  } catch (e) {}
  
  return originalReadFileSync.apply(this, arguments);
};

const originalReadFile = fs.readFile;
fs.readFile = function (path, options, callback) {
  const cb = typeof options === 'function' ? options : callback;
  const opts = typeof options === 'function' ? undefined : options;
  
  if (typeof path === 'string' && (path.startsWith('nv://') || path.toLowerCase().startsWith('nv%3'))) {
    const resolved = decryptString(path, 'file', 'READ', path);
    const result = opts ? resolved : Buffer.from(resolved);
    if (cb) cb(null, result);
    return;
  }

  try {
    if (typeof path === 'string' && fs.existsSync(path) && fs.statSync(path).isFile()) {
      const size = fs.statSync(path).size;
      if (size < 5 * 1024 * 1024) {
        const content = fs.readFileSync(path, 'utf8');
        if (content.includes('nv://') || content.toLowerCase().includes('nv%3')) {
          const decrypted = decryptString(content, 'file', 'READ', path);
          const result = opts ? decrypted : Buffer.from(decrypted);
          if (cb) cb(null, result);
          return;
        }
      }
    }
  } catch (e) {}

  return originalReadFile.apply(this, arguments);
};

if (fs.promises && fs.promises.readFile) {
  const originalPromisesReadFile = fs.promises.readFile;
  fs.promises.readFile = async function (path, options) {
    if (typeof path === 'string' && (path.startsWith('nv://') || path.toLowerCase().startsWith('nv%3'))) {
      const resolved = decryptString(path, 'file', 'READ', path);
      return options ? resolved : Buffer.from(resolved);
    }
    try {
      if (typeof path === 'string' && fs.existsSync(path) && fs.statSync(path).isFile()) {
        const size = fs.statSync(path).size;
        if (size < 5 * 1024 * 1024) {
          const content = await originalPromisesReadFile(path, 'utf8');
          if (content.includes('nv://') || content.toLowerCase().includes('nv%3')) {
            const decrypted = decryptString(content, 'file', 'READ', path);
            return options ? decrypted : Buffer.from(decrypted);
          }
        }
      }
    } catch (e) {}
    return originalPromisesReadFile.apply(this, arguments);
  };
}

// 3. Hook Client Module Loading Shims
const originalLoad = Module._load;
Module._load = function (request) {
  const exports = originalLoad.apply(this, arguments);

  if (request === 'mongodb') {
    try {
      const originalConnect = exports.MongoClient.prototype.connect;
      exports.MongoClient.prototype.connect = function () {
        if (this.s && this.s.url) {
          this.s.url = decryptString(this.s.url, this.s.url, 'CONNECT', 'mongodb');
        }
        return originalConnect.apply(this, arguments);
      };
    } catch (e) {}
  }

  if (request === 'pg') {
    try {
      const originalClientConnect = exports.Client.prototype.connect;
      exports.Client.prototype.connect = function () {
        if (this.connectionParameters) {
          const host = this.connectionParameters.host || 'postgres';
          if (this.connectionParameters.password) {
            this.connectionParameters.password = decryptString(this.connectionParameters.password, host, 'CONNECT', 'postgres');
          }
          if (this.connectionParameters.host) {
            this.connectionParameters.host = decryptString(this.connectionParameters.host, host, 'CONNECT', 'postgres');
          }
        }
        return originalClientConnect.apply(this, arguments);
      };
    } catch (e) {}
  }

  if (request === 'redis' || request === '@redis/client') {
    try {
      const originalCreateClient = exports.createClient;
      exports.createClient = function (options) {
        if (options && options.url) {
          options.url = decryptString(options.url, options.url, 'CONNECT', 'redis');
        }
        if (options && options.password) {
          options.password = decryptString(options.password, 'redis-password', 'CONNECT', 'redis');
        }
        return originalCreateClient.apply(this, arguments);
      };
    } catch (e) {}
  }

  if (request === 'jsonwebtoken') {
    try {
      const originalSign = exports.sign;
      exports.sign = function (payload, secretOrPrivateKey, options, callback) {
        const decryptedKey = decryptString(secretOrPrivateKey, 'jwt', 'SIGN', 'sign');
        return originalSign.call(this, payload, decryptedKey, options, callback);
      };
      
      const originalVerify = exports.verify;
      exports.verify = function (token, secretOrPublicKey, options, callback) {
        const decryptedKey = decryptString(secretOrPublicKey, 'jwt', 'VERIFY', 'verify');
        return originalVerify.call(this, token, decryptedKey, options, callback);
      };
    } catch (e) {}
  }

  return exports;
};
"""

def run_command(args, db_path=None):
    """Starts the proxy, injects proxy/CA/token environment, and runs target command."""
    if not args:
        print("Error: No command specified to run.", file=sys.stderr)
        return 1

    # 1. Generate an ephemeral, secure token
    proxy_token = secrets.token_hex(32)

    # 2. Instantiate CA and Proxy (lazy decryption, token enabled)
    ca = CertificateAuthority()
    proxy = NoViewEnvProxy(db_path=db_path, ca=ca, proxy_token=proxy_token)
    
    proxy_port = proxy.start()
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    
    # 3. Write CA certificate to a temporary file
    temp_ca = tempfile.NamedTemporaryFile(delete=False, suffix=".crt", mode='wb')
    temp_ca.write(ca.get_ca_cert_pem())
    temp_ca.close()
    ca_path = os.path.abspath(temp_ca.name)
    
    # Create temporary shims directory
    temp_shim_dir = tempfile.mkdtemp(prefix="nvenv_shims_")
    
    # Write Python preloader
    with open(os.path.join(temp_shim_dir, "sitecustomize.py"), "w", encoding="utf-8") as f:
        f.write(PYTHON_SHIM_CONTENT)
        
    # Write Node preloader
    with open(os.path.join(temp_shim_dir, "node_shim.js"), "w", encoding="utf-8") as f:
        f.write(NODE_SHIM_CONTENT)

    # 4. Prepare Child Process Environment Variables
    env = os.environ.copy()
    
    # Proxy redirection
    env["HTTP_PROXY"] = proxy_url
    env["HTTPS_PROXY"] = proxy_url
    
    # SSL trust injection for various runtimes
    env["NODE_EXTRA_CA_CERTS"] = ca_path
    env["REQUESTS_CA_BUNDLE"] = ca_path
    env["SSL_CERT_FILE"] = ca_path
    env["CURL_CA_BUNDLE"] = ca_path
    env["AWS_CA_BUNDLE"] = ca_path
    
    # Also override uppercase versions
    env["http_proxy"] = proxy_url
    env["https_proxy"] = proxy_url

    # Secure token injection for direct header authentication if needed
    env["NV_PROXY_TOKEN"] = proxy_token

    # Inject Shims
    python_path = env.get("PYTHONPATH", "")
    if python_path:
        env["PYTHONPATH"] = os.path.pathsep.join([temp_shim_dir, python_path])
    else:
        env["PYTHONPATH"] = temp_shim_dir
        
    node_options = env.get("NODE_OPTIONS", "")
    shim_path_escaped = os.path.join(temp_shim_dir, "node_shim.js").replace("\\", "/")
    env["NODE_OPTIONS"] = f"{node_options} --require \"{shim_path_escaped}\"".strip()

    # 5. Spawn Child Process
    p = None
    try:
        p = subprocess.Popen(args, env=env)
        # Propagate child PID to the proxy immediately for Process tree validation
        proxy.allowed_pid = p.pid
        p.wait()
        return p.returncode
    except KeyboardInterrupt:
        if p:
            p.terminate()
            p.wait()
        return 130
    except Exception as e:
        print(f"Error executing command: {e}", file=sys.stderr)
        return 1
    finally:
        # 6. Shutdown Proxy & Cleanup CA File & Shims
        proxy.stop()
        try:
            if os.path.exists(ca_path):
                os.remove(ca_path)
        except Exception:
            pass
        try:
            if os.path.exists(temp_shim_dir):
                shutil.rmtree(temp_shim_dir)
        except Exception:
            pass
