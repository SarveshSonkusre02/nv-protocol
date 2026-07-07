import os
import json
import time
import fnmatch
from collections import defaultdict

class PolicyEngine:
    def __init__(self, config_path=None):
        if config_path is None:
            home_dir = os.path.expanduser("~")
            config_path = os.path.join(home_dir, ".nv", "config.json")
        self.config_path = config_path
        self.config = {
            "default_action": "warn",
            "policies": {}
        }
        self.request_history = defaultdict(list)  # key -> list of timestamps
        self.load_config()

    def load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    self.config = json.load(f)
            except Exception as e:
                import sys
                print(f"Warning: Failed to load policy config at {self.config_path}: {e}. Using defaults.", file=sys.stderr)
        else:
            try:
                os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
                with open(self.config_path, "w", encoding="utf-8") as f:
                    json.dump(self.config, f, indent=2)
            except Exception:
                pass

    def check_rate_limit(self, key, max_per_minute):
        if not max_per_minute:
            return True
        now = time.time()
        self.request_history[key] = [t for t in self.request_history[key] if now - t < 60]
        if len(self.request_history[key]) >= max_per_minute:
            return False
        self.request_history[key].append(now)
        return True

    def validate(self, key, host, method, path, process_name):
        """
        Validates request against policies.
        Returns: (status, reason)
        where status is 'allow', 'warn', 'deny', 'rate_limited'
        """
        self.load_config()

        default_action = self.config.get("default_action", "warn")
        policies = self.config.get("policies", {})

        if key not in policies:
            if default_action == "deny":
                return "deny", f"Access to secret '{key}' denied: no policy defined and default_action is 'deny'."
            elif default_action == "warn":
                return "warn", f"Access to secret '{key}' allowed but unconfigured: no policy defined for this key."
            else:
                return "allow", f"Access to secret '{key}' allowed (default)."

        policy = policies[key]

        # 1. Validate process name
        allowed_processes = policy.get("allowed_processes")
        if allowed_processes:
            process_match = False
            for pattern in allowed_processes:
                if fnmatch.fnmatch(process_name.lower(), pattern.lower()):
                    process_match = True
                    break
            if not process_match:
                return "deny", f"Process '{process_name}' is not allowed to access secret '{key}'."

        # 2. Validate target host
        allowed_hosts = policy.get("allowed_hosts")
        if allowed_hosts:
            host_match = False
            for pattern in allowed_hosts:
                if fnmatch.fnmatch(host.lower(), pattern.lower()):
                    host_match = True
                    break
            if not host_match:
                return "deny", f"Host '{host}' is not allowed for secret '{key}'."

        # 3. Validate HTTP method
        allowed_methods = policy.get("allowed_methods")
        if allowed_methods:
            method_match = False
            for m in allowed_methods:
                if m.upper() == method.upper():
                    method_match = True
                    break
            if not method_match:
                return "deny", f"HTTP Method '{method}' is not allowed for secret '{key}'."

        # 4. Validate request path
        allowed_paths = policy.get("allowed_paths")
        if allowed_paths:
            path_match = False
            for pattern in allowed_paths:
                if fnmatch.fnmatch(path.lower(), pattern.lower()):
                    path_match = True
                    break
            if not path_match:
                return "deny", f"HTTP Path '{path}' is not allowed for secret '{key}'."

        # 5. Validate rate limiting
        max_requests_per_minute = policy.get("max_requests_per_minute")
        if max_requests_per_minute is not None:
            if not self.check_rate_limit(key, max_requests_per_minute):
                return "rate_limited", f"Rate limit of {max_requests_per_minute} requests/min exceeded for secret '{key}'."

        return "allow", f"Access to secret '{key}' validated successfully."
