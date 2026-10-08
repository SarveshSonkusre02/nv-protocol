import sys
import json
import os

# Add py_wrapper directory to sys.path if not present
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from vault import Vault
from policy import PolicyEngine

def run_mcp_server():
    """Lightweight Model Context Protocol (MCP) server for nvenv using stdio JSON-RPC 2.0."""
    vault = Vault()
    policy_engine = PolicyEngine()
    
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
                
            request = json.loads(line)
            req_id = request.get("id")
            method = request.get("method")
            params = request.get("params", {})
            
            if method == "initialize":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "nvenv-mcp",
                            "version": "1.0.0"
                        }
                    }
                }
            elif method == "notifications/initialized":
                continue # No response required for notifications
            elif method == "tools/list":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [
                            {
                                "name": "nvenv_list_keys",
                                "description": "List all protected secret key aliases stored in the nvenv vault (values remain hidden).",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {}
                                }
                            },
                            {
                                "name": "nvenv_check_policy",
                                "description": "Verify if a secret key is authorized to be injected for a specific target host, HTTP method, and path.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "key": {"type": "string", "description": "Secret alias key"},
                                        "host": {"type": "string", "description": "Target hostname"},
                                        "method": {"type": "string", "description": "HTTP method (POST, GET, etc.)"},
                                        "path": {"type": "string", "description": "HTTP path"}
                                    },
                                    "required": ["key", "host"]
                                }
                            },
                            {
                                "name": "nvenv_status",
                                "description": "Check the health and policy status of the nvenv cryptographic vault.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {}
                                }
                            }
                        ]
                    }
                }
            elif method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                
                if tool_name == "nvenv_list_keys":
                    keys = vault.list_keys()
                    content_text = json.dumps({"keys": keys, "count": len(keys)}, indent=2)
                elif tool_name == "nvenv_check_policy":
                    key = tool_args.get("key", "")
                    host = tool_args.get("host", "")
                    http_method = tool_args.get("method", "POST")
                    path = tool_args.get("path", "/")
                    status, reason = policy_engine.validate(key, host, http_method, path, "mcp-agent")
                    content_text = json.dumps({"key": key, "host": host, "status": status, "reason": reason}, indent=2)
                elif tool_name == "nvenv_status":
                    keys_count = len(vault.list_keys())
                    default_action = policy_engine.config.get("default_action", "warn")
                    content_text = json.dumps({"status": "active", "total_secrets": keys_count, "default_policy_action": default_action}, indent=2)
                else:
                    content_text = f"Unknown tool: {tool_name}"
                    
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": content_text
                            }
                        ]
                    }
                }
            elif method == "ping":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {}
                }
            else:
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }
                
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    run_mcp_server()
