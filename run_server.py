"""
SecurityShells Multi-Port Server Runner
Runs:
- HTTPS on port 443 (https://securityshells.com)
- HTTP on port 80 (http://securityshells.com)
- HTTP on port 8000 (http://localhost:8000)
"""
import sys
import threading
import uvicorn
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()
CERT_FILE = BASE_DIR / "cert.pem"
KEY_FILE = BASE_DIR / "key.pem"

def run_https_443():
    try:
        print("[*] Starting HTTPS server on port 443 (https://securityshells.com)...")
        config = uvicorn.Config(
            "server:app",
            host="0.0.0.0",
            port=443,
            ssl_certfile=str(CERT_FILE),
            ssl_keyfile=str(KEY_FILE),
            log_level="info"
        )
        server = uvicorn.Server(config)
        server.run()
    except Exception as e:
        print(f"[!] Warning: Could not bind HTTPS port 443: {e}")

def run_http_80():
    try:
        print("[*] Starting HTTP server on port 80 (http://securityshells.com)...")
        config = uvicorn.Config(
            "server:app",
            host="0.0.0.0",
            port=80,
            log_level="warning"
        )
        server = uvicorn.Server(config)
        server.run()
    except Exception as e:
        print(f"[!] Warning: Could not bind HTTP port 80: {e}")

def run_http_8000():
    try:
        print("[*] Starting HTTP server on port 8000 (http://localhost:8000)...")
        config = uvicorn.Config(
            "server:app",
            host="0.0.0.0",
            port=8000,
            log_level="warning"
        )
        server = uvicorn.Server(config)
        server.run()
    except Exception as e:
        print(f"[!] Warning: Could not bind HTTP port 8000: {e}")

if __name__ == "__main__":
    t443 = threading.Thread(target=run_https_443, daemon=True)
    t80 = threading.Thread(target=run_http_80, daemon=True)
    
    t443.start()
    t80.start()
    
    # Run port 8000 on main thread
    run_http_8000()
