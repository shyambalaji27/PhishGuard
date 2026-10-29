"""
PhishGuard - Threat Intelligence Backend Proxy Server
=====================================================

A secure, lightweight backend proxy that mediates requests to external threat
intelligence APIs (Google Safe Browsing v4, VirusTotal v3).

Security & Privacy Design:
--------------------------
1. ZERO EXPOSURE OF SECRETS: API keys reside strictly on the server in environment
   variables (GOOGLE_SAFE_BROWSING_KEY, VIRUSTOTAL_API_KEY) and are NEVER sent to
   or exposed in client-side JavaScript.
2. TRANSPARENT DISCLOSURE: Clearly differentiates local heuristic verdicts from
   reputation-based database lookups.
3. DEFENSIVE NETWORK BEHAVIOR:
   - Does NOT visit, crawl, render, or execute submitted URLs.
   - Strictly enforces request timeouts (5.0s).
   - Gracefully handles rate limits (HTTP 429), timeouts, and service outages.
4. SAFE DEFAULT: Operates seamlessly in offline/heuristic-only mode when no API keys
   are configured.
"""

import json
import os
import sys
import base64
import urllib.request
import urllib.parse
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(os.environ.get("PORT", 8765))
HOST = "127.0.0.1"

# Environment Variables for External Services
GSB_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "").strip()
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()


def query_google_safe_browsing(target_url: str) -> dict:
    """
    Query Google Safe Browsing Lookup API v4.
    Documentation: https://developers.google.com/safe-browsing/v4/lookup-api
    """
    if not GSB_API_KEY:
        return {
            "enabled": False,
            "checked": False,
            "reason": "GOOGLE_SAFE_BROWSING_KEY environment variable not configured."
        }

    api_endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    payload = {
        "client": {
            "clientId": "PhishGuard-CyberSec-Demo",
            "clientVersion": "1.4.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": target_url}]
        }
    }

    req = urllib.request.Request(
        api_endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            matches = data.get("matches", [])
            is_malicious = len(matches) > 0

            return {
                "enabled": True,
                "checked": True,
                "service": "Google Safe Browsing v4",
                "status": "MALICIOUS" if is_malicious else "CLEAN",
                "matches": matches,
                "details": f"Found {len(matches)} match(es)" if is_malicious else "No threat matches in Google database"
            }
    except urllib.error.HTTPError as e:
        return {
            "enabled": True,
            "checked": False,
            "service": "Google Safe Browsing v4",
            "error": f"HTTP {e.code}: {e.reason}"
        }
    except Exception as e:
        return {
            "enabled": True,
            "checked": False,
            "service": "Google Safe Browsing v4",
            "error": str(e)
        }


def query_virustotal(target_url: str) -> dict:
    """
    Query VirusTotal API v3 URL lookup.
    Documentation: https://developers.virustotal.com/reference/url-info
    """
    if not VT_API_KEY:
        return {
            "enabled": False,
            "checked": False,
            "reason": "VIRUSTOTAL_API_KEY environment variable not configured."
        }

    # VirusTotal v3 URL identifiers are base64-encoded URL strings without padding '='
    url_id = base64.urlsafe_b64encode(target_url.encode("utf-8")).decode("utf-8").strip("=")
    api_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    req = urllib.request.Request(
        api_endpoint,
        headers={
            "x-apikey": VT_API_KEY,
            "Accept": "application/json"
        },
        method="GET"
    )

    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            harmless_count = stats.get("harmless", 0)

            return {
                "enabled": True,
                "checked": True,
                "service": "VirusTotal v3",
                "stats": stats,
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "harmless": harmless_count,
                "details": f"{malicious_count} engines flagged as malicious; {suspicious_count} suspicious"
            }
    except urllib.error.HTTPError as e:
        # 404 indicates VirusTotal hasn't scanned this URL yet
        if e.code == 404:
            return {
                "enabled": True,
                "checked": True,
                "service": "VirusTotal v3",
                "status": "UNSEEN",
                "details": "URL has not been previously submitted or analyzed on VirusTotal."
            }
        return {
            "enabled": True,
            "checked": False,
            "service": "VirusTotal v3",
            "error": f"HTTP {e.code}: {e.reason}"
        }
    except Exception as e:
        return {
            "enabled": True,
            "checked": False,
            "service": "VirusTotal v3",
            "error": str(e)
        }


class ThreatIntelProxyHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()

            resp = {
                "status": "online",
                "engine": "PhishGuard Threat Intel Backend Proxy",
                "services": {
                    "google_safe_browsing": bool(GSB_API_KEY),
                    "virustotal": bool(VT_API_KEY)
                },
                "mode": "hybrid" if (GSB_API_KEY or VT_API_KEY) else "local_heuristics_only"
            }
            self.wfile.write(json.dumps(resp, indent=2).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/check-threat-intel":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)

            try:
                payload = json.loads(body.decode("utf-8"))
                target_url = payload.get("url", "").strip()

                if not target_url:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self._send_cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Missing 'url' parameter"}).encode("utf-8"))
                    return

                # Perform Threat Intel Lookups
                gsb_result = query_google_safe_browsing(target_url)
                vt_result = query_virustotal(target_url)

                response_payload = {
                    "target_url": target_url,
                    "reputation_services": {
                        "google_safe_browsing": gsb_result,
                        "virustotal": vt_result
                    },
                    "timestamp": urllib.request.datetime.datetime.utcnow().isoformat() + "Z"
                }

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps(response_payload, indent=2).encode("utf-8"))

            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid JSON body"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Clean logging format
        sys.stderr.write(f"[PhishGuard Proxy] {self.address_string()} - {format % args}\n")


def run_proxy():
    server_address = (HOST, PORT)
    httpd = HTTPServer(server_address, ThreatIntelProxyHandler)
    print("=" * 65)
    print(f" PhishGuard Threat Intelligence Backend Proxy")
    print(f" Running on http://{HOST}:{PORT}")
    print("=" * 65)
    print(f" * Google Safe Browsing API: {'ACTIVE' if GSB_API_KEY else 'DISABLED (No Key)'}")
    print(f" * VirusTotal API:           {'ACTIVE' if VT_API_KEY else 'DISABLED (No Key)'}")
    print(" * Ready to receive client proxy queries safely.")
    print("=" * 65)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down PhishGuard proxy server gracefully.")
        httpd.server_close()


if __name__ == "__main__":
    run_proxy()

