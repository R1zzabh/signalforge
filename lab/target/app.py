import json, os, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

TELEMETRY = os.getenv("TELEMETRY_URL", "http://sf-telemetry:9100/events")
C2 = os.getenv("C2_URL", "http://sf-c2:9200/beacon")
HOST = "172.30.0.20"
ACCOUNTS = {"alice": ("alice-password", "employee"), "bob": ("bob-password", "employee"), "charlie": ("charlie-password", "employee"), "admin": ("admin-password", "admin"), "root": ("root-password", "root"), "security_admin": ("security-password", "security_admin"), "service_account": ("service-password", "service")}
beacon_stop = threading.Event()

def emit(kind, handler, **extra):
    event = {"event_id": "EVT-" + uuid.uuid4().hex[:12].upper(), "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source_ip": handler.headers.get("X-Lab-Source-IP", handler.client_address[0]), "destination_ip": HOST, "event_type": kind, "target_asset": "AUTH-SERVER-01", "asset_criticality": 5, "raw_source": "lab-target", "user_agent": handler.headers.get("User-Agent", "lab-browser"), "source_context": "isolated-lab", "scenario": handler.headers.get("X-Lab-Scenario"), **extra}
    try:
        body = json.dumps(event).encode(); urlopen(Request(TELEMETRY, data=body, headers={"Content-Type": "application/json"}), timeout=3).read()
    except Exception as exc: print("telemetry unavailable", exc, flush=True)

def beacon_loop():
    while not beacon_stop.wait(5):
        event = {"event_id": "BEACON-" + uuid.uuid4().hex[:10].upper(), "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source_ip": HOST, "destination_ip": "172.30.0.30", "event_type": "C2_BEACON", "target_asset": "AUTH-SERVER-01", "asset_criticality": 5, "raw_source": "lab-target", "source_context": "LAB_SIMULATION"}
        try:
            body = json.dumps(event).encode(); urlopen(Request(C2, data=body, headers={"Content-Type": "application/json"}), timeout=3).read()
        except Exception as exc: print("c2 unavailable", exc, flush=True)

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, content_type="text/html"):
        data = body if isinstance(body, bytes) else body.encode(); self.send_response(code); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health": return self._send(200, json.dumps({"status":"ok","asset":"AUTH-SERVER-01","environment":"LAB_MODE"}), "application/json")
        if path == "/login": return self._send(200, "<html><body><h1>SignalForge LAB target</h1><p>AUTH-SERVER-01 · LAB SIMULATION</p><form method='post'><input name='username' placeholder='username'><input name='password' type='password' placeholder='password'><button>Log in</button></form></body></html>")
        if path == "/lab/probe":
            port = int(parse_qs(urlparse(self.path).query).get("port", [0])[0]); emit("NETWORK_CONNECTION", self, destination_port=port, protocol="TCP", target_asset="WEB-SERVER-01" if port in (80,443,8080) else "AUTH-SERVER-01"); return self._send(202, json.dumps({"status":"recorded","port":port}), "application/json")
        return self._send(404, "not found")
    def do_POST(self):
        path = urlparse(self.path).path; length = int(self.headers.get("Content-Length", "0")); form = parse_qs(self.rfile.read(length).decode())
        if path == "/login":
            username = form.get("username", [""])[0]; password = form.get("password", [""])[0]; account = ACCOUNTS.get(username); success = bool(account and account[0] == password); emit("AUTH_SUCCESS" if success else "AUTH_FAILURE", self, username=username, success=success, user_role=account[1] if account else "unknown", session_id="SES-" + uuid.uuid4().hex[:10] if success else None); return self._send(200 if success else 401, json.dumps({"success": success, "message": "LAB login accepted" if success else "LAB login rejected"}), "application/json")
        if path == "/logout": emit("LOGOUT", self, username=form.get("username", ["alice"])[0]); return self._send(200, json.dumps({"status":"logged_out"}), "application/json")
        if path == "/lab/vulnerable": emit("VULNERABILITY_EXPLOIT_ATTEMPT", self, service="lab-web-service", cve="CVE-2024-6387", cvss=9.8, lab_simulation=True); return self._send(200, json.dumps({"status":"LAB_SIMULATION","message":"No real vulnerability was exploited"}), "application/json")
        if path == "/beacon/start":
            beacon_stop.clear(); threading.Thread(target=beacon_loop, daemon=True).start(); return self._send(202, json.dumps({"status":"beacon_started","interval_seconds":5}), "application/json")
        if path == "/beacon/stop": beacon_stop.set(); return self._send(200, json.dumps({"status":"beacon_stopped"}), "application/json")
        return self._send(404, "not found")
    def log_message(self, *_): pass

def stub(port):
    class Stub(BaseHTTPRequestHandler):
        def handle(self):
            try: emit("NETWORK_CONNECTION", self, destination_port=port, protocol="TCP", target_asset="WEB-SERVER-01" if port in (80,443,8080) else "AUTH-SERVER-01")
            except Exception: pass
            self.request.recv(32); self.request.close()
        def log_message(self, *_): pass
    ThreadingHTTPServer(("0.0.0.0", port), Stub).serve_forever()

if __name__ == "__main__":
    for port in (22, 80, 443, 9000, 9100, 9200, 9300, 9400, 9500, 9999): threading.Thread(target=stub, args=(port,), daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
