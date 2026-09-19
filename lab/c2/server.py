import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

TELEMETRY = os.getenv("TELEMETRY_URL", "http://sf-telemetry:9100/events")
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        data=json.dumps({"status":"ok","mode":"LAB_SIMULATION"}).encode(); self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        event=json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0")))); event.update({"event_type":"C2_BEACON","target_asset":"AUTH-SERVER-01","asset_criticality":5,"raw_source":"sf-c2","source_context":"LAB_SIMULATION"}); body=json.dumps(event).encode()
        try: urlopen(Request(TELEMETRY, data=body, headers={"Content-Type":"application/json"}), timeout=3).read(); code=202
        except Exception: code=502
        self.send_response(code); self.end_headers()
    def log_message(self, *_): pass
ThreadingHTTPServer(("0.0.0.0", 9200), Handler).serve_forever()
