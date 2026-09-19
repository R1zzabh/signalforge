import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

BACKEND = os.getenv("SIGNALFORGE_URL", "http://signalforge-backend:8000/lab/events")
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health": return self.send_json(200, {"status":"ok","bridge":"connected"})
        self.send_json(404, {"error":"not found"})
    def do_POST(self):
        if self.path != "/events": return self.send_json(404, {"error":"not found"})
        try:
            event = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            body = json.dumps(event).encode(); response = urlopen(Request(BACKEND, data=body, headers={"Content-Type":"application/json"}), timeout=5); result = json.loads(response.read())
            return self.send_json(202, {"accepted": True, "backend": result})
        except Exception as exc: return self.send_json(502, {"accepted": False, "error": str(exc)})
    def send_json(self, code, value):
        data=json.dumps(value).encode(); self.send_response(code); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def log_message(self, *_): pass
ThreadingHTTPServer(("0.0.0.0", 9100), Handler).serve_forever()
