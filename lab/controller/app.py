import json, os, socket, threading, time
from urllib.error import HTTPError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.request import Request, urlopen

TARGET=os.getenv("TARGET_URL", "http://sf-target:8080"); TELEMETRY=os.getenv("TELEMETRY_URL", "http://sf-telemetry:9100/events"); C2=os.getenv("C2_URL", "http://sf-c2:9200")
ALLOWED={"normal_login","brute_force","credential_stuffing","port_scan","c2_simulation","cve_lab","privileged_account","allowlisted_scanner","alert_burst"}
running={"scenario":None,"status":"IDLE","events_generated":0}
def post(path, values, source="172.30.0.10"):
    body=values if isinstance(values, bytes) else json.dumps(values).encode(); return urlopen(Request(TARGET+path, data=body, headers={"Content-Type":"application/x-www-form-urlencoded" if isinstance(values, bytes) else "application/json","X-Lab-Source-IP":source,"X-Lab-Scenario":running.get("scenario","")}), timeout=5).read()
def login(user, password, source="172.30.0.10"):
    try:
        return urlopen(Request(TARGET+"/login", data=(f"username={user}&password={password}").encode(), headers={"Content-Type":"application/x-www-form-urlencoded","X-Lab-Source-IP":source,"X-Lab-Scenario":running.get("scenario","")}), timeout=5).read()
    except HTTPError as exc:
        return exc.read()
def emit_network(port, source):
    urlopen(Request(TARGET+f"/lab/probe?port={port}", headers={"X-Lab-Source-IP":source,"X-Lab-Scenario":running.get("scenario","")}), timeout=5).read()
def run(name):
    running.update({"scenario":name,"status":"RUNNING","events_generated":0})
    try:
        if name=="normal_login": login("alice","alice-password","172.30.0.10")
        elif name in ("brute_force","privileged_account"):
            user="admin" if name=="brute_force" else "security_admin"
            for i in range(63): login(user, f"wrong-{i}", "172.30.0.11")
        elif name=="credential_stuffing":
            for user in ("alice","bob","charlie","admin","root","service_account"):
                login(user,"wrong-password","172.30.0.12"); login(user,"wrong-password-2","172.30.0.12")
        elif name in ("port_scan","allowlisted_scanner"):
            source="172.30.0.50" if name=="allowlisted_scanner" else "172.30.0.13"
            for port in (22,80,443,8080,9000,9100,9200,9300,9400,9500,9999): emit_network(port, source)
        elif name=="c2_simulation": post("/beacon/start", b"", "172.30.0.20")
        elif name=="cve_lab": post("/lab/vulnerable", b"", "172.30.0.14")
        elif name=="alert_burst":
            for _ in range(24): login("alice","wrong-burst","172.30.0.15")
        running.update({"status":"COMPLETED","events_generated":63 if name in ("brute_force","privileged_account") else 24 if name=="alert_burst" else 11 if name in ("port_scan","allowlisted_scanner") else 1})
    except Exception as exc: running.update({"status":"FAILED","error":str(exc)})
def reset(): running.update({"scenario":None,"status":"IDLE","events_generated":0});
class Handler(BaseHTTPRequestHandler):
    def send_json(self, code, value):
        data=json.dumps(value).encode(); self.send_response(code); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        if self.path=="/status": return self.send_json(200,{"components":{"target":"CONNECTED","attacker":"CONNECTED","c2":"CONNECTED","telemetry":"CONNECTED","controller":"CONNECTED","network":"ISOLATED"},"running":running})
        self.send_json(404,{"error":"not found"})
    def do_POST(self):
        path=urlparse(self.path).path
        if path=="/reset": reset(); return self.send_json(200,{"reset":True})
        if path.startswith("/scenarios/"):
            name=path.split("/")[-1]
            if name not in ALLOWED: return self.send_json(404,{"error":"unknown safe scenario"})
            if running["status"]=="RUNNING": return self.send_json(409,{"error":"scenario already running"})
            threading.Thread(target=run,args=(name,),daemon=True).start(); return self.send_json(202,{"accepted":True,"scenario":name,"status":"STARTED"})
        self.send_json(404,{"error":"not found"})
    def log_message(self,*_): pass
ThreadingHTTPServer(("0.0.0.0",9101),Handler).serve_forever()
