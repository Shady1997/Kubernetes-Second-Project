#!/usr/bin/env python3
import os, time, json, uuid, random, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVICE = os.environ.get("SERVICE_NAME", "service")
NEXT_URL = os.environ.get("NEXT_URL", "")
FAILURE_MODE = os.environ.get("FAILURE_MODE", "none")
PORT = int(os.environ.get("PORT", "8080"))
DELAY_MS = int(os.environ.get("DELAY_MS", "0"))
SECRET_VALUE = os.environ.get("LAB_SECRET", "lab-secret")
CONFIG_VALUE = os.environ.get("LAB_CONFIG", "configured")

def log(level, event, **fields):
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "level": level,
        "service": SERVICE,
        "event": event,
        **fields,
    }
    print(" ".join(f"{k}={json.dumps(str(v))}" for k,v in record.items()), flush=True)

def call_next(payload):
    if not NEXT_URL:
        return {"ok": True, "service": SERVICE}
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        NEXT_URL, data=body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        log("ERROR", "downstream_call_failed", error=str(e), **payload)
        return {"ok": False, "error": str(e)}

def process(payload):
    if FAILURE_MODE == "timeout":
        log("ERROR", "injected_timeout", **payload)
        time.sleep(8)
        return {"ok": False, "error": "injected_timeout"}
    if FAILURE_MODE == "500":
        log("ERROR", "injected_http_500", **payload)
        return {"ok": False, "error": "injected_http_500"}
    if FAILURE_MODE == "404":
        log("ERROR", "injected_record_not_found", **payload)
        return {"ok": False, "error": "record_not_found"}
    if FAILURE_MODE == "slow":
        log("WARN", "injected_slow_dependency", **payload)
        time.sleep(3)
    if DELAY_MS:
        time.sleep(DELAY_MS / 1000)

    if SERVICE == "customer-service":
        national_id = payload.get("national_id", "784512345678")
        flow_id = "FLOW-" + uuid.uuid4().hex[:8]
        log("INFO", "customer_received", national_id=national_id, flow_id=flow_id)
        return call_next({"national_id": national_id, "flow_id": flow_id})

    if SERVICE == "session-service":
        session_id = "SES-" + uuid.uuid4().hex[:8]
        log("INFO", "session_created", **payload, session_id=session_id)
        return call_next({**payload, "session_id": session_id})

    if SERVICE == "attestation-service":
        attestation_id = "ATT-" + uuid.uuid4().hex[:8]
        log("INFO", "attestation_created", **payload, attestation_id=attestation_id)
        return call_next({**payload, "attestation_id": attestation_id})

    if SERVICE == "legacy-service":
        original_id = "ORG-" + uuid.uuid4().hex[:8]
        log("INFO", "legacy_record_found", **payload, original_id=original_id)
        return call_next({**payload, "original_id": original_id})

    if SERVICE == "payment-service":
        log("INFO", "payment_processed", **payload, secret_loaded=bool(SECRET_VALUE), config_loaded=bool(CONFIG_VALUE))
        return {"ok": True, "service": SERVICE, **payload}

    return {"ok": True, **payload}

class Handler(BaseHTTPRequestHandler):
    def _reply(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/health":
            self._reply(200, {"status": "ok", "service": SERVICE})
        elif self.path == "/ready":
            if FAILURE_MODE == "readiness":
                self._reply(503, {"status": "not_ready", "service": SERVICE})
            else:
                self._reply(200, {"status": "ready", "service": SERVICE})
        else:
            self._reply(200, {"service": SERVICE, "failure_mode": FAILURE_MODE})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            result = process(payload)
            if FAILURE_MODE == "500":
                self._reply(500, result)
            elif FAILURE_MODE == "404":
                self._reply(404, result)
            else:
                self._reply(200 if result.get("ok", True) else 502, result)
        except Exception as e:
            log("ERROR", "request_exception", error=str(e))
            self._reply(500, {"ok": False, "error": str(e)})

    def log_message(self, fmt, *args):
        return

log("INFO", "service_starting", port=PORT, failure_mode=FAILURE_MODE)
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
