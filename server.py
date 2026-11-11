"""Loopback-only status web server for Windows and Linux AutoPatch.

Windows may also expose an owner-initiated read-only enrollment wizard.
No API can patch, update, restart or grant itself remote access.
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def make_log(filename):
    path = Path(tempfile.gettempdir()) / filename
    def log(message):
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("%s %s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message))
        except OSError:
            pass
    log.path = path
    return log


def same_origin(headers, port):
    """Backward-compatible guard for the existing elevation action."""
    host_ok = headers.get("Host") in ("127.0.0.1:%d" % port, "localhost:%d" % port)
    return host_ok and headers.get("Sec-Fetch-Site") in (None, "same-origin")


def enrolment_origin_ok(headers, port):
    """For enrolment writes require an actual same-origin browser POST."""
    if not same_origin(headers, port):
        return False
    origin = headers.get("Origin")
    if origin not in ("http://127.0.0.1:%d" % port, "http://localhost:%d" % port):
        return False
    return headers.get("Content-Type", "").split(";")[0].strip().lower() == "application/json"


def serve(scan, port, page_html, on_elevate=None, on_enrol=None):
    """Bind exclusively to localhost and return a ThreadingHTTPServer."""
    class H(BaseHTTPRequestHandler):
        def reply(self, status, body, kind="application/json"):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, separators=(",", ":")).encode("utf-8")
            elif isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.headers.get("Host") not in (
                "127.0.0.1:%d" % port, "localhost:%d" % port,
            ):
                self.reply(403, {"error": "Local requests only"})
            elif self.path == "/api/state":
                self.reply(200, scan.state())
            elif self.path == "/status.json":
                self.reply(200, getattr(scan, "status", {}))
            elif self.path == "/api/enrol" and on_enrol is not None:
                self.reply(200, on_enrol.state())
            elif self.path in ("/", "/index.html"):
                self.reply(200, page_html, "text/html; charset=utf-8")
            else:
                self.reply(404, {"error": "Unknown path"})

        def do_POST(self):
            if self.path == "/api/elevate":
                if on_elevate is None or not same_origin(self.headers, port):
                    self.reply(403, {"error": "Forbidden"})
                    return
                scan.elevation = "asked"
                def ask():
                    try:
                        ok = bool(on_elevate(port))
                    except (AttributeError, OSError):
                        ok = False
                    scan.elevation = "started" if ok else "declined"
                threading.Thread(target=ask, daemon=True).start()
                self.reply(200, {"asked": True})
                return
            if self.path not in ("/api/enrol/request", "/api/enrol/import"):
                self.reply(404, {"error": "Unknown path"})
                return
            if on_enrol is None or not enrolment_origin_ok(self.headers, port):
                self.reply(403, {"error": "Only this app's own page can enrol devices"})
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if not 0 < length <= 16384:
                self.reply(413, {"error": "Request missing or too large"})
                return
            try:
                payload = json.loads(self.rfile.read(length))
                result = (on_enrol.prepare(payload) if self.path == "/api/enrol/request"
                          else on_enrol.import_receipt(payload))
            except (ValueError, TypeError, OSError, RuntimeError) as exc:
                self.reply(422, {"error": str(exc)[:200]})
                return
            self.reply(200, result)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.daemon_threads = True
    return srv
