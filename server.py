"""Shared local web server for the AutoPatch apps (Windows and Linux): loopback only.

Routes: GET / (the page), GET /api/state (progress and results), GET /status.json (shared status document),
POST /api/elevate (only if the app supplies a handler, and only from its own page).
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def make_log(filename):
    """Return log(message) writing to a small file in the temp folder. Never raises."""
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
    """Only the page this server itself serves may ask for elevation, never another website."""
    host_ok = headers.get("Host") in ("127.0.0.1:%d" % port, "localhost:%d" % port)
    site = headers.get("Sec-Fetch-Site")
    return host_ok and site in (None, "same-origin")


def serve(scan, port, page_html, on_elevate=None):
    """Bind 127.0.0.1:port and return the server (caller runs serve_forever). Raises OSError if the port is taken."""
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/api/state":
                body, kind = json.dumps(scan.state()).encode(), "application/json"
            elif self.path == "/status.json":
                body, kind = json.dumps(getattr(scan, "status", {})).encode(), "application/json"
            else:
                body, kind = page_html.encode(), "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path != "/api/elevate" or on_elevate is None or not same_origin(self.headers, port):
                self.send_response(403)
                self.end_headers()
                return
            try:
                ok = bool(on_elevate(port))
            except (AttributeError, OSError):
                ok = False
            body = json.dumps({"started": ok}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    return HTTPServer(("127.0.0.1", port), H)
