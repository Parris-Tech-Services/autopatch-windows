#!/usr/bin/env python3
"""AutoPatch for Windows: read-only local status app.

Collects the device inventory with the existing read-only PowerShell agent, checks the OS update gate, and
shows the result on http://127.0.0.1:<port> (loopback only). It applies nothing: Windows Update remains the
only patcher. The gate DENIES until a verified restore point, maintenance window and rollback plan are
supplied, so a fresh install never claims an update is safe.
"""
from __future__ import annotations

import argparse
import html
import json
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import device_status  # noqa: E402
import os_update_gate  # noqa: E402
import posture  # noqa: E402



def resource(frozen_name, source_path):
    """PyInstaller unpacks bundled files under sys._MEIPASS; from source they sit in the repo."""
    base = getattr(sys, "_MEIPASS", None)
    return Path(base) / frozen_name if base else source_path


AGENT = resource("devices/agent-windows.ps1", ROOT / "devices" / "agent-windows.ps1")
POSTURE = resource("posture.ps1", Path(__file__).resolve().parent / "posture.ps1")
MIN_FREE_GB = 10.0


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)


def collect_inventory(device_id, run=_run):
    out = Path(tempfile.mkdtemp()) / "inventory.json"
    r = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(AGENT),
             "-DeviceId", device_id, "-OutFile", str(out)])
    if r.returncode != 0 or not out.exists():
        raise RuntimeError("inventory agent failed: " + (r.stderr or "no output")[:200])
    return json.loads(out.read_text(encoding="utf-8-sig"))


def collect_posture(run=_run):
    """Raw posture probe. A failed or unparsable probe returns {} so every check reads as unknown."""
    r = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(POSTURE)])
    try:
        return json.loads(r.stdout) if r.returncode == 0 else {}
    except ValueError:
        return {}


def build_status(inv, raw_posture, gate, device_id, when):
    """Shared-contract status document (device_status.py v1)."""
    doc = {
        "schema_version": 1,
        "device": {"id": device_id, "class": "windows", "label": str(inv.get("hostname") or "")[:40]},
        "collected_utc": when,
        "os": {"name": str(inv.get("os") or ""), "patch_level": str(inv.get("patch_level") or "")},
        "updates": {"pending_security": inv.get("security_updates_pending") if isinstance(inv.get("security_updates_pending"), int) else None,
                    "reboot_required": bool(inv.get("reboot_required"))},
        "checks": posture.to_checks(raw_posture),
        "findings": [],
        "gate": {"decision": gate["decision"], "reasons": gate["reasons"]},
        "agent_version": "windows-0.2",
    }
    return doc


def running_processes(run=_run):
    names = (run(["tasklist", "/fo", "csv", "/nh"]).stdout or "").lower()
    return [p for p in os_update_gate.BLOCKING_PROCESSES if p in names]


def assess(inv, procs, extra=None):
    """Build the gate request from facts the app can see; unverifiable facts stay False/absent (= DENY)."""
    req = {
        "device": inv.get("hostname"), "os": "windows", "enrolled": False,
        "mechanism": "windows_update", "update_kind": "security",
        "precheck_ok": float(inv.get("disk_free_gb") or 0) >= MIN_FREE_GB,
        "running_processes": procs, "requires_reboot": bool(inv.get("reboot_required")),
        "in_maintenance_window": False, "backup_taken": False, "rollback_plan": "",
    }
    req.update(extra or {})
    return {"inventory": inv, "gate": os_update_gate.check(req)}


def checks_html(result):
    cs = (result.get("status") or {}).get("checks", [])
    return "".join("<li>%s: <b>%s</b> (%s)</li>" % (html.escape(c["id"]), html.escape(c["state"]), html.escape(c["detail"])) for c in cs)


def render(result):
    inv, gate = result["inventory"], result["gate"]
    rows = "".join("<li>%s</li>" % html.escape(r) for r in gate["reasons"])
    return ("<!doctype html><meta charset=utf-8><title>AutoPatch</title><body style='font:16px system-ui;max-width:36rem;margin:2rem auto'>"
            "<h1>AutoPatch: %s</h1><p>%s &middot; patch %s &middot; %s security updates pending &middot; reboot needed: %s</p>"
            "<h2>Posture score: %s</h2><ul>%s</ul><h2>Safe to auto-apply now? %s</h2><ul>%s</ul><p><small>Read-only. Windows Update does the patching.</small></p>"
            % (html.escape(str(inv.get("hostname"))), html.escape(str(inv.get("os"))), html.escape(str(inv.get("patch_level"))),
               html.escape(str(inv.get("security_updates_pending"))), inv.get("reboot_required"),
               html.escape(str(result.get("score", "not measured"))), checks_html(result),
               html.escape(gate["decision"]), rows))


def serve(result, port):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = (json.dumps(result) if self.path == "/status.json" else render(result)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json" if self.path == "/status.json" else "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a):
            pass
    HTTPServer(("127.0.0.1", port), H).serve_forever()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--device-id", default=None, help="default: windows-<hash of this PC name>")
    p.add_argument("--port", type=int, default=8765)
    a = p.parse_args(argv)
    if not a.device_id:
        import hashlib
        import socket
        a.device_id = "windows-" + hashlib.sha1(socket.gethostname().encode()).hexdigest()[:8]
    result = assess(collect_inventory(a.device_id), running_processes())
    from datetime import datetime, timezone
    status = build_status(result["inventory"], collect_posture(), result["gate"], a.device_id,
                          datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    problems = device_status.validate(status)
    if problems:
        raise SystemExit("status failed its own contract: " + "; ".join(problems))
    result["status"], result["score"] = status, device_status.score(status)
    import webbrowser
    print("Open http://127.0.0.1:%d (opening your browser; Ctrl+C to stop)" % a.port)
    webbrowser.open("http://127.0.0.1:%d" % a.port)
    serve(result, a.port)


if __name__ == "__main__":
    main()
