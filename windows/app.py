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
import ui  # noqa: E402



def resource(frozen_name, source_path):
    """PyInstaller unpacks bundled files under sys._MEIPASS; from source they sit in the repo."""
    base = getattr(sys, "_MEIPASS", None)
    return Path(base) / frozen_name if base else source_path


AGENT = resource("devices/agent-windows.ps1", ROOT / "devices" / "agent-windows.ps1")
POSTURE = resource("posture.ps1", Path(__file__).resolve().parent / "posture.ps1")
MIN_FREE_GB = 10.0
BASE_VERSION = "0.3.2"
try:
    from _version import BUILD  # written by the release workflow: "<short commit> <UTC time>"
except ImportError:
    BUILD = "dev build"
VERSION = "%s (%s)" % (BASE_VERSION, BUILD)


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)


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


import server  # noqa: E402

log = server.make_log("autopatch-windows.log")
LOG = log.path


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


same_origin = server.same_origin


def elevation_command(frozen, exe, script, port):
    """(program, parameters) to relaunch this app with admin rights on the next port."""
    args = "--port %d" % (port + 1)
    return (exe, args) if frozen else (exe, '"%s" %s' % (script, args))


def launch_elevated(port):
    import ctypes
    prog, params = elevation_command(bool(getattr(sys, "frozen", False)), sys.executable, str(Path(__file__).resolve()), port)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", prog, params, None, 1)
    return rc > 32  # <= 32 means the user declined the prompt or Windows refused


class Scan:
    """Runs the read-only scan in a background thread so the page can open immediately and show progress."""

    STEPS = ["Reading Windows Update status", "Checking security settings", "Checking whether your other work is running", "Working out your score"]

    def __init__(self, device_id, run=_run):
        self.device_id, self.run = device_id, run
        self.step, self.error, self.view = 0, None, None
        self.warnings = []

    def state(self):
        return {"product": "AutoPatch for Windows", "version": VERSION, "admin": is_admin(), "can_elevate": True, "steps": [{"name": n, "state": "done" if i < self.step else "on" if i == self.step else "todo"}
                          for i, n in enumerate(self.STEPS)], "error": self.error, "view": self.view,
                "warnings": self.warnings}

    def work(self):
        from datetime import datetime, timezone
        import socket
        try:
            try:
                inv = collect_inventory(self.device_id, self.run)
            except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
                self.warnings.append("Windows Update status unavailable: %s" % exc)
                inv = {"hostname": socket.gethostname()}
            self.step = 1
            raw = collect_posture(self.run)
            self.step = 2
            procs = running_processes(self.run)
            self.step = 3
            result = assess(inv, procs)
            status = build_status(result["inventory"], raw, result["gate"], self.device_id,
                                  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
            problems = device_status.validate(status)
            if problems:
                raise RuntimeError("status failed its own contract: " + "; ".join(problems))
            self.status = status
            self.view = ui.view(status, device_status.score(status), result["inventory"], result["gate"])
            self.step = len(self.STEPS)
        except Exception as exc:  # shown on the page; a silent black window is the failure to avoid
            self.error = "%s: %s" % (type(exc).__name__, str(exc)[:300])


def serve(scan, port):
    return server.serve(scan, port, ui.page("Windows Update"), launch_elevated)


def main(argv=None):
    import hashlib
    import socket
    import threading
    import time
    import webbrowser
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--device-id", default=None, help="default: windows-<hash of this PC name>")
    p.add_argument("--port", type=int, default=8765)
    a = p.parse_args(argv)
    device_id = a.device_id or "windows-" + hashlib.sha1(socket.gethostname().encode()).hexdigest()[:8]
    scan = Scan(device_id)
    log("start version=%s port=%d admin=%s device=%s" % (VERSION, a.port, is_admin(), device_id))
    try:
        server = serve(scan, a.port)
    except OSError as exc:
        log("cannot listen on port %d: %s" % (a.port, exc))
        print("Could not start: port %d is already in use. Close the other AutoPatch window and try again." % a.port)
        input("Press Enter to close.")
        return
    url = "http://127.0.0.1:%d" % a.port
    print("AutoPatch for Windows  version %s" % VERSION)
    print("--------------------------------------------")
    print("Opening %s in your browser. The scan runs there and can take a minute or two." % url)
    print("It only reads information and changes nothing. Close this window to stop.")
    # The server must be answering before anything else can go wrong, so it runs in its own thread
    # and neither the scan nor a slow browser launch can keep it from starting.
    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=scan.work, daemon=True).start()

    def open_browser():
        try:
            webbrowser.open(url)
        except Exception as exc:  # a browser that will not open must not stop the app
            log("browser did not open: %s" % exc)
    threading.Thread(target=open_browser, daemon=True).start()
    log("listening on %s" % url)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
