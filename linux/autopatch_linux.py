#!/usr/bin/env python3
"""AutoPatch for Linux (Fedora first): read-only local status page on http://127.0.0.1:8765.

Reads update and security state, asks the update gate whether an automatic update would be allowed, and
changes nothing. dnf stays the only thing that patches.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import socket
import sys
import threading
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
for p in (HERE, HERE.parent, HERE.parent / "windows"):
    sys.path.insert(0, str(p))
import device_status  # noqa: E402
import os_update_gate  # noqa: E402
import probe  # noqa: E402
import server  # noqa: E402
import ui  # noqa: E402

BASE_VERSION = "0.1"
try:
    from _version import BUILD  # written by the release workflow
except ImportError:
    BUILD = "dev build"
VERSION = "%s (%s)" % (BASE_VERSION, BUILD)
log = server.make_log("autopatch-linux.log")


class Scan:
    STEPS = ["Reading update status (this can take a minute)", "Checking security settings",
             "Checking whether your other work is running", "Working out your score"]

    def __init__(self, device_id, run=probe.run_cmd, read=probe.read_text, offline=False):
        self.device_id, self.run, self.read, self.offline = device_id, run, read, offline
        self.step, self.error, self.view, self.warnings = 0, None, None, []
        self.current, self.history = None, []

    def progress(self, kind, label, cmd, rc, seconds):
        """Live view of what the scan is doing: one command at a time, never any command output."""
        if kind == "start":
            self.current = {"label": label, "cmd": " ".join(cmd), "began": time.monotonic()}
            log("start  %s  [%s]" % (label, " ".join(cmd)))
        else:
            self.history.append({"label": label, "rc": rc, "seconds": seconds})
            self.history = self.history[-14:]
            self.current = None
            log("done   %s  rc=%s  %ss" % (label, rc, seconds))

    def state(self):
        return {"product": "AutoPatch for Linux", "version": VERSION, "admin": probe.os.geteuid() == 0 if hasattr(probe.os, "geteuid") else False,
                "can_elevate": False,
                "steps": [{"name": n, "state": "done" if i < self.step else "on" if i == self.step else "todo"} for i, n in enumerate(self.STEPS)],
                "error": self.error, "view": self.view, "warnings": self.warnings,
                "current": ({"label": self.current["label"], "cmd": self.current["cmd"],
                             "seconds": round(time.monotonic() - self.current["began"])} if self.current else None),
                "history": self.history, "log_file": str(log.path)}

    def work(self):
        try:
            raw = probe.collect(self.run, self.read, progress=self.progress, offline=self.offline)
            self.step = 1
            checks = probe.to_checks(raw)
            self.step = 2
            rc, out = self.run(["ps", "-eo", "comm"])
            procs = [n for n in os_update_gate.BLOCKING_PROCESSES if n in (out or "").lower()] if rc == 0 else []
            self.step = 3
            inv = {"hostname": raw["hostname"], "os": raw["os_name"], "patch_level": raw["kernel"]}
            gate = os_update_gate.check({
                "device": raw["hostname"], "os": "linux", "enrolled": False, "mechanism": "dnf_automatic",
                "update_kind": "security", "precheck_ok": (raw.get("disk_free_gb") or 0) >= probe.MIN_FREE_GB,
                "running_processes": procs, "requires_reboot": bool(raw.get("reboot_required")),
                "in_maintenance_window": False, "backup_taken": False, "rollback_plan": "",
            })
            n = raw.get("security_updates")
            status = {
                "schema_version": 1,
                "device": {"id": self.device_id, "class": "linux", "label": str(raw["hostname"])[:40]},
                "collected_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "os": {"name": str(raw["os_name"]), "patch_level": str(raw["kernel"])},
                "updates": {"pending_security": n if isinstance(n, int) else None, "reboot_required": bool(raw.get("reboot_required"))},
                "checks": checks, "findings": [], "gate": {"decision": gate["decision"], "reasons": gate["reasons"]},
                "agent_version": "linux-" + BASE_VERSION,
            }
            problems = device_status.validate(status)
            if problems:
                raise RuntimeError("status failed its own contract: " + "; ".join(problems))
            self.status = status
            self.view = ui.view(status, device_status.score(status), inv, gate, probe.TITLES, probe.UNKNOWN_HINT)
            self.step = len(self.STEPS)
        except Exception as exc:  # shown on the page: a silent failure is the thing to avoid
            log("scan failed: %r" % exc)
            self.error = "%s: %s" % (type(exc).__name__, str(exc)[:300])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--device-id", default=None)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--offline", action="store_true", help="never refresh package lists over the network (uses the local cache only)")
    a = ap.parse_args(argv)
    device_id = a.device_id or "linux-" + hashlib.sha1(socket.gethostname().encode()).hexdigest()[:8]
    scan = Scan(device_id, offline=a.offline)
    try:
        srv = server.serve(scan, a.port, ui.page("dnf"))
    except OSError as exc:
        log("cannot listen on port %d: %s" % (a.port, exc))
        print("Could not start: port %d is already in use. Close the other AutoPatch and try again." % a.port)
        return 1
    url = "http://127.0.0.1:%d" % a.port
    print("AutoPatch for Linux  version %s" % VERSION)
    print("--------------------------------------------")
    print("Open %s if your browser does not open by itself." % url)
    print("It only reads information and changes nothing. Press Ctrl+C to stop.")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=scan.work, daemon=True).start()
    if not a.no_browser:
        def open_browser():
            try:
                webbrowser.open(url)
            except Exception as exc:
                log("browser did not open: %s" % exc)
        threading.Thread(target=open_browser, daemon=True).start()
    log("listening on %s version=%s" % (url, VERSION))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
