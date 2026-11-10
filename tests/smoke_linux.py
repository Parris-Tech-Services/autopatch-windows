"""End-to-end smoke test of the BUILT Linux app on a real Fedora system (CI container). Usage: smoke_linux.py <pyz>"""
import json
import subprocess
import sys
import time
import urllib.request

PYZ = sys.argv[1]
proc = subprocess.Popen([sys.executable, PYZ, "--no-browser", "--port", "8765"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def get(path):
    with urllib.request.urlopen("http://127.0.0.1:8765" + path, timeout=10) as r:
        return r.status, r.read()


try:
    state, end = None, time.time() + 900
    while time.time() < end:
        try:
            state = json.loads(get("/api/state")[1])
            if state.get("error") or state.get("view"):
                break
        except Exception:
            pass
        time.sleep(3)
    else:
        raise SystemExit("TIMEOUT waiting for the scan; last state: %s" % json.dumps(state)[:500])
    if state["error"]:
        raise SystemExit("SCAN ERROR: " + state["error"])
    view = state["view"]
    print("version:", state["version"], "| admin:", state["admin"], "| score:", view["score"], "| gate:", view["gate"]["decision"])
    for c in view["checks"]:
        print("  %-8s %-34s %s" % (c["state"], c["title"], c["detail"]))
    assert len(view["checks"]) >= 9
    assert view["gate"]["decision"] == "DENY"  # nothing is enrolled, so it must never say ALLOW
    status, page = get("/")
    assert status == 200 and b"AutoPatch" in page
    assert json.loads(get("/status.json")[1])["schema_version"] == 1
    by_title = {c["title"]: c for c in view["checks"]}
    sec = by_title["Security updates installed"]
    print("security updates check:", sec["state"], "-", sec["detail"])
    assert "dnf not found" not in sec["detail"], "dnf must exist on a Fedora system"
    assert sec["state"] in ("pass", "fail"), "dnf is present, so the update check must give a real answer, not unknown"
    print("FEDORA SMOKE OK")
finally:
    proc.terminate()
