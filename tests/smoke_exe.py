"""End-to-end smoke test of the BUILT exe on real Windows (CI).

Launches the exe, waits for the scan to finish through the same HTTP API the page uses, then asks for
elevation exactly like the page's button and checks that an elevated second instance answers.
Usage: python tests/smoke_exe.py <exe> [elevation]   (the elevation step is reported, and gates only when asked)
"""
import json
import subprocess
import sys
import time
import urllib.request

EXE = sys.argv[1]
CHECK_ELEVATION = len(sys.argv) > 2 and sys.argv[2] == "elevation"


def get(port, path, timeout=10):
    with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=timeout) as r:
        return r.status, r.read()


def wait_state(port, limit, want_done=True):
    end = time.time() + limit
    last = None
    while time.time() < end:
        try:
            _, body = get(port, "/api/state")
            last = json.loads(body)
            if last.get("error") or last.get("view"):
                return last
        except Exception as exc:  # server not up yet
            last = {"waiting": str(exc)}
        time.sleep(3)
    raise SystemExit("TIMEOUT waiting for scan on port %d; last state: %s" % (port, json.dumps(last)[:500]))


proc = subprocess.Popen([EXE], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
try:
    st = wait_state(8765, 600)
    if st.get("error"):
        raise SystemExit("SCAN ERROR: " + st["error"])
    assert "0.3" in st["version"], st["version"]
    view = st["view"]
    checks = {c["title"]: c["state"] for c in view["checks"]}
    print("version:", st["version"], "| admin:", st["admin"], "| score:", view["score"], "| warnings:", st["warnings"])
    for title, state in checks.items():
        print("  %-8s %s" % (state, title))
    assert len(checks) >= 11, "expected at least 11 checks, got %d" % len(checks)
    status, page = get(8765, "/")
    assert status == 200 and b"AutoPatch" in page
    status, body = get(8765, "/status.json")
    assert json.loads(body).get("schema_version") == 1
    print("SMOKE OK: exe starts, scans, serves the page and the shared status document")

    if CHECK_ELEVATION:
        req = urllib.request.Request("http://127.0.0.1:8765/api/elevate", method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            started = json.loads(r.read())["started"]
        print("elevation request accepted by Windows:", started)
        assert started, "ShellExecute runas did not start the elevated instance"
        st2 = wait_state(8766, 240)
        assert not st2.get("error"), st2.get("error")
        print("ELEVATED instance: admin =", st2["admin"], "| score:", st2["view"]["score"])
        for c in st2["view"]["checks"]:
            print("  %-8s %-40s %s" % (c["state"], c["title"], c["detail"]))
        assert st2["admin"] is True, "second instance is not elevated"
        print("ELEVATION OK")
finally:
    subprocess.run(["taskkill", "/F", "/IM", "autopatch-windows.exe", "/T"], capture_output=True)
