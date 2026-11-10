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


def diag():
    """What is actually running and listening, and what the app itself logged."""
    import os
    import tempfile
    for cmd in (["tasklist", "/FI", "IMAGENAME eq autopatch-windows.exe"], ["netstat", "-ano"]):
        out = subprocess.run(cmd, capture_output=True, text=True).stdout
        lines = [l for l in out.splitlines() if "autopatch" in l.lower() or ":876" in l]
        print("DIAG", cmd[0], "->", lines or "nothing relevant")
    log = os.path.join(tempfile.gettempdir(), "autopatch-windows.log")
    print("DIAG app log:", open(log, encoding="utf-8").read() if os.path.exists(log) else "no log file")


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
        with urllib.request.urlopen(req, timeout=30) as r:
            assert json.loads(r.read())["asked"] is True
        t0 = time.time()
        while time.time() - t0 < 360:  # Windows can take minutes to start the elevated copy
            elevation = json.loads(get(8765, "/api/state")[1]).get("elevation")
            if elevation in ("started", "declined"):
                break
            time.sleep(3)
        print("elevation outcome:", elevation, "after", round(time.time() - t0), "s")
        assert elevation == "started", "Windows did not start the elevated instance: %s" % elevation
        try:
            st2 = wait_state(8766, 300)
        except SystemExit:
            diag()
            raise
        assert not st2.get("error"), st2.get("error")
        print("ELEVATED instance: admin =", st2["admin"], "| score:", st2["view"]["score"])
        for c in st2["view"]["checks"]:
            print("  %-8s %-40s %s" % (c["state"], c["title"], c["detail"]))
        assert st2["admin"] is True, "second instance is not elevated"
        print("ELEVATION OK")
finally:
    subprocess.run(["taskkill", "/F", "/IM", "autopatch-windows.exe", "/T"], capture_output=True)
