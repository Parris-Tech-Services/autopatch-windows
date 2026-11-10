"""Assemble the single-file Linux app (autopatch-linux.pyz) with the standard library zipapp. Run: python tools/build_pyz.py [out]"""
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [ROOT / "linux" / "probe.py", ROOT / "server.py", ROOT / "device_status.py", ROOT / "os_update_gate.py", ROOT / "windows" / "ui.py"]
out = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "dist" / "autopatch-linux.pyz")
with tempfile.TemporaryDirectory() as tmp:
    build = Path(tmp)
    for f in FILES:
        shutil.copy(f, build / f.name)
    shutil.copy(ROOT / "linux" / "autopatch_linux.py", build / "autopatch_linux.py")
    version = ROOT / "linux" / "_version.py"
    if version.exists():
        shutil.copy(version, build / "_version.py")
    (build / "__main__.py").write_text("import sys\nfrom autopatch_linux import main\nsys.exit(main())\n")
    out.parent.mkdir(parents=True, exist_ok=True)
    zipapp.create_archive(build, out, interpreter="/usr/bin/env python3")
print("built", out, out.stat().st_size, "bytes")
