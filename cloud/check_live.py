"""Read-only smoke check of deployed AutoPatch Cloud.

Makes no registration, patch, or write calls.
"""
import json
from urllib.request import urlopen, Request
from urllib.error import HTTPError

BASE="https://autopatch-cloud-enrolment.parris-neathaustralia.workers.dev"
HEADERS={"User-Agent":"AutoPatchCloudHealth/1.0 (+https://github.com/Parris-Tech-Services/autopatch-windows)"}
try:
    with urlopen(Request(BASE+"/healthz",headers=HEADERS),timeout=20) as response:
        assert response.status==200
        health=json.load(response)
except HTTPError as exc:
    print("Cloud HTTP status:",exc.code,"server:",exc.headers.get("Server"),
          "ray:",exc.headers.get("CF-Ray"),"body:",exc.read(600).decode("utf8","replace"))
    raise
assert health["status"]=="ok",health
assert health["service"]=="autopatch-cloud",health
assert health["patching_enabled"] is False,health
try:
    urlopen(Request(BASE+"/v1/devices",headers=HEADERS),timeout=20)
    raise AssertionError("Public fleet list must be forbidden")
except HTTPError as exc:
    assert exc.code==403,f"Unexpected fleet-list status {exc.code}"
    exc.close()
print("CLOUD VERIFIED: HTTPS healthy, patching disabled, anonymous fleet list denied.")
