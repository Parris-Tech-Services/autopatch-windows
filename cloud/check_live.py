"""Read-only smoke check of deployed AutoPatch Cloud.

Makes no registration, patch, or write calls.
"""
import json
from urllib.request import urlopen
from urllib.error import HTTPError

BASE="https://autopatch-cloud-enrolment.parris-neathaustralia.workers.dev"
try:
    with urlopen(BASE+"/healthz",timeout=20) as response:
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
    urlopen(BASE+"/v1/devices",timeout=20)
    raise AssertionError("Public fleet list must be forbidden")
except HTTPError as exc:
    assert exc.code==403,f"Unexpected fleet-list status {exc.code}"
    exc.close()
print("CLOUD VERIFIED: HTTPS healthy, patching disabled, anonymous fleet list denied.")
