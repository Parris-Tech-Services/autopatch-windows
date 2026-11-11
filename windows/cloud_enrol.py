"""AutoPatch Cloud's one-click Windows read-only registration client.

No user/phone keys, no remote commands, no app/OS patching, no scheduler.
The server gives an unverified device record, NOT fleet-owner approval.
Only a minimal device identity is transmitted after a user click.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import socket
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

CLOUD_BASE = "https://autopatch-cloud-enrolment.parris-neathaustralia.workers.dev"
DEVICE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
TOKEN = re.compile(r"^[A-Za-z0-9_-]{40,100}$")

class CloudError(ValueError):
    pass

def cloud_storage() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "AutoPatch" / "cloud-device.json"

def request_cloud(method: str, path: str, *, payload=None, device_id=None, credential=None):
    url = CLOUD_BASE + path
    headers = {"User-Agent": "AutoPatch-Windows-CloudEnrollment/1.0", "Accept": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if credential is not None:
        headers["Authorization"] = "Bearer " + credential
        headers["X-AutoPatch-Device-ID"] = device_id
    try:
        with urlopen(Request(url, data=data, headers=headers, method=method), timeout=15) as reply:
            raw = reply.read(4096)
            result = json.loads(raw)
    except HTTPError as exc:
        try:
            error = json.loads(exc.read(1024)).get("error", "Cloud registration rejected")
        except (ValueError, TypeError, OSError):
            error = "Cloud registration rejected"
        raise CloudError(str(error)[:160]) from None
    except (URLError, TimeoutError, OSError, ValueError):
        raise CloudError("Could not reach AutoPatch Cloud. Check your internet connection and try again.") from None
    if not isinstance(result, dict):
        raise CloudError("Cloud response was invalid")
    return result

class CloudEnrolment:
    def __init__(self, device_id: str, *, hostname: str | None = None,
                 store: Path | None = None, transport=request_cloud):
        if not DEVICE_ID.fullmatch(device_id):
            raise CloudError("Invalid local device ID")
        self.device_id = device_id
        self.hostname = hostname if hostname is not None else socket.gethostname()
        self.store = Path(store) if store is not None else cloud_storage()
        self.transport = transport

    def _read(self):
        try:
            record = json.loads(self.store.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None
        if (not isinstance(record, dict)
                or record.get("device_id") != self.device_id
                or record.get("hostname") != self.hostname
                or not TOKEN.fullmatch(str(record.get("credential","")))):
            return None
        if record.get("state") not in ("pending", "cloud_registered_unverified"):
            return None
        return record

    def _save(self, record):
        self.store.parent.mkdir(parents=True, exist_ok=True)
        temp = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                    dir=self.store.parent, prefix="cloud-", suffix=".tmp", delete=False) as handle:
                temp=Path(handle.name)
                json.dump(record, handle, sort_keys=True)
                handle.write("\n")
            os.chmod(temp, 0o600)
            os.replace(temp, self.store)
        finally:
            if temp is not None and temp.exists(): temp.unlink()

    def state(self):
        record = self._read()
        status = "NOT_CLOUD_REGISTERED"
        if record and record["state"] == "pending":
            status = "CLOUD_ENROLMENT_PENDING"
        elif record:
            status = "CLOUD_REGISTERED_UNVERIFIED"
        return {"device_id": self.device_id, "hostname": self.hostname,
                "status": status, "cloud_connected": status == "CLOUD_REGISTERED_UNVERIFIED",
                "owner_verified": False, "patching_enabled": False, "remote_control": False,
                "dashboard_url": CLOUD_BASE + "/",
                "last_registered_utc": record.get("registered_utc") if record else None}

    def enrol(self, payload: dict):
        if (not isinstance(payload, dict) or set(payload) != {"confirmed_personal"}
                or payload["confirmed_personal"] is not True):
            raise CloudError("You must explicitly confirm this is an authorised personal PC")
        if not HOST.fullmatch(self.hostname):
            raise CloudError("Computer hostname is invalid for cloud enrolment")
        record = self._read()
        if record and record["state"] == "cloud_registered_unverified":
            # Still require live proof. Never claim a stale local file means
            # the cloud is reachable or the device is still registered.
            check = self.transport("GET","/v1/device",device_id=self.device_id,
                                   credential=record["credential"])
            if check.get("status") != "CLOUD_REGISTERED_UNVERIFIED" or check.get("auto_patch") is not False:
                raise CloudError("Cloud enrolment is no longer active")
            return self.state()
        if not record:
            record={"device_id":self.device_id, "hostname":self.hostname,
                    "credential":secrets.token_urlsafe(32), "state":"pending"}
            self._save(record)
        response=self.transport("POST","/v1/enrol",payload={
            "device_id":self.device_id,"hostname":self.hostname,
            "device_class":"windows","credential":record["credential"]})
        if (response.get("device_id") != self.device_id or
                response.get("status") != "CLOUD_REGISTERED_UNVERIFIED" or
                response.get("owner_verified") is not False or
                response.get("auto_patch") is not False or
                response.get("remote_control") is not False):
            raise CloudError("Cloud did not confirm restricted read-only registration")
        record["state"]="cloud_registered_unverified"
        record["registered_utc"]=datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._save(record)
        return self.state()
