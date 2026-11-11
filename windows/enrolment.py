"""One-click local read-only opt-in for the Windows AutoPatch UI.

The owner can opt in locally with a single click, without a phone, file transfer
or command line. It stores only a local read-only acknowledgement in the user's
profile; it DOES NOT enrol the machine in any remote fleet or authorise patching.

An optional legacy phone-authority file workflow remains available to advanced
users. No remote service, unattended updates, restart or privilege change.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import re
import socket
import tempfile

DEVICE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
ALLOWED_INVENTORY = {
    "device_id", "device_class", "collected_utc", "hostname", "os", "kernel",
    "patch_level", "packages_total", "security_updates_pending",
    "reboot_required", "disk_free_gb", "agent_version",
}
ALLOWED_RECEIPT = {
    "device_id", "device_class", "hostname", "status", "permissions",
    "auto_patch", "remote_control", "enrolled_utc",
}
LOCAL_RECORD_FIELDS = {
    "schema_version", "kind", "device_id", "device_class", "hostname",
    "permissions", "auto_patch", "remote_control", "enrolled_utc",
}


class EnrolmentError(ValueError):
    pass


def storage_path() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        base = str(Path.home() / "AppData" / "Local")
    return Path(base) / "AutoPatch" / "enrolment.json"


def utc_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise EnrolmentError("Missing enrolment timestamp")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EnrolmentError("Invalid enrolment timestamp") from None
    if dt.tzinfo is None:
        raise EnrolmentError("Enrolment timestamp must include a timezone")
    return dt.astimezone(timezone.utc)


class LocalEnrolment:
    def __init__(self, device_id: str, collect_inventory, *, hostname: str | None = None,
                 store: Path | None = None):
        if not DEVICE_ID.fullmatch(device_id):
            raise EnrolmentError("Invalid device ID")
        self.device_id = device_id
        self.hostname = hostname if hostname is not None else socket.gethostname()
        self.collect_inventory = collect_inventory
        self.store = Path(store) if store is not None else storage_path()

    def state(self) -> dict:
        base = {
            "device_id": self.device_id, "device_class": "windows",
            "hostname": self.hostname, "status": "NOT_ENROLLED",
            "patching_enabled": False, "approval_verified": False,
            "fleet_connected": False, "monitoring_mode": "on_launch_only",
        }
        try:
            receipt = json.loads(self.store.read_text(encoding="utf-8"))
            if isinstance(receipt, dict) and receipt.get("kind") == "local_readonly":
                self.validate_local_record(receipt)
                return dict(base, status="ENROLLED_ON_THIS_PC", enrolled_utc=receipt["enrolled_utc"])
            self.validate_receipt(receipt)
            return dict(base, status="LOCAL_RECEIPT_IMPORTED", enrolled_utc=receipt["enrolled_utc"])
        except (OSError, ValueError, TypeError):
            return base

    def validate_local_record(self, record: dict) -> None:
        if not isinstance(record, dict) or set(record) != LOCAL_RECORD_FIELDS:
            raise EnrolmentError("Invalid local enrolment fields")
        if record["schema_version"] != 1 or record["kind"] != "local_readonly":
            raise EnrolmentError("Unsupported local enrolment format")
        if record["device_id"] != self.device_id or record["device_class"] != "windows":
            raise EnrolmentError("Local enrolment belongs to another computer")
        if not isinstance(record["hostname"], str) or record["hostname"].casefold() != self.hostname.casefold():
            raise EnrolmentError("Local enrolment hostname does not match")
        if (record["permissions"] != ["inventory_read"] or record["auto_patch"] is not False
                or record["remote_control"] is not False):
            raise EnrolmentError("Local enrolment cannot grant patching or remote access")
        if utc_time(record["enrolled_utc"]) > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise EnrolmentError("Local enrolment timestamp is in the future")

    def _save_record(self, record: dict) -> None:
        self.store.parent.mkdir(parents=True, exist_ok=True)
        tmp: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.store.parent,
                prefix="autopatch-enrol-", suffix=".tmp", delete=False,
            ) as handle:
                tmp = Path(handle.name)
                json.dump(record, handle, sort_keys=True)
                handle.write("\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.store)
        finally:
            if tmp is not None and tmp.exists():
                tmp.unlink()

    def enrol_local(self, payload: dict) -> dict:
        """One explicit local click; instant and independent of the slow Windows Update scan."""
        if not isinstance(payload, dict) or set(payload) != {"confirmed_personal"}:
            raise EnrolmentError("Invalid local enrolment request")
        if payload.get("confirmed_personal") is not True:
            raise EnrolmentError("Only enrol a personal PC you are authorised to manage")
        existing = self.state()
        if existing["status"] != "NOT_ENROLLED":
            return existing
        record = {
            "schema_version": 1, "kind": "local_readonly",
            "device_id": self.device_id, "device_class": "windows",
            "hostname": self.hostname, "permissions": ["inventory_read"],
            "auto_patch": False, "remote_control": False,
            "enrolled_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        self.validate_local_record(record)
        self._save_record(record)
        return self.state()

    def remove_local(self, payload: dict) -> dict:
        """Remove only this user's local record; cannot change the phone authority."""
        if not isinstance(payload, dict) or payload != {"confirmed_remove": True}:
            raise EnrolmentError("Explicit removal confirmation required")
        if self.state()["status"] == "NOT_ENROLLED":
            return self.state()
        self.store.unlink(missing_ok=True)
        return self.state()

    def prepare(self, payload: dict) -> dict:
        if not isinstance(payload, dict) or set(payload) != {"confirmed_personal"}:
            raise EnrolmentError("Invalid enrolment request")
        if payload.get("confirmed_personal") is not True:
            raise EnrolmentError("Confirm personal ownership before preparing an inventory")
        inventory = self.collect_inventory(self.device_id)
        if not isinstance(inventory, dict):
            raise EnrolmentError("Device inventory could not be collected")
        if (inventory.get("device_id") != self.device_id
                or inventory.get("device_class") != "windows"
                or str(inventory.get("hostname", "")).casefold() != self.hostname.casefold()):
            raise EnrolmentError("Inventory does not match this computer")
        if not isinstance(inventory.get("collected_utc"), str):
            raise EnrolmentError("Inventory has no collection timestamp")
        # The central authority strictly permits these fields only. The Windows
        # agent adds updates_pending_total for UI use: omit that extra field.
        selected = {k: inventory[k] for k in ALLOWED_INVENTORY if k in inventory}
        return {
            "filename": f"autopatch-{self.device_id}-inventory.json",
            "inventory": selected,
            "message": "Read-only inventory prepared. The trusted phone must approve it.",
        }

    def validate_receipt(self, receipt: dict) -> None:
        if not isinstance(receipt, dict) or set(receipt) != ALLOWED_RECEIPT:
            raise EnrolmentError("Invalid approval receipt fields")
        if receipt.get("device_id") != self.device_id or receipt.get("device_class") != "windows":
            raise EnrolmentError("Approval is for another device")
        if (not isinstance(receipt.get("hostname"), str)
                or receipt["hostname"].casefold() != self.hostname.casefold()):
            raise EnrolmentError("Approval hostname does not match this computer")
        if (receipt.get("status") != "enrolled_readonly"
                or receipt.get("permissions") != ["inventory_read"]
                or receipt.get("auto_patch") is not False
                or receipt.get("remote_control") is not False):
            raise EnrolmentError("Approval must grant read-only inventory access only")
        when = utc_time(receipt.get("enrolled_utc"))
        now = datetime.now(timezone.utc)
        if when > now + timedelta(minutes=5) or when < now - timedelta(days=365):
            raise EnrolmentError("Approval timestamp is in the future or too old")

    def import_receipt(self, payload: dict) -> dict:
        if not isinstance(payload, dict) or set(payload) != {"confirmed_personal", "receipt"}:
            raise EnrolmentError("Invalid approval request")
        if payload.get("confirmed_personal") is not True:
            raise EnrolmentError("Personal ownership confirmation required")
        receipt = payload.get("receipt")
        self.validate_receipt(receipt)
        # Import remains a local acknowledgement, not signed remote authority.
        self._save_record(receipt)
        return self.state()
