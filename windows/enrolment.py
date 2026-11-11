"""Owner-initiated, read-only Windows enrolment for the existing local AutoPatch UI.

The phone authority remains the source of truth. This client NEVER enrols itself
in that authority. It prepares the inventory for owner approval, and stores a
locally imported read-only receipt. No remote service, auto patch, restart, or
privilege change. Imported receipts are not cryptographically authenticated.
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
        }
        try:
            receipt = json.loads(self.store.read_text(encoding="utf-8"))
            self.validate_receipt(receipt)
        except (OSError, ValueError, TypeError):
            return base
        return dict(base, status="LOCAL_RECEIPT_IMPORTED", enrolled_utc=receipt["enrolled_utc"])

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
        self.store.parent.mkdir(parents=True, exist_ok=True)
        tmp: Path | None = None
        try:
            # User-local storage only; Windows profile ACL applies. No phone key,
            # token or entire fleet registry is copied to this computer.
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.store.parent,
                prefix="autopatch-approval-", suffix=".tmp", delete=False,
            ) as handle:
                tmp = Path(handle.name)
                json.dump(receipt, handle, sort_keys=True)
                handle.write("\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.store)
        finally:
            if tmp is not None and tmp.exists():
                tmp.unlink()
        return self.state()
