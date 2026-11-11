"""Local enrolment wizard tests. All requests use fake inventory; no PC is enrolled."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/"windows"))
import enrolment
import server

DEVICE="windows-test123"
HOST="OWNER-TEST-PC"

def inv():
    return {"device_id":DEVICE,"device_class":"windows","hostname":HOST,
            "collected_utc":"2026-11-11T00:00:00Z","os":"Windows 11",
            "kernel":"26000","patch_level":"KBTEST","packages_total":0,
            "security_updates_pending":1,"updates_pending_total":2,
            "reboot_required":False,"disk_free_gb":50.0,"agent_version":"1.0"}

def receipt():
    return {"device_id":DEVICE,"device_class":"windows","hostname":HOST,
            "status":"enrolled_readonly","permissions":["inventory_read"],
            "remote_control":False,"auto_patch":False,
            "enrolled_utc":datetime.now(timezone.utc).isoformat()}

class EnrolmentTests(unittest.TestCase):
    def setUp(self):
        self.dir=tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.file=Path(self.dir.name)/"private"/"enrolment.json"
        self.collect_calls=[]
        def collect(d):
            self.collect_calls.append(d)
            return inv()
        self.e=enrolment.LocalEnrolment(DEVICE,collect,hostname=HOST,store=self.file)

    def test_default_state_is_not_enrolled(self):
        self.assertEqual(self.e.state()["status"],"NOT_ENROLLED")
        self.assertFalse(self.file.exists())
        self.assertFalse(self.e.state()["patching_enabled"])

    def test_prepare_requires_confirmation_and_never_enrols(self):
        with self.assertRaises(enrolment.EnrolmentError):
            self.e.prepare({"confirmed_personal":False})
        self.assertEqual(self.collect_calls,[])
        result=self.e.prepare({"confirmed_personal":True})
        self.assertEqual(result["inventory"]["device_id"],DEVICE)
        self.assertEqual(self.collect_calls,[DEVICE])
        self.assertNotIn("updates_pending_total",result["inventory"])
        self.assertEqual(self.e.state()["status"],"NOT_ENROLLED")
        self.assertFalse(self.file.exists())

    def test_import_read_only_receipt_persists_but_never_enables_patch(self):
        result=self.e.import_receipt({"confirmed_personal":True,"receipt":receipt()})
        self.assertEqual(result["status"],"LOCAL_RECEIPT_IMPORTED")
        self.assertFalse(result["patching_enabled"])
        self.assertFalse(result["approval_verified"])
        saved=json.loads(self.file.read_text(encoding="utf8"))
        self.assertEqual(saved["permissions"],["inventory_read"])
        self.assertNotIn("token",saved)
        self.assertEqual(self.e.state()["status"],"LOCAL_RECEIPT_IMPORTED")

    def test_rejects_bad_approval_and_other_devices(self):
        for k,v in (("device_id","somebody-elses-machine"),("hostname","not-this-host"),
                    ("auto_patch",True),("remote_control",True),
                    ("permissions",["shell"]),("status","admin")):
            r=receipt();r[k]=v
            with self.subTest(k=k),self.assertRaises(enrolment.EnrolmentError):
                self.e.import_receipt({"confirmed_personal":True,"receipt":r})
        r=receipt();r["secret"]="bad"
        with self.assertRaises(enrolment.EnrolmentError):
            self.e.import_receipt({"confirmed_personal":True,"receipt":r})
        self.assertFalse(self.file.exists())

    def test_timestamp_expiry_and_missing_ownership(self):
        r=receipt();r["enrolled_utc"]=(datetime.now(timezone.utc)-timedelta(days=400)).isoformat()
        with self.assertRaises(enrolment.EnrolmentError):
            self.e.import_receipt({"confirmed_personal":True,"receipt":r})
        with self.assertRaises(enrolment.EnrolmentError):
            self.e.import_receipt({"confirmed_personal":False,"receipt":receipt()})
        self.assertFalse(self.file.exists())

    def test_tampered_disk_record_never_appears_enrolled(self):
        self.file.parent.mkdir(parents=True,exist_ok=True)
        r=receipt();r["hostname"]="WRONG"
        self.file.write_text(json.dumps(r),encoding="utf8")
        self.assertEqual(self.e.state()["status"],"NOT_ENROLLED")

class ServerEnrolmentTests(unittest.TestCase):
    def setUp(self):
        self.dir=tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        owner=enrolment.LocalEnrolment(DEVICE,lambda d:inv(),hostname=HOST,
                                     store=Path(self.dir.name)/"approval.json")
        class FakeScan:
            status={"schema_version":1}
            def state(self):return {"view":None}
        # Explicitly allocate port for server's security origin guards.
        sock=socket.socket()
        sock.bind(("127.0.0.1",0))
        port=sock.getsockname()[1]
        sock.close()
        self.port=port
        self.srv=server.serve(FakeScan(),port,"<h1>AutoPatch wizard</h1>",on_enrol=owner)
        self.thread=threading.Thread(target=self.srv.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def request(self,path,payload=None,origin=True,site="same-origin"):
        headers={}
        if payload is not None:
            headers["Content-Type"]="application/json"
            if origin:headers["Origin"]=f"http://127.0.0.1:{self.port}"
            headers["Sec-Fetch-Site"]=site
        req=Request(f"http://127.0.0.1:{self.port}{path}",
                    data=None if payload is None else json.dumps(payload).encode(),
                    headers=headers,method="GET" if payload is None else "POST")
        try:
            with urlopen(req,timeout=10) as resp:
                return resp.status,json.loads(resp.read()) if path.startswith("/api") else resp.read()
        except HTTPError as exc:
            return exc.code,json.loads(exc.read())

    def test_wizard_state_get_is_read_only(self):
        status,body=self.request("/api/enrol")
        self.assertEqual(status,200)
        self.assertEqual(body["status"],"NOT_ENROLLED")
        self.assertFalse(body["patching_enabled"])

    def test_cross_site_no_origin_and_unconfirmed_requests_rejected(self):
        body={"confirmed_personal":True}
        self.assertEqual(self.request("/api/enrol/request",body,origin=False)[0],403)
        self.assertEqual(self.request("/api/enrol/request",body,site="cross-site")[0],403)
        self.assertEqual(self.request("/api/enrol/request",{"confirmed_personal":False})[0],422)

    def test_owner_request_and_import_work_with_valid_file(self):
        self.assertEqual(self.request("/api/enrol/request",{"confirmed_personal":True})[0],200)
        status,body=self.request("/api/enrol/import",{"confirmed_personal":True,"receipt":receipt()})
        self.assertEqual(status,200)
        self.assertEqual(body["status"],"LOCAL_RECEIPT_IMPORTED")
        status,body=self.request("/api/enrol")
        self.assertEqual(body["status"],"LOCAL_RECEIPT_IMPORTED")
        self.assertFalse(body["patching_enabled"])

    def test_unknown_paths_are_not_index_page(self):
        self.assertEqual(self.request("/api/enrol/something")[0],404)

if __name__=="__main__":unittest.main()
