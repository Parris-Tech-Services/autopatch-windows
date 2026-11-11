"""Cloud enrolment unit tests: no real external calls, devices or secrets."""
from pathlib import Path
import json
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"windows"))
import cloud_enrol

ID="windows-test123"
HOST="HOME-TEST-01"

class CloudUnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.record=Path(self.tmp.name)/"cloud-device.json"
        self.calls=[]
        def transport(method,path,*,payload=None,device_id=None,credential=None):
            self.calls.append((method,path,payload,device_id,credential))
            if method=="POST" and path=="/v1/enrol":
                return {"status":"CLOUD_REGISTERED_UNVERIFIED",
                        "device_id":payload["device_id"],"owner_verified":False,
                        "auto_patch":False,"remote_control":False}
            if method=="GET" and path=="/v1/device":
                return {"status":"CLOUD_REGISTERED_UNVERIFIED","auto_patch":False}
            raise AssertionError("unexpected network call")
        self.client=cloud_enrol.CloudEnrolment(ID,hostname=HOST,store=self.record,transport=transport)

    def test_explicit_click_registers_without_phone_or_file(self):
        self.assertEqual(self.client.state()["status"],"NOT_CLOUD_REGISTERED")
        self.assertFalse(self.record.exists())
        result=self.client.enrol({"confirmed_personal":True})
        self.assertEqual(result["status"],"CLOUD_REGISTERED_UNVERIFIED")
        self.assertFalse(result["patching_enabled"])
        self.assertFalse(result["owner_verified"])
        self.assertFalse(result["remote_control"])
        self.assertEqual(len(self.calls),1)
        method,path,payload,_,_=self.calls[0]
        self.assertEqual((method,path),("POST","/v1/enrol"))
        self.assertEqual(payload["hostname"],HOST)
        self.assertEqual(set(payload),{"device_id","hostname","device_class","credential"})
        self.assertGreaterEqual(len(payload["credential"]),40)
        self.assertNotIn("credential",str(result))
        self.assertIn("credential",self.record.read_text())
        self.assertNotIn("credential",str(self.client.state()))

    def test_decline_does_not_send_or_store(self):
        for p in ({},{"confirmed_personal":False},{"confirmed_personal":1}):
            with self.subTest(p=p),self.assertRaises(cloud_enrol.CloudError):
                self.client.enrol(p)
        self.assertFalse(self.calls)
        self.assertFalse(self.record.exists())

    def test_reenrol_checks_live_status_and_keeps_credential(self):
        self.client.enrol({"confirmed_personal":True})
        secret=json.loads(self.record.read_text())["credential"]
        self.client.enrol({"confirmed_personal":True})
        self.assertEqual([r[0] for r in self.calls],["POST","GET"])
        self.assertEqual(json.loads(self.record.read_text())["credential"],secret)

    def test_failed_connection_can_retry_same_device_credential(self):
        supplied=[]
        def intermittent(method,path,*,payload=None,device_id=None,credential=None):
            supplied.append(payload["credential"])
            if len(supplied)==1:raise cloud_enrol.CloudError("Offline")
            return {"status":"CLOUD_REGISTERED_UNVERIFIED","device_id":ID,
                    "owner_verified":False,"auto_patch":False,"remote_control":False}
        c=cloud_enrol.CloudEnrolment(ID,hostname=HOST,store=self.record,transport=intermittent)
        with self.assertRaises(cloud_enrol.CloudError):
            c.enrol({"confirmed_personal":True})
        self.assertEqual(c.state()["status"],"CLOUD_ENROLMENT_PENDING")
        self.assertEqual(c.enrol({"confirmed_personal":True})["status"],"CLOUD_REGISTERED_UNVERIFIED")
        self.assertEqual(supplied[0],supplied[1])

    def test_forged_cloud_success_not_trusted(self):
        def forged(*args,**kwargs):
            return {"status":"CLOUD_REGISTERED_UNVERIFIED","device_id":ID,
                    "owner_verified":True,"auto_patch":True,"remote_control":True}
        c=cloud_enrol.CloudEnrolment(ID,hostname=HOST,store=self.record,transport=forged)
        with self.assertRaises(cloud_enrol.CloudError):
            c.enrol({"confirmed_personal":True})
        self.assertEqual(c.state()["status"],"CLOUD_ENROLMENT_PENDING")

    def test_mismatched_record_not_read(self):
        self.record.write_text(json.dumps({"state":"cloud_registered_unverified",
             "device_id":"windows-else","hostname":HOST,"credential":"X"*43}))
        self.assertEqual(self.client.state()["status"],"NOT_CLOUD_REGISTERED")

    def test_public_website_constant_https(self):
        self.assertEqual(cloud_enrol.CLOUD_BASE,
           "https://autopatch-cloud-enrolment.parris-neathaustralia.workers.dev")
        self.assertTrue(self.client.state()["dashboard_url"].startswith("https://"))

if __name__=="__main__":
    unittest.main()
