"""Web-server tests.  Run:  python -m unittest tests.test_app -v   (needs flask and pypdf)"""
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as appmod  # noqa: E402

PDF = ROOT / "tests" / "fixtures" / "sample_incident_report.pdf"


def ndjson(resp):
    return [json.loads(line) for line in resp.get_data(as_text=True).splitlines() if line.strip()]


class Server(unittest.TestCase):
    def setUp(self):
        self.c = appmod.app.test_client()

    def test_index_and_samples(self):
        self.assertIn(b"ThreatLens", self.c.get("/").data)
        self.assertEqual(len(self.c.get("/api/samples").get_json()), 2)

    def test_bad_requests_are_400_not_500(self):
        self.assertEqual(self.c.post("/api/analyze", data="not json", content_type="application/json").status_code, 400)
        self.assertEqual(self.c.post("/api/analyze", json=["a list"]).status_code, 400)
        self.assertEqual(self.c.post("/api/analyze", json={"text": "too short"}).status_code, 400)
        self.assertEqual(self.c.post("/api/extract-text").status_code, 400)

    def test_pdf_upload_then_analyse_gives_the_right_story(self):
        up = self.c.post("/api/extract-text", data={"file": (io.BytesIO(PDF.read_bytes()), "report.pdf")}, content_type="multipart/form-data")
        self.assertEqual(up.status_code, 200)
        text = up.get_json()["text"]
        self.assertIn("PowerShell", text)
        msgs = ndjson(self.c.post("/api/analyze", json={"text": text, "mode": "rag"}))
        result = [m for m in msgs if m["type"] == "result"][-1]
        tactics = [e["tactic"] for e in result["events"]]
        self.assertEqual(tactics[-1], "impact")  # the advice at the end of the report is not an attack stage
        ps = [e["time"] for e in result["events"] for t in e["techniques"] if t["id"] == "T1059.001"]
        self.assertEqual(len(ps), 1)
        ids = {t["id"] for e in result["events"] for t in e["techniques"]}
        for need in ("T1078", "T1059.001", "T1053.005", "T1003.001", "T1021.002", "T1041", "T1486"):
            self.assertIn(need, ids)


if __name__ == "__main__":
    unittest.main()
