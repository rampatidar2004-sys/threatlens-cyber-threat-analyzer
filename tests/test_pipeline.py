"""Run:  python -m unittest tests.test_pipeline -v   (from the project folder)"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import engine  # noqa: E402
import fake_ollama  # noqa: E402


def run(text, **opts):
    stages, result, err = [], None, None
    for m in engine.run_pipeline(text, opts):
        if m["type"] == "stage" and m["status"] == "done":
            stages.append(m["stage"])
        elif m["type"] == "result":
            result = m
        elif m["type"] == "error":
            err = m
    return stages, result, err


CONTI = (ROOT / "samples" / "conti_sample.txt").read_text()
QUANTUM = (ROOT / "samples" / "quantum_sample.txt").read_text()


class RagOnly(unittest.TestCase):
    def test_conti_stages_and_order(self):
        stages, r, _ = run(CONTI, mode="rag")
        self.assertEqual(stages, ["ingest", "chunk", "index", "retrieve", "extract", "validate", "compose"])
        tactics = [e["tactic"] for e in r["events"]]
        self.assertEqual(tactics, ["initial-access", "credential-access", "discovery", "lateral-movement", "exfiltration", "impact"])
        ids = {t["id"] for e in r["events"] for t in e["techniques"]}
        for need in ("T1078", "T1003.001", "T1018", "T1021.002", "T1567.002", "T1486", "T1490"):
            self.assertIn(need, ids)
        self.assertTrue(r["events"][0]["time"].startswith("11th Apr 2022"))
        self.assertNotIn("T1556.006", ids)  # defender advice (MFA) must not become an attack step

    def test_quantum_time_ordering(self):
        _, r, _ = run(QUANTUM, mode="rag")
        self.assertEqual([e["tactic"] for e in r["events"]], ["execution", "discovery", "persistence", "command-and-control", "credential-access", "lateral-movement", "impact"])
        self.assertIn("18:57", r["events"][1]["time"])

    def test_every_id_exists_in_kb(self):
        kb = engine.load_kb()
        for txt in (CONTI, QUANTUM):
            _, r, _ = run(txt, mode="rag")
            for e in r["events"]:
                for t in e["techniques"]:
                    self.assertIn(t["id"], kb["techniques"])
                    self.assertEqual(t["name"], kb["techniques"][t["id"]]["name"])

    def test_empty_report(self):
        _, r, err = run("short.", mode="rag")
        self.assertIsNone(r)
        self.assertIsNotNone(err)


class WithFakeOllama(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = fake_ollama.start(11555)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_llm_path_rejects_hallucinations(self):
        _, r, _ = run(CONTI, mode="llm", model="fake:1b", embed_model="fake-embed:latest", ollama_url="http://127.0.0.1:11555")
        self.assertEqual(r["stats"]["llm"], "fake:1b")
        reasons = " ".join(x["why"] for x in r["inspect"]["rejected"])
        self.assertIn("hallucinated", reasons)
        ids = {t["id"] for e in r["events"] for t in e["techniques"]}
        self.assertNotIn("T9999", ids)
        self.assertEqual(r["events"][0]["narration"].startswith("Panel"), True)
        self.assertEqual(r["comic_title"], "Fake Title")

    def test_falls_back_when_ollama_down(self):
        _, r, _ = run(CONTI, mode="llm", model="fake:1b", ollama_url="http://127.0.0.1:1")
        self.assertIsNone(r["stats"]["llm"])
        self.assertTrue(any("not running" in w for w in r["warnings"]))
        self.assertGreaterEqual(len(r["events"]), 5)



# A report as a PDF extractor returns it: sentences broken across lines at a fixed width.
WRAPPED = (
    "Summary\n"
    "Between 11 April 2022 and 16 April 2022, a threat actor compromised a mid-sized company and\n"
    "deployed ransomware.\n"
    "On 12 April 2022, the attacker ran PowerShell commands (T1059.001) on a workstation to\n"
    "download a second-stage payload from an external server.\n"
    "On 16 April 2022, the attacker deployed ransomware that encrypted files across the network, which\n"
    "is Data Encrypted for Impact (T1486).\n"
    "Recommendations\n"
    "Organizations should enforce multi-factor authentication on VPN accounts and monitor for unusual\n"
    "PowerShell activity.\n"
)


class LineWrapping(unittest.TestCase):
    def test_wrapped_lines_are_rejoined_into_sentences(self):
        sents = engine.split_sentences(WRAPPED)
        self.assertTrue(any(s.startswith("On 12 April 2022") and s.endswith("external server.") for s in sents))

    def test_headings_are_not_glued_to_the_next_paragraph(self):
        for s in engine.split_sentences(WRAPPED):
            self.assertFalse(s.startswith("Summary Between"), s)
            self.assertNotIn("Recommendations Organizations", s)

    def test_hyphenated_line_break_is_repaired(self):
        text = "The attacker started the data exfil-\ntration to a cloud server on 15 April 2022 using rclone, as the logs show.\n" * 2
        self.assertTrue(any("exfiltration" in s for s in engine.split_sentences(text)))

    def test_defender_advice_split_across_lines_is_not_an_attack_step(self):
        _, r, _ = run(WRAPPED, mode="rag")
        # PowerShell appears once (12 Apr). The advice to "monitor for unusual PowerShell activity" is not a stage.
        ps = [(e["n"], e["time"]) for e in r["events"] for t in e["techniques"] if t["id"] == "T1059.001"]
        self.assertEqual(len(ps), 1)
        self.assertTrue(ps[0][1].startswith("12th Apr"))
        self.assertEqual(r["events"][-1]["tactic"], "impact")


class Options(unittest.TestCase):
    def test_missing_options_fall_back_to_defaults(self):
        _, r, err = run(CONTI, mode=None, top_k=None, lang=None, model=None, embed_model=None)
        self.assertIsNone(err)
        self.assertGreater(len(r["events"]), 0)

    def test_result_says_how_stages_were_ordered(self):
        _, r, _ = run(CONTI, mode="rag")
        self.assertEqual(r["stats"]["order"], "time")  # every stage in the sample has a date
        self.assertTrue(all("tactic_desc" in e for e in r["events"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
