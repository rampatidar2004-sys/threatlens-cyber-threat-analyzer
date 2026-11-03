"""Static checks on the web page.  Run:  python -m unittest tests.test_ui -v"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import engine  # noqa: E402

HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
CSS = HTML.split("<style>")[1].split("</style>")[0]


class Page(unittest.TestCase):
    def test_runs_offline_no_external_resources(self):
        self.assertIsNone(re.search(r"<(?:script|link|img)[^>]+(?:src|href)=[\"']https?://", HTML, re.I))

    def test_palette_is_burnt_sienna(self):
        for colour in ("#E35336", "#F5F5DC", "#F4A460", "#A0522D"):
            self.assertIn(colour.lower(), CSS.lower())

    def test_no_blue_left_over(self):
        for h in set(re.findall(r"#[0-9a-fA-F]{6}\b", HTML)):
            r, g, b = int(h[1:3], 16), int(h[3:5], 16), int(h[5:7], 16)
            self.assertFalse(b > r + 12, f"{h} is blue-dominant")

    def test_unwanted_controls_are_gone_and_wanted_ones_remain(self):
        for gone in ("bSvg", "bNav", "id=\"refresh\""):
            self.assertNotIn(gone, HTML)
        for kept in ("id=\"bPng\"", "id=\"bJson\"", "id=\"run\"", "data-v=\"comic\"", "id=\"lang\"", "Hinglish", "id=\"embed\""):
            self.assertIn(kept, HTML)

    def test_fonts_are_defined_once_and_used_by_the_diagrams(self):
        self.assertIn("--font-ui:", CSS)
        self.assertIn("--font-mono:", CSS)
        self.assertIn("const FONT_UI", HTML)
        self.assertIn("const FONT_COMIC", HTML)
        self.assertNotIn("font-family:Segoe", CSS.replace(" ", ""))  # no stray hard-coded families in the stylesheet

    def test_top_k_default_matches_the_engine(self):
        m = re.search(r'<select id="topk">(.*?)</select>', HTML, re.S).group(1)
        selected = re.search(r"<option selected>(\d+)</option>", m).group(1)
        self.assertEqual(int(selected), engine.DEFAULT_TOP_K)


if __name__ == "__main__":
    unittest.main()
