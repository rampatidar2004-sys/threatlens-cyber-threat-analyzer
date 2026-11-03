"""Tiny stand-in for an Ollama server, used ONLY by the tests so the LLM code path can be exercised
without downloading a model. It mimics /api/tags, /api/chat and /api/embed."""
import hashlib
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


def fake_vec(text, dim=24):
    v = [0.0] * dim
    for w in re.findall(r"[a-z0-9]+", text.lower()):
        v[int(hashlib.md5(w.encode()).hexdigest(), 16) % dim] += 1.0
    return v


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/api/tags":
            self._send({"models": [{"name": "fake:1b"}, {"name": "fake-embed:latest"}]})
        else:
            self.send_error(404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/api/embed":
            inp = body["input"]
            inp = [inp] if isinstance(inp, str) else inp
            self._send({"embeddings": [fake_vec(t) for t in inp]})
        elif self.path == "/api/chat":
            system = body["messages"][0]["content"]
            user = body["messages"][1]["content"]
            if "CANDIDATE TECHNIQUES" in user:
                sents = {int(i): t for i, t in re.findall(r"^\[(\d+)\] (.*)$", user, re.M)}
                cands = re.findall(r"^(T\d{4}(?:\.\d{3})?) \| ([^|]+) \|", user, re.M)
                events = []
                for tid, name in cands:
                    key = name.split(": ")[-1].lower().split()[0]
                    for i, t in sents.items():
                        if key in t.lower():
                            events.append({"sentence": i, "technique_id": tid, "tactic": "", "reason": "fake model keyword"})
                            break
                if sents:
                    first = min(sents)
                    events.append({"sentence": first, "technique_id": "T9999", "tactic": "impact", "reason": "hallucinated"})  # must be rejected
                    events.append({"sentence": 9999, "technique_id": "T1078", "tactic": "initial-access", "reason": "bad sentence"})  # must be rejected
                self._send({"message": {"content": json.dumps({"events": events})}})
            else:
                panels = [{"i": i, "narration": f"Panel {i} narration from the fake LLM.", "attacker_says": "Hehe."} for i in range(30)]
                self._send({"message": {"content": json.dumps({"title": "Fake Title", "panels": panels})}})
        else:
            self.send_error(404)


def start(port=11555):
    srv = HTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
