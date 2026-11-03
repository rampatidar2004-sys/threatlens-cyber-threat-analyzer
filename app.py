"""ThreatLens web app - runs on localhost only, no internet needed.

    python app.py            ->  http://127.0.0.1:8765
"""
import io
import json
import os
import re
from html.parser import HTMLParser
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context

import engine

HERE = Path(__file__).parent
app = Flask(__name__, static_folder=str(HERE / "static"), static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0  # always serve the current UI (no stale cached page after an update)
OLLAMA = os.environ.get("OLLAMA_URL", engine.OLLAMA_DEFAULT)


class _Strip(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "nav", "footer", "header", "form"}

    def __init__(self):
        super().__init__()
        self.out, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        if tag in ("p", "br", "li", "h1", "h2", "h3", "h4", "tr", "div"):
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.skip:
            self.skip -= 1
        if tag in ("p", "li", "tr"):
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def extract_text(name: str, raw: bytes) -> str:
    low = name.lower()
    if low.endswith(".pdf"):
        from pypdf import PdfReader  # optional dependency, only needed for PDF upload

        reader = PdfReader(io.BytesIO(raw))
        return "\n".join((p.extract_text() or "") for p in reader.pages)
    text = raw.decode("utf-8", errors="replace")
    if low.endswith((".html", ".htm", ".mhtml")) or re.search(r"<html|<body|<p[ >]", text[:2000], re.I):
        p = _Strip()
        p.feed(text)
        text = "".join(p.out)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/status")
def status():
    kb = engine.load_kb()
    return jsonify({"ollama": engine.ollama_status(OLLAMA), "kb": kb["meta"], "ollama_url": OLLAMA})


@app.get("/api/samples")
def samples():
    out = []
    for f in sorted((HERE / "samples").glob("*.txt")):
        out.append({"name": f.stem.replace("_sample", "").replace("_", " ").title(), "file": f.name, "text": f.read_text(encoding="utf-8")})
    return jsonify(out)


@app.post("/api/extract-text")
def upload():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "no file"}), 400
    try:
        return jsonify({"name": f.filename, "text": extract_text(f.filename, f.read())})
    except ImportError:
        return jsonify({"error": "PDF support needs pypdf: pip install pypdf (offline wheel is fine)"}), 400
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"Could not read file: {e}"}), 400


@app.post("/api/analyze")
def analyze():
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400
    text = (body.get("text") or "").strip()
    opts = {k: body.get(k) for k in ("mode", "model", "embed_model", "top_k", "lang", "title")}
    opts["ollama_url"] = OLLAMA
    if len(text) < 40:
        return jsonify({"error": "Paste or upload a threat report first."}), 400

    def gen():
        try:
            for msg in engine.run_pipeline(text, opts):
                yield json.dumps(msg, ensure_ascii=False) + "\n"
        except Exception as e:  # noqa: BLE001
            yield json.dumps({"type": "error", "message": f"Pipeline error: {e}"}) + "\n"

    return Response(stream_with_context(gen()), mimetype="application/x-ndjson", headers={"Cache-Control": "no-store"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8765"))
    print(f"\n  ThreatLens running at  http://127.0.0.1:{port}   (offline - nothing leaves this machine)\n")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
