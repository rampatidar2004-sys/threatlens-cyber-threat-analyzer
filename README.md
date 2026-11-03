# ThreatLens — Local Cyber Threat Report Analyzer

ThreatLens is a local web application for turning cyber-threat reports into an evidence-linked MITRE ATT&CK analysis. It extracts report text, retrieves candidate ATT&CK techniques, validates selected mappings, and presents the result as a timeline, evidence view, and educational comic storyboard.

## Features

- Paste report text or upload `.txt`, `.md`, `.html`, or `.pdf` files.
- Local MITRE ATT&CK Enterprise knowledge base bundled under `data/`.
- Retrieval pipeline using BM25 ranking and optional local embeddings.
- Optional local Ollama model for constrained technique selection and storyboard captions.
- RAG-only mode that can run without an LLM.
- Validation against the bundled ATT&CK knowledge base, including rejected candidate explanations.
- Timeline, evidence table/drawer, inspection view, and PNG/JSON outputs.
- English, Hindi, and Hinglish comic-caption options.

## Tech stack

- Python and Flask
- MITRE ATT&CK Enterprise STIX-derived knowledge data
- BM25 retrieval and optional Ollama embeddings/chat
- Vanilla HTML, CSS, and JavaScript frontend
- `pypdf` for PDF text extraction

## Run locally

**Requirements:** Python 3.10+ recommended. PDF uploads require `pypdf` (included in `requirements.txt`).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:8765`.

## Optional local LLM mode

ThreatLens can run in RAG-only mode without Ollama. To enable local LLM assistance, install Ollama and download a supported chat model. The source README gives `qwen3:8b` and `qwen3:4b` as examples, with `nomic-embed-text` as an optional embedding model:

```bash
ollama pull qwen3:4b
ollama pull nomic-embed-text
```

Keep Ollama running while using LLM mode. Model quality and speed depend on the machine and model selected. The application can fall back to RAG-only mode when the local Ollama service is unavailable.

## Refreshing the ATT&CK knowledge base

The bundled `data/mitre_kb.json` is an offline snapshot. To refresh it, download the official Enterprise ATT&CK STIX bundle from the MITRE ATT&CK STIX data project and run:

```bash
python build_kb.py path/to/enterprise-attack.json
```

Review the upstream MITRE data terms and cite the appropriate ATT&CK version when presenting analysis.

## Tests

```bash
python -m unittest discover -s tests -v
```

The repository includes tests for the analysis pipeline and local web interface. The LLM-related tests use a fake Ollama server; that does not replace evaluating the real model on representative reports.

## Limitations

- This is report-analysis support, not endpoint detection, live network monitoring, or incident-response automation.
- RAG-only mode favors precision and may miss techniques that are not explicitly named in a report.
- Confidence values are heuristic, not calibrated probabilities.
- PDF extraction flattens text and does not preserve page-level evidence references.
- The generated comic is an educational summary, not a forensic record.
- Validate important findings with a qualified analyst and the original report.

## Data and privacy

The Flask server binds to `127.0.0.1` by default. Reports are processed by the local application; when Ollama is enabled, model requests go to the local Ollama service. Do not expose the development server publicly without adding authentication, request limits, and a security review.
