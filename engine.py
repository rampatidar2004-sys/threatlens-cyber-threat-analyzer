"""ThreatLens engine - fully offline RAG pipeline.

Stages (mirrors the paper's Fig. 1, but every stage runs locally):
  1 ingest   -> clean text, split into sentences, track dates/times
  2 chunk    -> semantic chunking (lexical-similarity breakpoints, no internet)
  3 index    -> BM25 index over the official MITRE ATT&CK KB (+ optional local embeddings via Ollama)
  4 retrieve -> per-sentence top-K candidate techniques (RAG over the *knowledge base*)
  5 extract  -> local LLM (Ollama) chooses among candidates, or deterministic RAG-only mode
  6 validate -> every ID / tactic / evidence checked against the KB; hallucinations are rejected
  7 compose  -> ordered events, mitigations, comic narration
"""
from __future__ import annotations

import datetime as dt
import json
import math
import re
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).parent
KB_PATH = HERE / "data" / "mitre_kb.json"
OLLAMA_DEFAULT = "http://127.0.0.1:11434"
DEFAULT_TOP_K = 5  # candidates retrieved per sentence (the UI uses the same default)

# --------------------------------------------------------------------------------------
# Knowledge base
# --------------------------------------------------------------------------------------
_KB = None


def load_kb():
    global _KB
    if _KB is None:
        _KB = json.loads(KB_PATH.read_text(encoding="utf-8"))
        _KB["_order"] = {t: i for i, t in enumerate(_KB["tactic_order"])}
    return _KB


GENERIC_TACTICS = {"stealth", "defense-impairment", "defense-evasion"}

STOP = set("""a an the and or of to in on at by for with from into onto over under is are was were be been being this that these those
it its as than then so such not no nor can could would should may might will shall do does did done has have had using used use via per
their there they them he she his her we our you your also which who whom whose what when where while after before during between within
without about above below up down out off again further once all any both each few more most other some only own same too very s t just
""".split())


def stem(w: str) -> str:
    if len(w) > 5 and w.endswith("ing"):
        return w[:-3]
    if len(w) > 4 and w.endswith("ed"):
        return w[:-2]
    if len(w) > 4 and w.endswith("es"):
        return w[:-2]
    if len(w) > 3 and w.endswith("s") and not w.endswith("ss"):
        return w[:-1]
    return w


def tokens(text: str) -> list[str]:
    return [stem(w) for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOP and len(w) > 1]


def norm_phrase(text: str) -> str:
    return " " + " ".join(re.findall(r"[a-z0-9]+", text.lower())) + " "


# curated report-vocabulary hints (analyst shorthand that rarely appears in ATT&CK text)
ALIASES = {
    "rdp": "T1021.001", "remote desktop": "T1021.001", "lsass": "T1003.001", "vssadmin": "T1490",
    "shadow copies": "T1490", "shadow copy": "T1490", "ransom note": "T1486", "psexec": "T1569.002",
    "admin share": "T1021.002", "admin shares": "T1021.002", "c$": "T1021.002", "wmi": "T1047",
    "powershell": "T1059.001", "cmd.exe": "T1059.003", "command shell": "T1059.003", "vpn": "T1133",
    "spearphishing attachment": "T1566.001", "phishing email": "T1566.001", "malicious shortcut": "T1204.002",
    "lnk file": "T1204.002", "scheduled task": "T1053.005", "run key": "T1547.001", "dcsync": "T1003.006",
    "kerberoast": "T1558.003", "ntds.dit": "T1003.003", "mimikatz": "T1003.001", "brute force": "T1110",
    "password spray": "T1110.003", "ingress tool transfer": "T1105", "rclone": "T1567.002",
    "cloud storage": "T1567.002", "were encrypted": "T1486", "was encrypted": "T1486", "encrypted for impact": "T1486",
    "domain trust": "T1482", "remote systems": "T1018", "system information": "T1082", "network configuration": "T1016",
    "network connections": "T1049", "active network connections": "T1049", "disk image": "T1204.002",
}

DEFENSIVE = re.compile(r"\b(recommend|should|mitigat|best practice|we advise|advise|organi[sz]ations (?:can|should)|defenders?|detection tip|can help defenders)\b", re.I)


def is_defensive(sentence: str) -> bool:
    return bool(DEFENSIVE.search(sentence))
CUE_TACTICS = [
    (r"\b(initial access|gained (?:entry|access)|logged in|log in|vpn|phish|exploited|entry)\b", "initial-access"),
    (r"\b(privilege|escalat|domain admin|administrator rights)\b", "privilege-escalation"),
    (r"\b(persist\w*|reboot|startup|autorun|keep running)\b", "persistence"),
    (r"\b(laterally|lateral|moved to other|spread to|admin share|psexec|rdp|remote desktop)\b", "lateral-movement"),
    (r"\b(dump|credential|password|lsass|hash)\b", "credential-access"),
    (r"\b(enumerat|discover|reconnaissance of|listed|queried)\b", "discovery"),
    (r"\b(exfiltrat|uploaded|upload|stole|stolen data|cloud storage)\b", "exfiltration"),
    (r"\b(encrypt|ransom|wiper|deleted backups|shadow cop)\b", "impact"),
    (r"\b(beacon|command and control|c2|callback|downloaded additional|tool transfer)\b", "command-and-control"),
    (r"\b(executed|ran|launched|opened)\b", "execution"),
]


class KBIndex:
    """BM25 over technique docs + phrase / software / alias evidence."""

    def __init__(self, kb):
        self.kb = kb
        self.techs = kb["techniques"]
        self.docs = {}
        self.df = Counter()
        self.post = defaultdict(list)  # token -> [(tid, tf)]
        for tid, t in self.techs.items():
            name_part = t["name"].split(": ")[-1]
            text = (t["name"] + " ") * 3 + name_part + " " + t["desc"]
            toks = tokens(text)
            c = Counter(toks)
            self.docs[tid] = len(toks)
            for tok, f in c.items():
                self.df[tok] += 1
                self.post[tok].append((tid, f))
        self.N = len(self.techs)
        self.avgdl = sum(self.docs.values()) / max(1, self.N)
        self.idf = {t: math.log(1 + (self.N - n + 0.5) / (n + 0.5)) for t, n in self.df.items()}

        # phrase evidence
        self.phrases = []  # (normalized phrase, tid)
        for tid, t in self.techs.items():
            sub = t["name"].split(": ")[-1]
            if len(sub) >= 7 and not (t["sub"] and " " not in sub.strip()):  # skip generic one-word sub-names ("Credentials")
                self.phrases.append((norm_phrase(sub), tid))
        # software
        self.sw = []
        for s in kb["software"]:
            for nm in [s["name"]] + s.get("aliases", []):
                if len(nm) >= 5 and nm.lower() not in {"agent", "tools"}:
                    self.sw.append((norm_phrase(nm), s["name"], set(s["techs"])))

    def bm25(self, query_tokens, k1=1.4, b=0.75):
        scores = defaultdict(float)
        for tok, qf in Counter(query_tokens).items():
            idf = self.idf.get(tok)
            if not idf:
                continue
            for tid, tf in self.post[tok]:
                dl = self.docs[tid]
                scores[tid] += idf * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * dl / self.avgdl))
        return scores

    def tools_in(self, sentence: str):
        ns = norm_phrase(sentence)
        found = {}
        for ph, name, techs in self.sw:
            if ph in ns and name not in found:
                found[name] = techs
        return found

    def candidates(self, sentence: str, k=5, emb=None):
        """Return [(tid, score, [reasons])] sorted desc.
        Evidence (explicit ID / name match / alias) outweighs raw BM25, which is capped.
        """
        ns = norm_phrase(sentence)
        base = self.bm25(tokens(sentence))
        why = defaultdict(list)
        score = defaultdict(float)
        for tid, s in base.items():
            score[tid] = min(s, 15.0)
        for m in re.finditer(r"\bT\d{4}(?:\.\d{3})?\b", sentence):
            tid = m.group(0)
            if tid in self.techs:
                score[tid] += 100
                why[tid].append("explicit-id")
        for ph, tid in self.phrases:
            if ph in ns or (ph[:-1] + "s ") in ns:
                score[tid] += 30
                why[tid].append("name-match")
        for al, tid in ALIASES.items():
            if (" " + al + " ") in ns or (" " + al + "s ") in ns or (al == "c$" and "c$" in sentence.lower()):
                if tid in self.techs:
                    score[tid] += 30
                    why[tid].append("alias:" + al)
        tools = self.tools_in(sentence)
        for name, techs in tools.items():
            for tid in techs:
                if base.get(tid, 0) > 0:
                    score[tid] += 6
                    why[tid].append("tool:" + name)
        if emb is not None:
            for tid, cos in emb:
                if cos > 0.3:
                    score[tid] += 25 * (cos - 0.3)
                    why[tid].append(f"embed:{cos:.2f}")
        ranked = sorted(score.items(), key=lambda kv: -kv[1])[:k]
        return [(tid, round(s, 2), why.get(tid, [])) for tid, s in ranked if s > 0]


# --------------------------------------------------------------------------------------
# Text -> sentences with date/time tracking
# --------------------------------------------------------------------------------------
MONTHS = {m: i + 1 for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split())}
MON_RE = r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?"
NUMW = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10}


def ordinal(n):
    return "%d%s" % (n, "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th"))


BULLET = re.compile(r"^(?:[-*•–]|\d{1,2}[.)])\s+")


def unwrap_lines(text: str) -> str:
    """Re-join lines that a PDF (or a narrow text box) broke in the middle of a sentence.

    A line counts as "wrapped" when it is nearly as wide as the document's longest lines and does not
    end with sentence punctuation (or ends in a hyphen, i.e. a broken word). Short lines (headings, last lines of paragraphs), blank lines and
    bullets always start a new block, so headings never get glued to the paragraph below them.
    """
    lines = [l.strip() for l in text.replace("\r", "").split("\n")]
    widths = sorted(len(l) for l in lines if l)
    if not widths:
        return ""
    full = 0.7 * widths[int(0.9 * (len(widths) - 1))]
    out, cur, cur_wrapped = [], "", False
    for line in lines:
        if not line:
            if cur:
                out.append(cur)
            cur, cur_wrapped = "", False
            continue
        if cur and cur_wrapped and not BULLET.match(line):
            glue = "" if (cur.endswith("-") and line[:1].islower()) else " "  # exfil-/tration -> exfiltration
            cur = (cur[:-1] if glue == "" else cur) + glue + line
        else:
            if cur:
                out.append(cur)
            cur = line
        cur_wrapped = line[-1] not in ".!?:;" and (len(line) >= full or line.endswith("-"))
    if cur:
        out.append(cur)
    return "\n".join(out)


def split_sentences(text: str):
    text = re.sub(r"[ \t]+", " ", unwrap_lines(text))
    parts = []
    for block in re.split(r"\n+", text):
        block = block.strip(" -*•\t")
        if not block:
            continue
        for s in re.split(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(\[])", block):
            s = s.strip()
            if len(s) >= 20:
                parts.append(s[:700])
    return parts


class TimeTracker:
    def __init__(self):
        self.date = None  # datetime.date
        self.day = None  # "Day N"
        self.year = None

    def parse(self, sent: str):
        low = sent.lower()
        dates, year_hint = [], None
        pat1 = re.compile(r"((?:\d{1,2}(?:st|nd|rd|th)?\s*(?:,|and|&|-|–|to)\s*)*\d{1,2}(?:st|nd|rd|th)?)\s+(?:of\s+)?" + MON_RE + r"(?:,?\s+(\d{4}|\d{2})(?![\d:]))?")
        for m in pat1.finditer(low):
            days = [int(x) for x in re.findall(r"\d{1,2}", m.group(1))]
            mon = MONTHS[m.group(2)]
            yr = m.group(3)
            yr = (int(yr) + (2000 if len(yr) == 2 else 0)) if yr else (self.year or 2000)
            if yr and m.group(3):
                year_hint = yr
            for d in days:
                try:
                    dates.append(dt.date(yr, mon, d))
                except ValueError:
                    pass
        masked = pat1.sub(" ", low)
        for m in re.finditer(MON_RE + r"\s+(\d{4})(?!\d)", masked):
            year_hint = int(m.group(2))
        masked2 = re.sub(MON_RE + r"\s+\d{4}(?!\d)", " ", masked)
        for m in re.finditer(MON_RE + r"\s+(\d{1,2})(?!\d)(?:st|nd|rd|th)?(?:,?\s+(\d{4}))?", masked2):
            mon = MONTHS[m.group(1)]
            yr = int(m.group(3)) if m.group(3) else (self.year or 2000)
            if m.group(3):
                year_hint = yr
            try:
                d = dt.date(yr, mon, int(m.group(2)))
                if d not in dates:
                    dates.append(d)
            except ValueError:
                pass
        for m in re.finditer(r"\b(\d{4})-(\d{2})-(\d{2})\b", low):
            try:
                dates.append(dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))))
                year_hint = int(m.group(1))
            except ValueError:
                pass
        if year_hint:
            self.year = year_hint
        day = None
        m = re.search(r"\bday\s+(\d{1,3})\b", low)
        if m:
            day = int(m.group(1))
        rel = None
        if re.search(r"\b(next day|following day|day after|the next morning)\b", low):
            rel = 1
        m2 = re.search(r"\b(\d+|" + "|".join(NUMW) + r")\s+days?\s+(?:later|after)\b", low)
        if m2:
            v = m2.group(1)
            rel = int(v) if v.isdigit() else NUMW[v]
        times = []
        for m in re.finditer(r"\b([01]?\d|2[0-3]):([0-5]\d)(?::[0-5]\d)?\s*(utc|gmt|[a-z]{2,4})?", low):
            tz = m.group(3)
            tz = tz.upper() if tz and tz in ("utc", "gmt", "est", "pst", "cet", "ist", "edt", "pdt") else ""
            times.append((int(m.group(1)) * 60 + int(m.group(2)), f"{int(m.group(1)):02d}:{m.group(2)}", tz))

        if dates:
            self.date = dates[-1]
            self.day = None
        elif day is not None:
            self.day, self.date = day, None
        elif rel is not None:
            if self.date:
                self.date = self.date + dt.timedelta(days=rel)
            elif self.day is not None:
                self.day += rel
            else:
                self.day = 1 + rel
        return {
            "dates": [d.isoformat() for d in dates] or ([self.date.isoformat()] if self.date else []),
            "day": self.day,
            "times": [(a, b, c) for a, b, c in times],
        }


def fmt_date(iso):
    d = dt.date.fromisoformat(iso)
    yr = d.year
    return f"{ordinal(d.day)} {d.strftime('%b')}" + (f" {yr}" if yr != 2000 else "")


# --------------------------------------------------------------------------------------
# Chunking (semantic breakpoints from lexical similarity - works offline)
# --------------------------------------------------------------------------------------
def cosine(a: Counter, b: Counter):
    num = sum(v * b.get(k, 0) for k, v in a.items())
    da = math.sqrt(sum(v * v for v in a.values()))
    db = math.sqrt(sum(v * v for v in b.values()))
    return num / (da * db) if da and db else 0.0


def semantic_chunks(sents, max_size=7, min_size=3, thresh=0.04):
    chunks, cur, cur_vec = [], [], Counter()
    for i, s in enumerate(sents):
        v = Counter(tokens(s))
        if cur and len(cur) >= min_size and (len(cur) >= max_size or cosine(v, cur_vec) < thresh):
            chunks.append(cur)
            cur, cur_vec = [], Counter()
        cur.append(i)
        cur_vec.update(v)
    if cur:
        chunks.append(cur)
    return chunks


# --------------------------------------------------------------------------------------
# Ollama (local LLM) client
# --------------------------------------------------------------------------------------
def _http(method, url, payload=None, timeout=5):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def ollama_status(base=OLLAMA_DEFAULT):
    try:
        tags = _http("GET", base + "/api/tags", timeout=2)
        return {"up": True, "models": sorted(m["name"] for m in tags.get("models", []))}
    except Exception as e:  # noqa: BLE001
        return {"up": False, "models": [], "error": str(e)[:120]}


def ollama_chat(base, model, system, user, schema=None, timeout=240):
    payload = {
        "model": model,
        "stream": False,
        "format": schema or "json",
        "options": {"temperature": 0, "num_ctx": 8192},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    if any(x in model.lower() for x in ("qwen3", "deepseek-r1", "gpt-oss")):
        payload["think"] = False
    out = _http("POST", base + "/api/chat", payload, timeout=timeout)
    content = out.get("message", {}).get("content", "")
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.S).strip()
    return content


def ollama_embed(base, model, texts, timeout=120):
    out = _http("POST", base + "/api/embed", {"model": model, "input": texts}, timeout=timeout)
    return out["embeddings"]


def parse_json_loose(s: str):
    try:
        return json.loads(s)
    except Exception:  # noqa: BLE001
        m = re.search(r"\{.*\}", s, flags=re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:  # noqa: BLE001
                return None
    return None


EXTRACT_SYSTEM = (
    "You are a cybersecurity analyst trained in the MITRE ATT&CK framework. You receive numbered sentences from a threat report "
    "and a list of CANDIDATE techniques retrieved from the official ATT&CK knowledge base. Select only techniques that the sentences "
    "explicitly describe (or very clearly imply) as ATTACKER behaviour. Use ONLY technique IDs that appear in the candidate list - never "
    "invent or guess IDs. For every selected technique give the sentence number that proves it and the tactic (it must be one of the "
    "tactics listed for that candidate). Ignore defender actions, background and generic advice. If nothing applies return an empty list. "
    'Respond with JSON only: {"events":[{"sentence":<int>,"technique_id":"T....","tactic":"<shortname>","reason":"<8 words>"}]}'
)

COMIC_SYSTEM = (
    "You write captions for an educational comic strip that explains how a cyber attack unfolded, for students. Be accurate and use only the "
    "facts given. Never add instructions, commands or tool settings an attacker could reuse. For every panel return a short narration "
    "(max 26 words, simple words, past tense) and a short line the attacker thinks or says (max 9 words, a little cheeky). "
    'Respond with JSON only: {"title":"<max 8 words>","panels":[{"i":<int>,"narration":"...","attacker_says":"..."}]}'
)


# --------------------------------------------------------------------------------------
# Comic template fallbacks (no LLM needed)
# --------------------------------------------------------------------------------------
TEMPLATE = {
    "reconnaissance": ("Scouting the target before moving in.", "Let me see what you have."),
    "resource-development": ("The attacker prepared tools and infrastructure.", "Workshop is ready."),
    "initial-access": ("The attacker found a way inside the network.", "Door's open. Thanks!"),
    "execution": ("Malicious code started running on a machine.", "Now it runs."),
    "persistence": ("The attacker made sure the access would survive a reboot.", "I'm not leaving."),
    "privilege-escalation": ("Higher privileges gave the attacker much more power.", "Admin rights, finally."),
    "defense-evasion": ("The attacker tried to stay hidden from defenders.", "Shh, nobody look."),
    "stealth": ("The attacker tried to stay hidden from defenders.", "Shh, nobody look."),
    "defense-impairment": ("Security tools were weakened or switched off.", "Lights out for the guards."),
    "credential-access": ("Passwords and credentials were stolen.", "Your keys are mine."),
    "discovery": ("The attacker explored the network and mapped systems.", "So that's where you hide."),
    "lateral-movement": ("The attacker hopped from machine to machine.", "On to the next one."),
    "collection": ("Valuable data was gathered in one place.", "Pack it all up."),
    "command-and-control": ("The implant phoned home for instructions.", "Boss, I'm in."),
    "exfiltration": ("Stolen data left the network for the attacker's cloud.", "Uploading the loot."),
    "impact": ("Files were encrypted and the business came to a halt.", "Pay up, or else."),
}


# --------------------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------------------
def pick_tactic(kb, tid, sentence, prev_tactic, first):
    cands = kb["techniques"][tid]["tactics"]
    if len(cands) == 1:
        return cands[0]
    low = sentence.lower()
    for pat, tac in CUE_TACTICS:
        if tac in cands and re.search(pat, low):
            return tac
    if first and "initial-access" in cands:
        return "initial-access"
    if prev_tactic in cands:
        return prev_tactic
    non_gen = [t for t in cands if t not in GENERIC_TACTICS] or cands
    return sorted(non_gen, key=lambda t: kb["_order"].get(t, 99))[0]


def run_pipeline(text: str, opts: dict):
    """Generator yielding progress dicts, last one has type='result'."""
    kb = load_kb()
    index = KBIndex(kb)
    mode = opts.get("mode") or "llm"  # llm | rag
    base = opts.get("ollama_url") or OLLAMA_DEFAULT
    model = opts.get("model") or ""
    embed_model = opts.get("embed_model") or ""
    topk = int(opts.get("top_k") or DEFAULT_TOP_K)
    lang = opts.get("lang") or "English"
    T = time.time()
    warnings = []

    def stage(name, status, detail="", **extra):
        return {"type": "stage", "stage": name, "status": status, "detail": detail, "t": round(time.time() - T, 2), **extra}

    # 1 ingest
    yield stage("ingest", "run")
    sents = split_sentences(text)
    if not sents:
        yield {"type": "error", "message": "No usable sentences found in the report text."}
        return
    tracker = TimeTracker()
    when = [tracker.parse(s) for s in sents]
    n_dated = sum(1 for w in when if w["dates"] or w["day"] is not None or w["times"])
    yield stage("ingest", "done", f"{len(sents)} sentences, {n_dated} with time cues")

    # 2 chunk
    yield stage("chunk", "run")
    chunks = semantic_chunks(sents)
    yield stage("chunk", "done", f"{len(chunks)} semantic chunks")

    # 3 index
    yield stage("index", "run")
    emb_ok = False
    tech_vecs = None
    if embed_model and mode == "llm":
        try:
            cache = HERE / "data" / ("emb_" + re.sub(r"[^a-z0-9]+", "_", embed_model.lower()) + ".json")
            ids = list(kb["techniques"])
            if cache.exists():
                tech_vecs = json.loads(cache.read_text())
            else:
                docs = [kb["techniques"][i]["name"] + ". " + kb["techniques"][i]["desc"][:300] for i in ids]
                vecs = []
                for j in range(0, len(docs), 64):
                    vecs += ollama_embed(base, embed_model, docs[j:j + 64])
                tech_vecs = dict(zip(ids, vecs))
                cache.write_text(json.dumps(tech_vecs))
            emb_ok = True
        except Exception as e:  # noqa: BLE001
            warnings.append(f"Embedding model unavailable ({str(e)[:80]}); using BM25 only.")
    yield stage("index", "done", f"BM25 over {index.N} ATT&CK techniques" + (f" + {embed_model} embeddings" if emb_ok else ""))

    def emb_scores(sentence):
        if not emb_ok:
            return None
        try:
            q = ollama_embed(base, embed_model, [sentence])[0]
        except Exception:  # noqa: BLE001
            return None
        qn = math.sqrt(sum(x * x for x in q)) or 1
        out = []
        for tid, v in tech_vecs.items():
            vn = math.sqrt(sum(x * x for x in v)) or 1
            out.append((tid, sum(a * b for a, b in zip(q, v)) / (qn * vn)))
        out.sort(key=lambda x: -x[1])
        return out[:15]

    # 4 retrieve
    yield stage("retrieve", "run")
    cand = []
    defensive = [is_defensive(s) for s in sents]  # advice to defenders is not attacker behaviour
    for i, s in enumerate(sents):
        if defensive[i]:
            cand.append([])
            continue
        cand.append(index.candidates(s, k=topk, emb=emb_scores(s) if emb_ok else None))
    n_cand = sum(len(c) for c in cand)
    yield stage("retrieve", "done", f"{n_cand} candidate techniques retrieved (top-{topk} per sentence)")

    # 5 extract
    raw_llm, rejected = [], []
    selected = []  # dicts: sentence, tid, tactic, source, score, reason
    llm_used = False
    if mode == "llm":
        st = ollama_status(base)
        if not st["up"]:
            warnings.append("Ollama is not running - fell back to RAG-only extraction.")
        elif model not in st["models"]:
            warnings.append(f"Model '{model}' not found locally - fell back to RAG-only extraction.")
        else:
            llm_used = True
    yield stage("extract", "run", f"local LLM: {model}" if llm_used else "deterministic RAG-only")

    def is_strong(why):
        """Direct textual evidence: technique ID, official name phrase, or analyst alias."""
        return any(w == "explicit-id" or w == "name-match" or w.startswith("alias:") for w in why)

    explicit = set()
    for i, cl in enumerate(cand):
        for tid, sc, why in cl:
            if "explicit-id" in why:
                explicit.add((i, tid))

    if llm_used:
        proposed = 0
        for ci, ch in enumerate(chunks):
            pool = {}
            for i in ch:
                for tid, sc, why in cand[i][:4]:
                    pool[tid] = max(pool.get(tid, 0), sc)
            top = sorted(pool, key=lambda t: -pool[t])[:14]
            if not top:
                continue
            lines = "\n".join(f"[{i}] {sents[i]}" for i in ch)
            clist = "\n".join(
                f"{t} | {kb['techniques'][t]['name']} | tactics: {', '.join(kb['techniques'][t]['tactics'])} | {kb['techniques'][t]['desc'][:150]}" for t in top
            )
            user = f"SENTENCES:\n{lines}\n\nCANDIDATE TECHNIQUES:\n{clist}\n\nReturn JSON."
            try:
                out = ollama_chat(base, model, EXTRACT_SYSTEM, user)
                data = parse_json_loose(out) or {}
                raw_llm.append({"chunk": ci, "sentences": ch, "response": data})
            except Exception as e:  # noqa: BLE001
                warnings.append(f"LLM call failed on chunk {ci}: {str(e)[:80]}")
                data = {}
                raw_llm.append({"chunk": ci, "sentences": ch, "error": str(e)[:200]})
            for item in data.get("events", []) if isinstance(data, dict) else []:
                proposed += 1
                tid = str(item.get("technique_id", "")).strip().upper()
                try:
                    si = int(item.get("sentence"))
                except Exception:  # noqa: BLE001
                    rejected.append({"id": tid, "why": "bad sentence index"})
                    continue
                if tid not in kb["techniques"]:
                    rejected.append({"id": tid, "why": "not in MITRE KB (hallucinated ID)"})
                    continue
                if si not in ch:
                    rejected.append({"id": tid, "why": "evidence sentence outside chunk"})
                    continue
                if tid not in top and (si, tid) not in explicit:
                    rejected.append({"id": tid, "why": "not among retrieved candidates"})
                    continue
                cmap = {t: (s, w) for t, s, w in cand[si]}
                if defensive[si]:
                    rejected.append({"id": tid, "why": "evidence sentence is defender advice, not attacker behaviour"})
                    continue
                sc, why = cmap.get(tid, (0, []))
                selected.append({"sentence": si, "tid": tid, "tactic": str(item.get("tactic", "")).strip().lower(), "source": "llm+rag", "score": sc, "why": why, "reason": str(item.get("reason", ""))[:90]})
        for (si, tid) in explicit:
            if not any(x["sentence"] == si and x["tid"] == tid for x in selected):
                selected.append({"sentence": si, "tid": tid, "tactic": "", "source": "explicit-id", "score": 100, "why": ["explicit-id"], "reason": "technique ID written in report"})
        yield stage("extract", "done", f"LLM proposed {proposed}; kept {len(selected)}; rejected {len(rejected)}")
    else:
        for i, cl in enumerate(cand):
            if not cl:
                continue
            strong_here = [c for c in cl if is_strong(c[2])]
            # conservative policy (as in the paper): only techniques with direct textual evidence;
            # tool-only matches are accepted only if the sentence has no stronger evidence at all.
            pool_ = strong_here or [c for c in cl if any(w.startswith("tool:") for w in c[2]) and c[1] >= 18][:1]
            for tid, sc, why in pool_[:6]:
                selected.append({"sentence": i, "tid": tid, "tactic": "", "source": "explicit-id" if "explicit-id" in why else "rag-only", "score": sc, "why": why, "reason": ", ".join(why[:3]) or "lexical match"})
        yield stage("extract", "done", f"{len(selected)} techniques selected by retrieval score")

    # 6 validate against KB + assign tactic
    yield stage("validate", "run")
    selected.sort(key=lambda x: (x["sentence"], -x["score"]))
    seen = set()
    final = []
    prev_tactic = None
    for x in selected:
        key = (x["sentence"], x["tid"])
        if key in seen:
            continue
        seen.add(key)
        tinfo = kb["techniques"][x["tid"]]
        tactic = x["tactic"] if x["tactic"] in tinfo["tactics"] else pick_tactic(kb, x["tid"], sents[x["sentence"]], prev_tactic, first=not final)
        prev_tactic = tactic
        x["tactic"] = tactic
        why = x.get("why", [])
        if x["source"] == "explicit-id":
            conf = 0.99
        elif is_strong(why):
            conf = 0.97 if x["source"] == "llm+rag" else 0.90
        else:  # LLM picked it from retrieved candidates without direct textual evidence
            conf = min(0.85, 0.55 + x["score"] / 80)
        x["conf"] = round(conf, 2)
        final.append(x)
    yield stage("validate", "done", f"{len(final)} techniques validated against ATT&CK v{kb['meta']['attack_version']}; {len(rejected)} rejected")

    # 7 compose events
    yield stage("compose", "run")
    raw_events = []
    # Techniques described in the same sentence belong to ONE attack stage (the stage tactic is the one the
    # sentence is about); a technique whose official ATT&CK tactic differs keeps its own tactic tag.
    by_sent = defaultdict(list)
    for x in final:
        by_sent[x["sentence"]].append(x)
    for si in sorted(by_sent):
        grp = by_sent[si]
        tactics_here = [g["tactic"] for g in grp]
        stage_tactic = tactics_here[0]
        low = sents[si].lower()
        for pat, tac in CUE_TACTICS:
            if tac in tactics_here and re.search(pat, low):
                stage_tactic = tac
                break
        w = when[si]
        items = []
        for x in grp:
            tool_hits = [n for n, ts in index.tools_in(sents[si]).items() if x["tid"] in ts]
            items.append({
                "id": x["tid"], "name": kb["techniques"][x["tid"]]["name"], "conf": x["conf"], "source": x["source"], "reason": x["reason"],
                "sentence_idx": si, "evidence": sents[si], "tools": tool_hits[:2], "tactic": x["tactic"],
                "tactic_name": kb["tactics"].get(x["tactic"], {}).get("name", x["tactic"]),
                "off_stage": x["tactic"] != stage_tactic,
                "desc": kb["techniques"][x["tid"]]["desc"], "mitigations": kb["techniques"][x["tid"]]["mit"],
            })
        if raw_events and raw_events[-1]["tactic"] == stage_tactic:
            ev = raw_events[-1]
            for it in items:
                if not any(t["id"] == it["id"] for t in ev["techniques"]):
                    ev["techniques"].append(it)
            ev["when"].append(w)
            ev["sent"].append(si)
        else:
            raw_events.append({"tactic": stage_tactic, "techniques": items, "when": [w], "sent": [si]})

    def ev_key(ev):
        dates = sorted({d for w in ev["when"] for d in w["dates"]})
        days = [w["day"] for w in ev["when"] if w["day"] is not None]
        times = sorted(t[0] for w in ev["when"] for t in w["times"])
        return (dates[0] if dates else None, days[0] if days else None, times[0] if times else None)

    # Order by real time when EVERY stage has a time cue; otherwise keep narrative order.
    keys = [ev_key(e) for e in raw_events]
    all_times = bool(raw_events) and all(k[2] is not None for k in keys)
    all_dates = bool(raw_events) and all(k[0] is not None or k[1] is not None for k in keys)
    order_basis = "time" if (all_times or all_dates) else "narrative"
    if order_basis == "time":
        def sort_key(i):
            d, day, tm = keys[i]
            return (d or "", day or 0, tm if (all_times and tm is not None) else 0, raw_events[i]["sent"][0])
        raw_events = [raw_events[i] for i in sorted(range(len(raw_events)), key=sort_key)]

    events = []
    for n, ev in enumerate(raw_events):
        dates = []
        for w in ev["when"]:
            for d in w["dates"]:
                if d not in dates:
                    dates.append(d)
        days = sorted({w["day"] for w in ev["when"] if w["day"] is not None})
        times = sorted({t for w in ev["when"] for t in w["times"]})
        label = ""
        if dates:
            if len(dates) == 1:
                label = fmt_date(dates[0])
            elif len(dates) == 2:
                label = fmt_date(dates[0]) + ", " + fmt_date(dates[1])
            else:
                label = fmt_date(dates[0]) + " – " + fmt_date(dates[-1])
        elif days:
            label = f"Day {days[0]}" + (f"–{days[-1]}" if len(days) > 1 else "")
        if times:
            tz = next((t[2] for t in times if t[2]), "")
            t0, t1 = times[0][1], times[-1][1]
            tl = f"{t0}" + (f" - {t1}" if t1 != t0 else "") + (f" {tz}" if tz else "")
            label = (label + " · " if label else "") + tl
        tinfo = kb["tactics"].get(ev["tactic"], {"name": ev["tactic"].replace("-", " ").title(), "id": ""})
        mit = []
        for t in ev["techniques"]:
            for m in t["mitigations"]:
                if m not in mit:
                    mit.append(m)
        tmpl = TEMPLATE.get(ev["tactic"], ("The attacker advanced.", "Next step."))
        events.append({
            "n": n + 1, "tactic": ev["tactic"], "tactic_name": tinfo["name"], "tactic_id": tinfo.get("id", ""), "tactic_desc": tinfo.get("desc", ""), "time": label,
            "techniques": ev["techniques"], "mitigations": mit[:4],
            "narration": tmpl[0], "attacker_says": tmpl[1],
            "evidence_first": sents[ev["sent"][0]][:260],
        })

    title = opts.get("title") or "Cyber Attack"
    comic_title = f"How the {title} attack unfolded"
    comic_src = "template"
    if llm_used and events:
        try:
            brief = [
                {"i": e["n"] - 1, "tactic": e["tactic_name"], "time": e["time"], "techniques": [t["name"] for t in e["techniques"]], "what_the_report_says": e["evidence_first"]}
                for e in events
            ]
            user = f"Language: {lang}. Attack name: {title}.\nPANELS:\n{json.dumps(brief, ensure_ascii=False)}\nReturn JSON."
            out = ollama_chat(base, model, COMIC_SYSTEM, user)
            data = parse_json_loose(out) or {}
            for p in data.get("panels", []):
                i = p.get("i")
                if isinstance(i, int) and 0 <= i < len(events):
                    if p.get("narration"):
                        events[i]["narration"] = str(p["narration"])[:220]
                    if p.get("attacker_says"):
                        events[i]["attacker_says"] = str(p["attacker_says"])[:70]
            if data.get("title"):
                comic_title = str(data["title"])[:80]
            comic_src = "llm"
        except Exception as e:  # noqa: BLE001
            warnings.append(f"Comic captions fell back to templates ({str(e)[:60]}).")
    yield stage("compose", "done", f"{len(events)} attack stages, comic captions: {comic_src}")

    total_t = len({t["id"] for e in events for t in e["techniques"]})
    result = {
        "type": "result",
        "title": title,
        "comic_title": comic_title,
        "events": events,
        "tactic_order": kb["tactic_order"],
        "warnings": warnings,
        "stats": {
            "sentences": len(sents), "chunks": len(chunks), "candidates": n_cand, "techniques": total_t, "stages": len(events),
            "rejected": len(rejected), "llm": model if llm_used else None, "embeddings": embed_model if emb_ok else None,
            "attack_version": kb["meta"]["attack_version"], "seconds": round(time.time() - T, 2), "order": order_basis,
        },
        "inspect": {
            "sentences": [{"i": i, "text": s, "when": when[i]} for i, s in enumerate(sents)],
            "chunks": chunks,
            "candidates": [{"i": i, "cands": [{"id": t, "name": kb["techniques"][t]["name"], "score": sc, "why": w} for t, sc, w in cl]} for i, cl in enumerate(cand)],
            "llm_raw": raw_llm,
            "rejected": rejected,
        },
    }
    yield result
