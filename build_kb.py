"""Build the compact offline MITRE ATT&CK knowledge base used by ThreatLens.

Input : data/enterprise-attack.stix.json  (official STIX bundle from
        https://github.com/mitre-attack/attack-stix-data - download it ONCE
        while online, then the project never needs the internet again)
Output: data/mitre_kb.json  (techniques, tactics order, software, mitigations)

Usage:  python build_kb.py [path/to/enterprise-attack.json]
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).parent
SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "data" / "enterprise-attack.stix.json"
OUT = HERE / "data" / "mitre_kb.json"

CITE = re.compile(r"\(Citation:[^)]*\)")
MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")


def clean(text: str, limit: int = 600) -> str:
    text = CITE.sub("", text or "")
    text = MD_LINK.sub(r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def alive(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def main():
    bundle = json.loads(SRC.read_text(encoding="utf-8"))
    objs = bundle["objects"]
    by_id = {o["id"]: o for o in objs}

    tactics = {}
    for o in objs:
        if o["type"] == "x-mitre-tactic" and alive(o):
            tactics[o["x_mitre_shortname"]] = {"id": attack_id(o), "name": o["name"], "desc": clean(o.get("description"), 300)}
    matrix = next(o for o in objs if o["type"] == "x-mitre-matrix")
    order = [by_id[r]["x_mitre_shortname"] for r in matrix["tactic_refs"] if r in by_id]

    techs = {}
    stix2tid = {}
    for o in objs:
        if o["type"] != "attack-pattern" or not alive(o):
            continue
        tid = attack_id(o)
        if not tid:
            continue
        stix2tid[o["id"]] = tid
        techs[tid] = {
            "id": tid,
            "name": o["name"],
            "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])],
            "desc": clean(o.get("description")),
            "platforms": o.get("x_mitre_platforms", []),
            "sub": bool(o.get("x_mitre_is_subtechnique")),
            "mit": [],
            "sw": [],
        }
    # full name for sub-techniques: "Parent: Sub"
    for tid, t in techs.items():
        if t["sub"]:
            parent = techs.get(tid.split(".")[0])
            if parent:
                t["name"] = f'{parent["name"]}: {t["name"]}'

    software = {}
    mit_names = {o["id"]: o["name"] for o in objs if o["type"] == "course-of-action" and alive(o)}
    for o in objs:
        if o["type"] in ("tool", "malware") and alive(o):
            software[o["id"]] = {"name": o["name"], "aliases": [a for a in o.get("x_mitre_aliases", []) if a != o["name"]], "kind": o["type"], "techs": []}

    for r in objs:
        if r["type"] != "relationship" or r.get("revoked") or r.get("x_mitre_deprecated"):
            continue
        tid = stix2tid.get(r["target_ref"])
        if not tid:
            continue
        if r["relationship_type"] == "mitigates" and r["source_ref"] in mit_names:
            m = mit_names[r["source_ref"]]
            if m not in techs[tid]["mit"]:
                techs[tid]["mit"].append(m)
        elif r["relationship_type"] == "uses" and r["source_ref"] in software:
            software[r["source_ref"]]["techs"].append(tid)

    sw_out = []
    for s in software.values():
        if s["techs"]:
            s["techs"] = sorted(set(s["techs"]))
            sw_out.append(s)
            for tid in s["techs"]:
                techs[tid]["sw"].append(s["name"])
    for t in techs.values():
        t["mit"] = t["mit"][:4]
        t["sw"] = t["sw"][:10]

    coll = next((o for o in objs if o["type"] == "x-mitre-collection"), {})
    kb = {
        "meta": {
            "attack_version": coll.get("x_mitre_version"),
            "modified": coll.get("modified"),
            "technique_count": len(techs),
            "software_count": len(sw_out),
            "source": "MITRE ATT&CK Enterprise STIX 2.1 (attack-stix-data)",
        },
        "tactic_order": order,
        "tactics": tactics,
        "techniques": techs,
        "software": sw_out,
    }
    OUT.write_text(json.dumps(kb, separators=(",", ":")), encoding="utf-8")
    print(f"KB written: {OUT}  ({OUT.stat().st_size/1e6:.2f} MB)  techniques={len(techs)} software={len(sw_out)} tactics={order}")


if __name__ == "__main__":
    main()
