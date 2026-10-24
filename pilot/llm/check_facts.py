"""Mechanical checks on extracted fact JSON.

For every fact: quote is a verbatim substring of the input text, fact_type is
in the schema, value format is sane, confidence is valid. Writes a report and
exits non-zero if anything fails, so the orchestrator cannot miss it.

Usage: python3 check_facts.py <dir-with-json> [--fix-whitespace]
"""
import json
import os
import re
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
INPUT = os.path.join(HERE, "input")

FACT_TYPES = set(re.findall(r"^- ([A-Z_]+) :", open(os.path.join(HERE, "FACT_SCHEMA.md")).read(), re.M))
DATE_TYPES = {"INCIDENT_DISCOVERY_DATE", "INCIDENT_START_DATE", "MATERIALITY_DETERMINATION_DATE",
              "CONTAINMENT_DATE", "RESTORATION_DATE"}
YESNO = {"RANSOMWARE": {"yes", "no"}, "ENCRYPTION": {"yes", "no"}, "PROACTIVE_SHUTDOWN": {"yes", "no"},
         "CONTAINED": {"yes", "no"}, "EXTERNAL_EXPERTS_ENGAGED": {"yes", "no"}, "LAW_ENFORCEMENT_NOTIFIED": {"yes", "no"},
         "REGULATOR_NOTIFIED": {"yes", "no"}, "INSURANCE_MENTIONED": {"yes", "no"}, "INVESTIGATION_ONGOING": {"yes", "no"},
         "DATA_EXFILTRATION": {"yes", "no", "under investigation"},
         "OPERATIONAL_DISRUPTION": {"yes", "no", "limited"},
         "MATERIAL_IMPACT": {"yes", "no", "not yet determined"},
         "RANSOM_PAID": {"yes", "no", "not stated"},
         "HIT_OR_NEAR_MISS": {"hit", "near miss", "unclear"}}
REQUIRED = {"HIT_OR_NEAR_MISS", "MATERIAL_IMPACT", "OPERATIONAL_DISRUPTION"}


def squash(s):
    s = unicodedata.normalize("NFKC", s)
    s = s.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
    return re.sub(r"\s+", " ", s).strip()


def check_dir(d, fix_ws=False):
    problems, n_facts, n_files = [], 0, 0
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".json"):
            continue
        n_files += 1
        path = os.path.join(d, fn)
        try:
            doc = json.load(open(path))
        except json.JSONDecodeError as exc:
            problems.append((fn, "-", f"invalid JSON: {exc}"))
            continue
        src_path = os.path.join(INPUT, fn[:-5] + ".txt")
        if not os.path.exists(src_path):
            problems.append((fn, "-", "no matching input file"))
            continue
        raw = open(src_path, encoding="utf-8").read()
        text = raw.split("=== TEXT ===", 1)[-1]
        flat, flat_sq = re.sub(r"\s+", " ", text), squash(text)
        types_seen = set()
        changed = False
        for i, f in enumerate(doc.get("facts", [])):
            n_facts += 1
            ft, val, q, conf = f.get("fact_type"), str(f.get("value", "")), f.get("quote", ""), f.get("confidence")
            tag = f"{ft}={val[:30]}"
            if ft not in FACT_TYPES:
                problems.append((fn, tag, f"unknown fact_type"))
            types_seen.add(ft)
            if conf not in ("high", "medium", "low"):
                problems.append((fn, tag, f"bad confidence {conf!r}"))
            if ft in DATE_TYPES and not re.fullmatch(r"\d{4}-\d{2}(-\d{2})?", val):
                problems.append((fn, tag, "date not YYYY-MM-DD (or YYYY-MM)"))
            if ft in YESNO and val.lower() not in YESNO[ft]:
                problems.append((fn, tag, f"value not in {sorted(YESNO[ft])}"))
            if ft == "COST_ESTIMATE_USD" and not re.fullmatch(r"\d+(\.\d+)?", val):
                problems.append((fn, tag, "cost not a plain number"))
            if not q:
                problems.append((fn, tag, "empty quote"))
            elif q in text:
                pass
            elif re.sub(r"\s+", " ", q) in flat:
                if fix_ws:
                    f["quote"] = re.sub(r"\s+", " ", q); changed = True
                else:
                    problems.append((fn, tag, "quote matches only after whitespace collapse"))
            elif squash(q) in flat_sq:
                problems.append((fn, tag, "quote matches only after quote-char normalisation"))
            else:
                problems.append((fn, tag, f"QUOTE NOT FOUND: {q[:80]!r}"))
        for r in REQUIRED - types_seen:
            problems.append((fn, r, "required fact type missing"))
        if changed:
            json.dump(doc, open(path, "w"), indent=1, ensure_ascii=False)
    return n_files, n_facts, problems


if __name__ == "__main__":
    d = sys.argv[1]
    n_files, n_facts, problems = check_dir(d, "--fix-whitespace" in sys.argv)
    print(f"{n_files} files, {n_facts} facts, {len(problems)} problems")
    for p in problems:
        print("  ", " | ".join(p))
    sys.exit(1 if problems else 0)
