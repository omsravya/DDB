"""Reverse direction: start from leak-site victims, find the ones that are SEC
registrants, then look at every 8-K they filed around the leak post (any item,
not just 1.05) and check whether it talks about a cyber incident.

This catches incidents disclosed under Item 8.01 / 7.01 (common after the
SEC's May 2024 guidance) and incidents a public company never disclosed.

Usage:
  python3 reverse.py --pilot     # match everything, then inspect a sample of 40
  python3 reverse.py --full
"""

import argparse
import concurrent.futures as cf
import os
import random
import re
import sys
import warnings
from datetime import timedelta

warnings.filterwarnings("ignore")

import pandas as pd
from bs4 import BeautifulSoup
from rapidfuzz import fuzz, process

import pipeline as P

CYBER_TERMS = (
    r"ransomware|cyber ?security incident|cyber[- ]?security event|cyber[- ]?attack|"
    r"unauthorized (?:third[- ]party )?(?:access|activity)|threat actor|malicious (?:actor|activity)|"
    r"(?:data|information) security incident|network (?:security )?incident|encrypted"
)
# Incident-specific: a discovery verb close to a cyber term, in either order.
# This skips risk-factor boilerplate ("a significant data breach could ...").
CYBER_RX = re.compile(
    rf"(?:identified|detected|discovered|became aware|experienced|was notified|"
    rf"were notified|is investigating|responding to)[^.]{{0,160}}(?:{CYBER_TERMS})"
    rf"|(?:{CYBER_TERMS})[^.]{{0,120}}(?:was|were) (?:identified|detected|discovered)",
    re.I,
)
CCTLD_RX = re.compile(r"\.(?:co\.uk|uk|au|com\.au|ca|de|fr|it|es|nl|be|ch|at|jp|cn|in|co\.in|br|com\.br|mx|th|co\.th|sg|my|id|za|co\.za|nz|kr|tw|hk|se|no|dk|fi|pl|pt|ie|tr|ar|cl|co|pe|ph|vn)/?$")

# Words that make a one-word company name too generic to trust on its own.
GENERIC = {"american", "first", "united", "national", "general", "global", "community",
           "southern", "northern", "pacific", "atlantic", "central", "capital", "bank",
           "energy", "health", "home", "life", "group", "trust", "financial", "royal"}


def build_sec_index(companies):
    rows = []
    for c in companies:
        n = P.norm_name(c["name"])
        if n:
            rows.append({**c, "norm": n, "compact": n.replace(" ", "")})
    return pd.DataFrame(rows)


def match_all(leaks, sec):
    """Exact compact-name matches plus high-similarity fuzzy matches.

    rapidfuzz.process.cdist runs on all CPU cores (workers=-1); this is the
    one step where more cores actually help.
    """
    leaks = leaks.copy()
    leaks["norm"] = leaks["victim"].map(P.norm_name)
    leaks["compact"] = leaks["norm"].str.replace(" ", "", regex=False)
    uniq = leaks.loc[leaks["norm"].str.len() >= 3, "norm"].drop_duplicates().tolist()
    sec_names = sec["norm"].tolist()
    sim = process.cdist(uniq, sec_names, scorer=fuzz.ratio, score_cutoff=94,
                        workers=-1, dtype="uint8")
    pairs = {}
    for i, j in zip(*sim.nonzero()):
        pairs.setdefault(uniq[i], []).append((j, int(sim[i, j])))
    compact_ix = {}
    for j, cpt in enumerate(sec["compact"]):
        compact_ix.setdefault(cpt, []).append(j)
    out = []
    for _, v in leaks.iterrows():
        cands = {j: 100 for j in compact_ix.get(v["compact"], [])}
        for j, s in pairs.get(v["norm"], []):
            cands.setdefault(j, s)
        for j, s in cands.items():
            c = sec.iloc[j]
            words = c["norm"].split()
            if len(c["compact"]) < 3 or (len(words) == 1 and words[0] in GENERIC):
                continue
            out.append({**v.drop(["norm", "compact"]).to_dict(), "cik": int(c["cik"]),
                        "ticker": c["ticker"], "sec_name": c["name"], "name_score": s})
    return pd.DataFrame(out)


def eight_ks_near(cik, leak_date, before=30, after=180):
    sub = P.sec_get(f"https://data.sec.gov/submissions/CIK{cik:010d}.json",
                    os.path.join(P.CACHE, "sec", "submissions", f"{cik}.json"))
    if sub is None:
        return None
    filings = P.filings_from_block(sub["filings"]["recent"])
    lo = (leak_date - timedelta(days=before)).date().isoformat()
    hi = (leak_date + timedelta(days=after)).date().isoformat()
    for extra in sub["filings"].get("files", []):
        if extra.get("filingTo", "") >= lo and extra.get("filingFrom", "") <= hi:
            page = P.sec_get(f"https://data.sec.gov/submissions/{extra['name']}",
                             os.path.join(P.CACHE, "sec", "submissions", extra["name"]))
            if page:
                filings += P.filings_from_block(page)
    keep = []
    for f in filings:
        if not (lo <= f["filingDate"] <= hi):
            continue
        # 6-K = foreign private issuers (Sony, Canon, STMicro ...)
        if f["form"] in ("8-K", "8-K/A", "6-K", "6-K/A"):
            keep.append(f)
    sub_meta = {"website": sub.get("website") or "", "state": sub.get("stateOfIncorporation") or "",
                "category": sub.get("category") or ""}
    return keep, sub_meta


def doc_text(cik, acc, name):
    url = f"https://www.sec.gov/Archives/edgar/data/{cik}/{acc}/{name}"
    html = P.sec_get(url, os.path.join(P.CACHE, "sec", "docs", f"{cik}_{acc}_{name}"), as_json=False)
    if html is None:
        return url, None
    text = re.sub(r"\s+", " ", BeautifulSoup(html, "lxml").get_text(" "))
    # drop the forward-looking-statements boilerplate
    cut = re.search(r"(?:cautionary (?:note|statement)|forward[- ]looking statements?)\W", text, re.I)
    if cut and cut.start() > 400:
        text = text[: cut.start()]
    return url, text


def scan_filing(cik, f):
    """Scan the main document, then EX-99 exhibits (press releases)."""
    acc = f["accessionNumber"].replace("-", "")
    names = [f["primaryDocument"]]
    items = f.get("items") or ""
    if f["form"].startswith("6-K") or any(i in items for i in ("1.05", "7.01", "8.01")):
        idx = P.sec_get(f"https://www.sec.gov/Archives/edgar/data/{cik}/{acc}/index.json",
                        os.path.join(P.CACHE, "sec", "docs", f"{cik}_{acc}_index.json"))
        for it in (idx or {}).get("directory", {}).get("item", []):
            n = it.get("name", "")
            if re.search(r"ex[-_]?99|exhibit99|ex99", n, re.I) and n.lower().endswith((".htm", ".html", ".txt")):
                names.append(n)
    for n in names[:4]:
        url, text = doc_text(cik, acc, n)
        if text is None:
            continue
        m = CYBER_RX.search(text)
        if m:
            return True, url, text[max(0, m.start() - 250): m.end() + 350]
    return False, "", ""


def match_confidence(row, website):
    """high: domains agree or leak domain looks like the company name;
    low: leak domain is a foreign country domain; medium otherwise."""
    leak_dom = P.domain_root(row.get("domain") if isinstance(row.get("domain"), str) else "")
    sec_dom = P.domain_root(website)
    if leak_dom and sec_dom and leak_dom == sec_dom:
        return "high"
    if leak_dom and CCTLD_RX.search(leak_dom):
        return "low"
    if leak_dom:
        stem = re.sub(r"[^a-z0-9]", "", leak_dom.split(".")[0])
        sec_compact = P.compact(row["sec_name"])
        if stem and (stem == sec_compact or (len(stem) >= 5 and (stem in sec_compact or sec_compact in stem))):
            return "high"
    return "medium"


def check_pair(row):
    leak_date = pd.Timestamp(row["discovered"])
    got = eight_ks_near(row["cik"], leak_date)
    res = {**row, "history_ok": got is not None, "n_filings_window": 0, "cyber_filing": False,
           "cyber_form": "", "cyber_date": "", "cyber_items": "", "cyber_url": "", "snippet": "",
           "sec_website": "", "match_confidence": ""}
    if got is None:
        return res
    ks, meta = got
    res["sec_website"] = meta["website"]
    res["match_confidence"] = match_confidence(row, meta["website"])
    res["n_filings_window"] = len(ks)
    for f in sorted(ks, key=lambda f: f["filingDate"]):
        hit, url, snip = scan_filing(row["cik"], f)
        if hit:
            res.update(cyber_filing=True, cyber_form=f["form"], cyber_date=f["filingDate"],
                       cyber_items=f["items"], cyber_url=url, snippet=snip,
                       days_leak_minus_filing=(leak_date - pd.Timestamp(f["filingDate"])).days)
            break
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--sample", type=int, default=40)
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()
    tag = "pilot" if args.pilot else "full"

    companies = P.load_companies()
    sec = build_sec_index(companies)
    leaks = pd.read_csv(os.path.join(P.OUT, "leak_posts_all.csv"))
    print(f"[R1] matching {len(leaks)} leak posts to {len(sec)} SEC registrants ...", flush=True)
    matched = match_all(leaks, sec)
    matched = matched.drop_duplicates(["cik", "group", "discovered"])
    matched.to_csv(os.path.join(P.OUT, f"reverse_matches_{tag}.csv"), index=False)
    print(f"     {len(matched)} leak posts matched to {matched['cik'].nunique()} public companies", flush=True)

    todo = matched.to_dict("records")
    if args.pilot:
        random.seed(7)
        todo = random.sample(todo, min(args.sample, len(todo)))
    print(f"[R2] checking 8-Ks around {len(todo)} leak posts ...", flush=True)
    with cf.ThreadPoolExecutor(args.workers) as ex:
        results = list(ex.map(check_pair, todo))
    res = pd.DataFrame(results)
    res.to_csv(os.path.join(P.OUT, f"reverse_checked_{tag}.csv"), index=False)
    print(f"     history fetched: {int(res['history_ok'].sum())}/{len(res)}")
    print(f"     any 8-K/6-K in window: {int((res['n_filings_window'] > 0).sum())}/{len(res)}")
    print(f"     match confidence: {res['match_confidence'].value_counts().to_dict()}")
    print(f"     cyber filing found: {int(res['cyber_filing'].sum())}/{len(res)}")
    for conf in ("high", "medium", "low"):
        sub = res[res["match_confidence"] == conf]
        if len(sub):
            print(f"       {conf}: {int(sub['cyber_filing'].sum())}/{len(sub)}")
    print(f"     http: {P.stats}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
