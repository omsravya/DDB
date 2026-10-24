"""Pilot pipeline: SEC 8-K Item 1.05 cyber filings x ransomware leak-site posts.

Steps (each reports a success rate so the full run can't fail silently):
  1. SEC filing history per company -> every 8-K / 8-K/A tagged Item 1.05
  2. Fetch each filing's main document -> extract the Item 1.05 text -> rule-based facts
  3. Match filers to ransomware.live leak-site victims (name similarity + date window)
  4. Pull daily stock prices around each event (yfinance)

Usage:
  python3 pipeline.py --pilot        # ~300 random companies + a known-incident list
  python3 pipeline.py --full         # every company in the SEC ticker list

Everything is cached under cache/, so re-runs and the full run reuse downloads.
"""

import argparse
import concurrent.futures as cf
import json
import os
import random
import re
import sys
import threading
import time
import warnings
from datetime import date, datetime, timedelta

warnings.filterwarnings("ignore")

import pandas as pd
import requests
from bs4 import BeautifulSoup
from rapidfuzz import fuzz

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "cache")
OUT = os.path.join(HERE, "output")
SEC_UA = "IIM Indore ransomware research guntupallis@iimidr.ac.in"
RULE_START = "2023-12-18"  # SEC cyber disclosure rule effective date for Item 1.05

# Tickers of firms known to have filed Item 1.05 8-Ks. Used as a positive
# control in the pilot: if the pipeline can't find these, it is broken.
KNOWN_FILERS = ["CLX", "MGM", "UNH", "MSFT", "HPE", "DAIO", "HAL", "DNUT",
                "JCI", "T", "PRU", "VFC", "HUBB", "LDOS", "CNE"]


# --------------------------------------------------------------------------
# HTTP with a global rate limit and a disk cache
# --------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, per_second):
        self.interval = 1.0 / per_second
        self.lock = threading.Lock()
        self.next_time = 0.0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            if now < self.next_time:
                time.sleep(self.next_time - now)
            self.next_time = max(now, self.next_time) + self.interval


SEC_LIMIT = RateLimiter(8)  # SEC fair-access cap is 10/s; stay under it
RL_LIMIT = RateLimiter(2)   # be polite to ransomware.live
session = requests.Session()
stats = {"http_ok": 0, "http_fail": 0, "cache_hit": 0}


def fetch(url, cache_path, limiter, headers=None, as_json=True, retries=3):
    if os.path.exists(cache_path):
        stats["cache_hit"] += 1
        with open(cache_path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh) if as_json else fh.read()
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    for attempt in range(retries):
        limiter.wait()
        try:
            r = session.get(url, headers=headers or {}, timeout=30)
        except requests.RequestException:
            time.sleep(2 ** attempt)
            continue
        if r.status_code == 200:
            stats["http_ok"] += 1
            with open(cache_path, "w", encoding="utf-8") as fh:
                fh.write(r.text)
            return r.json() if as_json else r.text
        if r.status_code == 404:
            break
        time.sleep(2 ** attempt)  # 403/429/5xx: back off
    stats["http_fail"] += 1
    return None


def sec_get(url, cache_path, as_json=True):
    return fetch(url, cache_path, SEC_LIMIT, {"User-Agent": SEC_UA}, as_json)


# --------------------------------------------------------------------------
# Step 1: find Item 1.05 filings
# --------------------------------------------------------------------------
def load_companies():
    data = sec_get("https://www.sec.gov/files/company_tickers.json",
                   os.path.join(CACHE, "sec", "company_tickers.json"))
    rows = {}
    for rec in data.values():
        cik = int(rec["cik_str"])
        # keep the first ticker per CIK (multiple share classes share a CIK)
        rows.setdefault(cik, {"cik": cik, "ticker": rec["ticker"], "name": rec["title"]})
    return list(rows.values())


def filings_from_block(block):
    keys = ["accessionNumber", "filingDate", "acceptanceDateTime", "form",
            "items", "primaryDocument", "reportDate"]
    n = len(block.get("form", []))
    return [{k: (block.get(k) or [""] * n)[i] for k in keys} for i in range(n)]


def cyber_filings_for(company):
    cik = company["cik"]
    sub = sec_get(f"https://data.sec.gov/submissions/CIK{cik:010d}.json",
                  os.path.join(CACHE, "sec", "submissions", f"{cik}.json"))
    if sub is None:
        return None, []
    filings = filings_from_block(sub["filings"]["recent"])
    # Large filers: older filings live in extra pages. Fetch the ones that
    # overlap the rule period so we don't miss early-2024 filings.
    for extra in sub["filings"].get("files", []):
        if extra.get("filingTo", "") >= RULE_START:
            page = sec_get(f"https://data.sec.gov/submissions/{extra['name']}",
                           os.path.join(CACHE, "sec", "submissions", extra["name"]))
            if page:
                filings += filings_from_block(page)
    company["website"] = sub.get("website") or ""
    company["sic"] = sub.get("sic") or ""
    company["sic_desc"] = sub.get("sicDescription") or ""
    company["former_names"] = [f.get("name", "") for f in sub.get("formerNames", [])]
    hits = []
    for f in filings:
        if f["form"] in ("8-K", "8-K/A") and "1.05" in (f["items"] or "") \
                and f["filingDate"] >= RULE_START:
            hits.append({**f, "cik": cik, "ticker": company["ticker"],
                         "company": company["name"]})
    return sub, hits


# --------------------------------------------------------------------------
# Step 2: read the filing and extract facts (rule-based baseline)
# --------------------------------------------------------------------------
MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
DATE_RX = re.compile(rf"\b({MONTHS})\s+(\d{{1,2}}),\s+(\d{{4}})")

FACT_RULES = {
    "RANSOMWARE": r"ransomware",
    "ENCRYPTION": r"encrypt",
    "DATA_EXFILTRATION": r"exfiltrat|stole|stolen|took (?:certain )?data|copied|acquired (?:certain )?(?:data|files|information)",
    "OPERATIONAL_DISRUPTION": r"disrupt|outage|offline|shut ?down|took (?:certain )?systems|interruption|impair",
    "SYSTEMS_SHUTDOWN_PROACTIVE": r"proactively (?:took|shut|isolat|disconnect)|took (?:certain )?systems offline|as a precaution",
    "CONTAINED_LANGUAGE": r"contain(?:ed|ment)|remediat|restored|resum(?:e|ed) normal",
    "NOT_MATERIAL_YET": r"not (?:yet )?(?:determined|concluded)|has not had a material|not reasonably likely to (?:have a )?material|no material impact|does not (?:currently )?believe .{0,60}material",
    "MATERIAL_IMPACT": r"(?:has|have) materially (?:impacted|affected)|reasonably likely to materially (?:impact|affect)|material (?:adverse )?impact on (?:its|the company)",
    "LAW_ENFORCEMENT": r"law enforcement|FBI",
    "EXTERNAL_EXPERTS": r"third[- ]party (?:cybersecurity|forensic)|cybersecurity experts|forensic (?:experts|firm|investigat)|incident response",
    "INSURANCE": r"insurance",
    "THREAT_ACTOR_NAMED": r"threat actor|criminal group|nation[- ]state",
}


def extract_item_105(text):
    """Return the Item 1.05 section text, or '' if not found."""
    # "Item 1.05" can appear on the cover page, in a table of contents and in
    # the body. Take every occurrence and keep the longest section.
    best = ""
    for m in re.finditer(r"Item\s*1\.05\.?", text, re.I):
        tail = text[m.end():]
        end = re.search(r"\n\s*Item\s*(?:[2-9]\.\d\d|1\.0[6-9]|8\.01|9\.01)|SIGNATURES?\b|Forward[- ]Looking Statements", tail, re.I)
        section = tail[: end.start()] if end else tail[:8000]
        if len(section.strip()) > len(best.strip()):
            best = section
    return best


def read_filing(f):
    acc = f["accessionNumber"].replace("-", "")
    url = f"https://www.sec.gov/Archives/edgar/data/{f['cik']}/{acc}/{f['primaryDocument']}"
    html = sec_get(url, os.path.join(CACHE, "sec", "docs", f"{f['cik']}_{acc}.htm"), as_json=False)
    out = {"accessionNumber": f["accessionNumber"], "doc_url": url, "doc_ok": html is not None}
    if html is None:
        return out
    text = BeautifulSoup(html, "lxml").get_text("\n")
    text = re.sub(r"[ \t\xa0]+", " ", text)
    section = extract_item_105(text)
    out["section_found"] = bool(section.strip())
    out["section_chars"] = len(section)
    body = section if section.strip() else text
    for name, rx in FACT_RULES.items():
        out[name] = bool(re.search(rx, body, re.I))
    dates = [datetime.strptime(" ".join(d), "%B %d %Y").date() for d in DATE_RX.findall(body)]
    filed = date.fromisoformat(f["filingDate"])
    dates = [d for d in dates if filed - timedelta(days=400) <= d <= filed]
    out["first_date_in_text"] = min(dates).isoformat() if dates else ""
    out["section_excerpt"] = re.sub(r"\s+", " ", body)[:600]
    return out


# --------------------------------------------------------------------------
# Step 3: ransomware.live leak-site victims
# --------------------------------------------------------------------------
def load_leak_posts(start=(2023, 6), end=None):
    end = end or (date.today().year, date.today().month)
    y, m = start
    posts = []
    while (y, m) <= end:
        data = fetch(f"https://api.ransomware.live/v2/victims/{y}/{m:02d}",
                     os.path.join(CACHE, "rl", f"{y}-{m:02d}.json"), RL_LIMIT)
        for v in data or []:
            posts.append({
                "victim": v.get("victim") or v.get("post_title") or "",
                "group": v.get("group") or v.get("group_name") or "",
                "discovered": (v.get("discovered") or "")[:10],
                "attackdate": (v.get("attackdate") or "")[:10],
                "country": v.get("country") or "",
                "domain": (v.get("domain") or "").lower(),
                "activity": v.get("activity") or "",
                "press_source": (v.get("press") or {}).get("source", "") if isinstance(v.get("press"), dict) else "",
            })
        m += 1
        if m == 13:
            y, m = y + 1, 1
    return pd.DataFrame(posts)


SUFFIX_RX = re.compile(
    r"\b(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|plc|lp|l\.p|"
    r"holdings?|group|the|n\.?v|s\.?a|ag|se|international|intl|/de|/md|/ny|/nv)\b\.?", re.I)


def norm_name(s):
    s = (s or "").lower()
    s = re.sub(r"https?://|www\.", "", s)
    s = re.sub(r"\.(com|net|org|io|us|co\.uk|de|fr)\b.*$", "", s)
    s = s.replace("&", " and ")
    s = SUFFIX_RX.sub(" ", s)
    s = re.sub(r"[^a-z0-9 ]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def compact(s):
    return norm_name(s).replace(" ", "")


def domain_root(url):
    url = (url or "").lower()
    url = re.sub(r"^https?://", "", url)
    url = re.sub(r"^www\.", "", url)
    return url.split("/")[0]


def match_leaks(filings_df, companies_by_cik, leaks, window_days=365):
    leaks = leaks.copy()
    leaks["norm"] = leaks["victim"].map(norm_name)
    leaks["dom"] = leaks["domain"].map(domain_root)
    leaks["disc_date"] = pd.to_datetime(leaks["discovered"], errors="coerce")
    rows = []
    for cik, grp in filings_df.groupby("cik"):
        comp = companies_by_cik[cik]
        names = [comp["name"]] + comp.get("former_names", [])
        norms = {norm_name(n) for n in names if norm_name(n)}
        compacts = {compact(n) for n in names if compact(n)}
        site = domain_root(comp.get("website", ""))
        first = pd.to_datetime(grp["filingDate"].min())
        lo, hi = first - timedelta(days=window_days), first + timedelta(days=window_days)
        cand = leaks[(leaks["disc_date"] >= lo) & (leaks["disc_date"] <= hi)]
        for _, v in cand.iterrows():
            score = max((fuzz.token_set_ratio(n, v["norm"]) for n in norms), default=0)
            dom_hit = bool(site) and bool(v["dom"]) and (site == v["dom"])
            exact = v["norm"].replace(" ", "") in compacts  # "V F CORP" == "VF Corporation"
            # token_set_ratio is generous with short names; require the short
            # side to be reasonably long, or an exact / domain hit.
            short = min((len(n) for n in norms), default=0)
            if dom_hit or exact or (score >= 92 and short >= 4 and len(v["norm"]) >= 4):
                rows.append({
                    "cik": cik, "ticker": comp["ticker"], "company": comp["name"],
                    "first_105_filing": first.date().isoformat(),
                    "leak_victim": v["victim"], "leak_group": v["group"],
                    "leak_discovered": v["discovered"], "leak_attackdate": v["attackdate"],
                    "leak_domain": v["domain"], "match_score": score, "domain_match": dom_hit,
                    "days_leak_minus_filing": (v["disc_date"] - first).days,
                })
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------
# Step 4: stock prices
# --------------------------------------------------------------------------
def price_check(tickers_dates):
    import yfinance as yf
    ok, fail = [], []
    for ticker, d in tickers_dates:
        d = pd.Timestamp(d)
        try:
            px = yf.download(ticker.replace(".", "-"), start=d - timedelta(days=45),
                             end=d + timedelta(days=45), progress=False, auto_adjust=True)
        except Exception as exc:  # network / delisting
            fail.append((ticker, str(exc)[:80]))
            continue
        if px is None or px.empty:
            fail.append((ticker, "no rows"))
        else:
            ok.append((ticker, len(px)))
    return ok, fail


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()
    if not (args.pilot or args.full):
        ap.error("pass --pilot or --full")
    tag = "pilot" if args.pilot else "full"
    os.makedirs(OUT, exist_ok=True)
    report = {"mode": tag, "started": datetime.now().isoformat(timespec="seconds")}
    t0 = time.time()

    # Step 1 -------------------------------------------------------------
    companies = load_companies()
    by_ticker = {c["ticker"]: c for c in companies}
    if args.pilot:
        random.seed(42)
        known = [by_ticker[t] for t in KNOWN_FILERS if t in by_ticker]
        sample = random.sample(companies, args.n)
        targets = {c["cik"]: c for c in known + sample}.values()
        report["known_controls_in_ticker_list"] = [c["ticker"] for c in known]
    else:
        targets = companies
    targets = list(targets)
    print(f"[1] fetching filing history for {len(targets)} companies ...", flush=True)
    all_hits, sub_fail = [], 0
    with cf.ThreadPoolExecutor(args.workers) as ex:
        futs = {ex.submit(cyber_filings_for, c): c for c in targets}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            sub, hits = fut.result()
            if sub is None:
                sub_fail += 1
            all_hits += hits
            if i % 500 == 0:
                print(f"    {i}/{len(targets)}  filings so far: {len(all_hits)}", flush=True)
    filings_df = pd.DataFrame(all_hits)
    report["step1_companies"] = len(targets)
    report["step1_history_fetch_failures"] = sub_fail
    report["step1_item105_filings"] = len(filings_df)
    report["step1_item105_companies"] = int(filings_df["cik"].nunique()) if len(filings_df) else 0
    if args.pilot:
        found = set(filings_df["ticker"]) if len(filings_df) else set()
        report["known_controls_found"] = sorted(found & set(KNOWN_FILERS))
        report["known_controls_missed"] = sorted(set(report["known_controls_in_ticker_list"]) - found)
        random_ciks = {c["cik"] for c in sample}
        report["random_sample_companies_with_105"] = int(filings_df[filings_df["cik"].isin(random_ciks)]["cik"].nunique()) if len(filings_df) else 0
    print(f"    -> {len(filings_df)} Item 1.05 filings from {report['step1_item105_companies']} companies", flush=True)
    if filings_df.empty:
        print("no filings found; stopping"); json.dump(report, open(os.path.join(OUT, f"report_{tag}.json"), "w"), indent=2)
        return 1

    # Step 2 -------------------------------------------------------------
    print(f"[2] reading {len(filings_df)} filing documents ...", flush=True)
    with cf.ThreadPoolExecutor(args.workers) as ex:
        docs = list(ex.map(read_filing, filings_df.to_dict("records")))
    docs_df = pd.DataFrame(docs)
    filings_df = filings_df.merge(docs_df, on="accessionNumber", how="left")
    filings_df.to_csv(os.path.join(OUT, f"item105_filings_{tag}.csv"), index=False)
    report["step2_docs_fetched"] = int(filings_df["doc_ok"].sum())
    report["step2_section_found"] = int(filings_df.get("section_found", pd.Series(dtype=bool)).fillna(False).sum())
    report["step2_date_parsed"] = int((filings_df["first_date_in_text"].fillna("") != "").sum())
    report["step2_fact_rates"] = {k: round(float(filings_df[k].fillna(False).mean()), 2) for k in FACT_RULES}

    # Step 3 -------------------------------------------------------------
    print("[3] loading leak-site posts and matching ...", flush=True)
    leaks = load_leak_posts()
    leaks.to_csv(os.path.join(OUT, "leak_posts_all.csv"), index=False)
    by_cik = {c["cik"]: c for c in targets}
    matches = match_leaks(filings_df, by_cik, leaks)
    matches.to_csv(os.path.join(OUT, f"leak_matches_{tag}.csv"), index=False)
    report["step3_leak_posts_loaded"] = len(leaks)
    report["step3_leak_months_failed"] = stats["http_fail"]
    report["step3_companies_with_leak_match"] = int(matches["cik"].nunique()) if len(matches) else 0

    # Step 4 -------------------------------------------------------------
    first_by = filings_df.groupby("ticker")["filingDate"].min().reset_index()
    sample_px = first_by.head(25 if args.pilot else len(first_by)).values.tolist()
    print(f"[4] price check for {len(sample_px)} tickers ...", flush=True)
    ok, fail = price_check(sample_px)
    report["step4_price_ok"] = len(ok)
    report["step4_price_fail"] = fail

    report["http"] = stats
    report["minutes"] = round((time.time() - t0) / 60, 1)
    json.dump(report, open(os.path.join(OUT, f"report_{tag}.json"), "w"), indent=2, default=str)
    print(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
