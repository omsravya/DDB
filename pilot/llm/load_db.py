"""Load verified facts into a SQLite copy of Schuetz's schema (plus the
columns the event study needs). Also loads leak-site matches as announcements
from the 'Dark Web Leak Site' source so one incident shows both channels.

Usage: python3 load_db.py   -> writes ../output/ransomware_pilot.sqlite
"""
import json
import os
import sqlite3

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "output")
DB = os.path.join(OUT, "ransomware_pilot.sqlite")

SCHEMA = """
CREATE TABLE company (company_id INTEGER PRIMARY KEY, company_name TEXT NOT NULL, industry TEXT, country TEXT,
    cusip TEXT, cik INTEGER UNIQUE, ticker TEXT, website TEXT);
CREATE TABLE incident (incident_id INTEGER PRIMARY KEY, company_id INTEGER REFERENCES company, incident_date DATE,
    description TEXT);
CREATE TABLE source (source_id INTEGER PRIMARY KEY, source_name TEXT, source_type TEXT);
CREATE TABLE threat_actor (threat_actor_id INTEGER PRIMARY KEY, actor_name TEXT UNIQUE);
CREATE TABLE announcement (announcement_id INTEGER PRIMARY KEY, incident_id INTEGER REFERENCES incident,
    source_id INTEGER REFERENCES source, url TEXT, announcement_date DATE, announcement_timestamp TEXT,
    content TEXT, channel TEXT, form_type TEXT, accession_number TEXT UNIQUE, threat_actor_id INTEGER REFERENCES threat_actor,
    is_amendment INTEGER DEFAULT 0, summary TEXT, new_vs_prior TEXT);
CREATE TABLE fact_type (fact_type_id INTEGER PRIMARY KEY, fact_name TEXT UNIQUE NOT NULL, description TEXT);
CREATE TABLE fact (fact_id INTEGER PRIMARY KEY, incident_id INTEGER REFERENCES incident,
    announcement_id INTEGER REFERENCES announcement, fact_type_id INTEGER REFERENCES fact_type, value TEXT,
    confidence_level TEXT, coded_by INTEGER, coded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_quote TEXT, note TEXT, extraction_method TEXT);
CREATE TABLE fact_review (review_id INTEGER PRIMARY KEY, fact_id INTEGER REFERENCES fact, reviewer_id INTEGER,
    decision TEXT, comments TEXT, reviewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE users (user_id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE, role TEXT);
"""


def main():
    if os.path.exists(DB):
        os.remove(DB)
    con = sqlite3.connect(DB)
    con.executescript(SCHEMA)
    con.execute("INSERT INTO users VALUES (1,'LLM extractor (Claude, pilot)',NULL,'coder'),"
                "(2,'LLM verifier (Claude, pilot)',NULL,'reviewer'),(3,'Sravya Guntupalli','guntupallis@iimidr.ac.in','coder')")
    con.execute("INSERT INTO source VALUES (1,'SEC EDGAR 8-K','Regulatory'),(2,'Dark Web Leak Site','Leak Site'),(3,'Reuters','News')")

    schema_md = open(os.path.join(HERE, "FACT_SCHEMA.md")).read()
    import re
    for i, (name, desc) in enumerate(re.findall(r"^- ([A-Z_]+) : (.+)$", schema_md, re.M), 1):
        con.execute("INSERT INTO fact_type VALUES (?,?,?)", (i, name, desc.strip()))
    ft_id = {r[0]: r[1] for r in con.execute("SELECT fact_name, fact_type_id FROM fact_type")}

    manifest = json.load(open(os.path.join(HERE, "manifest.json")))
    filings = pd.read_csv(os.path.join(OUT, "item105_filings_pilot.csv"))
    comp_id, inc_id = {}, {}
    for m in manifest:
        if m["cik"] not in comp_id:
            cur = con.execute("INSERT INTO company (company_name, country, cik, ticker) VALUES (?,?,?,?)",
                              (m["company"], "United States", m["cik"], m["ticker"]))
            comp_id[m["cik"]] = cur.lastrowid
    # one incident per company (pilot: each company has one incident; amendments share it)
    for m in sorted(manifest, key=lambda x: x["filing_date"]):
        if m["cik"] not in inc_id:
            cur = con.execute("INSERT INTO incident (company_id, incident_date, description) VALUES (?,?,?)",
                              (comp_id[m["cik"]], None, f"Cybersecurity incident disclosed by {m['company']} (first 8-K {m['filing_date']})"))
            inc_id[m["cik"]] = cur.lastrowid

    n_facts = 0
    for m in manifest:
        jpath = os.path.join(HERE, "verified", m["file"][:-4] + ".json")
        doc = json.load(open(jpath))
        text = open(os.path.join(HERE, "input", m["file"]), encoding="utf-8").read().split("=== TEXT ===", 1)[-1].strip()
        cur = con.execute(
            "INSERT INTO announcement (incident_id, source_id, url, announcement_date, announcement_timestamp, content, "
            "channel, form_type, accession_number, is_amendment, summary, new_vs_prior) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (inc_id[m["cik"]], 1, m["url"], m["filing_date"], m["accepted"], text, "regulatory", m["form"],
             m["accession"], int(m["form"].endswith("/A")), doc.get("summary", ""), doc.get("new_vs_prior", "")))
        aid = cur.lastrowid
        for f in doc["facts"]:
            con.execute("INSERT INTO fact (incident_id, announcement_id, fact_type_id, value, confidence_level, coded_by, "
                        "source_quote, note, extraction_method) VALUES (?,?,?,?,?,?,?,?,?)",
                        (inc_id[m["cik"]], aid, ft_id[f["fact_type"]], str(f["value"]), f["confidence"], 1,
                         f["quote"], f.get("note", ""), "llm+verifier"))
            n_facts += 1
        # the verifier pass counts as an approving review of every surviving fact
        con.execute("INSERT INTO fact_review (fact_id, reviewer_id, decision, comments) "
                    "SELECT fact_id, 2, 'Approved', 'quote verified verbatim; cross-checked by independent agent' FROM fact WHERE announcement_id=?", (aid,))
        # set incident date from earliest discovery date fact
        d = con.execute("SELECT MIN(value) FROM fact WHERE incident_id=? AND fact_type_id=?",
                        (inc_id[m["cik"]], ft_id["INCIDENT_DISCOVERY_DATE"])).fetchone()[0]
        if d:
            con.execute("UPDATE incident SET incident_date=COALESCE(incident_date, ?) WHERE incident_id=?", (d, inc_id[m["cik"]]))

    # leak-site announcements
    leaks = pd.read_csv(os.path.join(OUT, "leak_matches_pilot.csv"))
    n_leaks = 0
    for _, r in leaks.iterrows():
        if r["cik"] not in inc_id:
            continue
        actor = con.execute("INSERT OR IGNORE INTO threat_actor (actor_name) VALUES (?)", (r["leak_group"],))
        ta = con.execute("SELECT threat_actor_id FROM threat_actor WHERE actor_name=?", (r["leak_group"],)).fetchone()[0]
        con.execute("INSERT INTO announcement (incident_id, source_id, url, announcement_date, content, channel, threat_actor_id) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (inc_id[r["cik"]], 2, "", r["leak_discovered"],
                     f"Victim '{r['leak_victim']}' posted on {r['leak_group']} leak site (ransomware.live, discovered {r['leak_discovered']})",
                     "darknet", ta))
        n_leaks += 1
    con.commit()
    print(f"loaded {len(comp_id)} companies, {len(inc_id)} incidents, {len(manifest)} SEC announcements, "
          f"{n_leaks} leak-site announcements, {n_facts} facts -> {DB}")


if __name__ == "__main__":
    main()
