"""Shared logic for loading the security-events CSV into the research database.

The CSV is a list of disclosed data-breach and ransomware events for public
companies. Each row becomes one ``company`` (deduplicated by CUSIP, else by
cleaned name), one ``incident``, one ``announcement`` (linked to a ``source``
derived from the CSV's ``dataset`` column), several ``fact`` rows, and a
``fact_review`` for roughly half of the facts.

``industry`` and ``country`` are not in the CSV, so they are synthesised
deterministically (seeded from CUSIP / name) purely so the dashboard charts have
variety. Everything else is taken straight from the file.

This module is used both by ``scripts/import_security_events.py`` (command line)
and by the ``/import-data`` upload page in the web app.
"""

import csv
import hashlib
import io
from datetime import datetime

import psycopg2.extras

INDUSTRIES = [
    "Healthcare", "Finance", "Technology", "Retail", "Manufacturing", "Energy",
    "Transportation", "Insurance", "Telecommunications", "Media", "Education",
    "Hospitality", "Pharmaceuticals", "Real Estate", "Consumer Goods",
]
COUNTRIES_US_HEAVY = (
    ["United States"] * 12
    + ["United Kingdom", "Canada", "Germany", "Japan", "France", "Australia",
       "Brazil", "India", "Netherlands", "Switzerland"]
)

CODERS = [1, 2, 3, 34, 101]
REVIEWERS = [100, 133, 35, 68]
REVIEW_DECISIONS = ["Approved", "Approved", "Approved", "Rejected", "Pending"]

FACT_TYPES = {
    "RANSOMWARE": "Whether the incident involved ransomware",
    "DATA_BREACH": "Whether the incident involved a data breach",
    "RECORDS_LOST": "Number of records lost or exposed",
    "BREACH_COST_USD": "Estimated financial cost of the breach in USD",
    "OPERATIONAL_DISRUPTION": "Whether business operations were disrupted",
    "INFORMATION_TYPE": "Category of information involved",
    "SEVERITY": "Whether the incident was classified as severe",
}

# The importer needs at least a company name and something to date the incident.
REQUIRED_COLUMNS = ("cname", "disclosure_date")


class ImportError_(Exception):
    """Raised when the uploaded file is not a security-events CSV we can read."""


def _seed(text):
    return int(hashlib.md5(text.encode("utf-8")).hexdigest(), 16)


def _pick(seq, key):
    return seq[_seed(key) % len(seq)]


def clean_name(raw):
    raw = (raw or "").strip()
    if raw.startswith("|") and raw.endswith("|"):
        parts = [p.strip() for p in raw.strip("|").split("|") if p.strip()]
        return parts[0] if parts else raw.strip("|")
    return raw


def parse_number(raw):
    """Handle values like '1,9e+07', '8e+06', '802200000', 'NA'."""
    if raw is None:
        return None
    raw = raw.strip()
    if raw in ("", "NA", "N/A"):
        return None
    raw = raw.replace(",", ".")
    try:
        return int(float(raw))
    except ValueError:
        return None


def parse_date(raw):
    raw = (raw or "").strip()
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y"):
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    return None


def flag(raw):
    return str(raw).strip() == "1"


def build_description(name, ransomware, databreach, info_type, year):
    kinds = []
    if ransomware:
        kinds.append("ransomware attack")
    if databreach:
        kinds.append("data breach")
    kind = " and ".join(kinds) or "security incident"
    tail = ""
    if info_type and info_type not in ("NA", "Not Disclosed", ""):
        tail = f" involving {info_type.lower()} information"
    year_part = f" in {year}" if year and year != "NA" else ""
    return f"{name} disclosed a {kind}{tail}{year_part}."


def _read_rows(source):
    """Accept a path, bytes, or a text/binary file-like; return (header, rows)."""
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8-sig", errors="replace")
    elif hasattr(source, "read"):
        raw = source.read()
        text = raw.decode("utf-8-sig", errors="replace") if isinstance(raw, (bytes, bytearray)) else raw
    else:
        with open(source, "r", encoding="utf-8-sig") as fh:
            text = fh.read()

    first_line = text.split("\n", 1)[0]
    delimiter = ";" if first_line.count(";") >= first_line.count(",") else ","
    rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))
    rows = [r for r in rows if any(cell.strip() for cell in r)]
    if not rows:
        raise ImportError_("The file is empty.")
    return rows[0], rows[1:]


def _column_index(header):
    index = {}
    for i, name in enumerate(header):
        index[name.strip().strip('"').lower()] = i
    missing = [c for c in REQUIRED_COLUMNS if c not in index]
    if missing:
        raise ImportError_(
            "This does not look like a security-events export. Missing column(s): "
            + ", ".join(missing)
            + ". Expected a semicolon-delimited file with columns like "
            "cname, cusip, disclosure_date, ransomware, databreach, dataset."
        )
    return index


def _ensure_fact_types(cur):
    ids = {}
    for name, description in FACT_TYPES.items():
        cur.execute("SELECT fact_type_id FROM fact_type WHERE fact_name = %s", (name,))
        row = cur.fetchone()
        if row:
            ids[name] = row[0]
        else:
            cur.execute(
                "INSERT INTO fact_type (fact_name, description) VALUES (%s, %s) RETURNING fact_type_id",
                (name, description),
            )
            ids[name] = cur.fetchone()[0]
    return ids


def _source_for_dataset(cur, dataset, cache):
    label = {
        "audit_analytics": "Audit Analytics",
        "ransomware": "Ransomware Tracker",
        "both_merged": "Merged Dataset",
        "merged": "Merged Dataset",
    }.get(dataset, dataset or "Unknown")
    if label in cache:
        return cache[label]
    cur.execute("SELECT source_id FROM source WHERE source_name = %s", (label,))
    row = cur.fetchone()
    if row:
        cache[label] = row[0]
        return row[0]
    cur.execute(
        "INSERT INTO source (source_name, source_type) VALUES (%s, %s) RETURNING source_id",
        (label, "Research Dataset"),
    )
    cache[label] = cur.fetchone()[0]
    return cache[label]


def import_csv(source, *, force=False, skip_threshold=100):
    """Load ``source`` into the database.

    Returns a summary dict. When the incident table already has more than
    ``skip_threshold`` rows and ``force`` is false, nothing is written and
    ``{"skipped": True, "existing": <count>}`` is returned.
    """
    import app  # lazy import keeps this module usable without a request context

    header, data_rows = _read_rows(source)
    col = _column_index(header)

    def cell(row, name):
        idx = col.get(name)
        return row[idx] if idx is not None and idx < len(row) else ""

    with app.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM incident")
        existing = cur.fetchone()[0]
        cur.close()

    if existing > skip_threshold and not force:
        return {"skipped": True, "existing": existing, "rows": len(data_rows)}

    with app.get_conn() as conn:
        cur = conn.cursor()

        if force:
            cur.execute("DELETE FROM fact_review")
            cur.execute("DELETE FROM fact")
            cur.execute("DELETE FROM announcement")
            cur.execute("DELETE FROM incident")
            cur.execute("DELETE FROM company WHERE cusip IS NOT NULL")

        fact_type_ids = _ensure_fact_types(cur)

        # --- companies -----------------------------------------------------
        company_ids = {}
        cur.execute("SELECT company_id, cusip, company_name FROM company")
        for cid, cusip, cname in cur.fetchall():
            company_ids[(cusip or "").strip() or cname.strip().lower()] = cid

        new_companies = {}
        for r in data_rows:
            cusip = cell(r, "cusip").strip()
            name = clean_name(cell(r, "cname"))
            if not name:
                continue
            key = cusip if cusip and cusip != "NA" else name.lower()
            if key in company_ids or key in new_companies:
                continue
            seed_key = cusip if cusip and cusip != "NA" else name
            new_companies[key] = (
                name,
                _pick(INDUSTRIES, seed_key + "|ind"),
                _pick(COUNTRIES_US_HEAVY, seed_key + "|ctry"),
                cusip if cusip and cusip != "NA" else None,
            )

        if new_companies:
            inserted = psycopg2.extras.execute_values(
                cur,
                "INSERT INTO company (company_name, industry, country, cusip) VALUES %s "
                "RETURNING company_id, company_name, cusip",
                list(new_companies.values()),
                fetch=True,
            )
            by_name_cusip = {((c or "").strip(), n): i for i, n, c in inserted}
            for key, (name, _ind, _ctry, cusip) in new_companies.items():
                company_ids[key] = by_name_cusip[((cusip or "").strip(), name)]

        # --- incidents / announcements / facts ---------------------------
        source_cache = {}
        incident_rows = []
        for r in data_rows:
            name = clean_name(cell(r, "cname"))
            if not name:
                continue
            cusip = cell(r, "cusip").strip()
            key = cusip if cusip and cusip != "NA" else name.lower()
            cid = company_ids.get(key)
            if cid is None:
                continue
            ransomware = flag(cell(r, "ransomware"))
            databreach = flag(cell(r, "databreach"))
            info_type = cell(r, "breach_information_type").strip()
            year = cell(r, "year").strip()
            disc = parse_date(cell(r, "disclosure_date")) or parse_date(cell(r, "start_date"))
            src_id = _source_for_dataset(cur, cell(r, "dataset").strip(), source_cache)
            incident_rows.append({
                "cid": cid, "date": disc, "src_id": src_id, "name": name,
                "desc": build_description(name, ransomware, databreach, info_type, year),
                "ransomware": ransomware, "databreach": databreach,
                "records": parse_number(cell(r, "records_lost")),
                "cost": parse_number(cell(r, "breach_cost")),
                "ops": cell(r, "operational_disruptions").strip(),
                "info_type": info_type,
                "severe": flag(cell(r, "severe")),
            })

        if not incident_rows:
            conn.rollback()
            cur.close()
            raise ImportError_("No usable rows found in the file.")

        inc_ids = psycopg2.extras.execute_values(
            cur,
            "INSERT INTO incident (company_id, incident_date, description) VALUES %s RETURNING incident_id",
            [(x["cid"], x["date"], x["desc"]) for x in incident_rows],
            fetch=True,
        )
        for x, (iid,) in zip(incident_rows, inc_ids):
            x["iid"] = iid

        ann_ids = psycopg2.extras.execute_values(
            cur,
            "INSERT INTO announcement (incident_id, source_id, url, announcement_date, content) "
            "VALUES %s RETURNING announcement_id",
            [(x["iid"], x["src_id"], "", x["date"], f"Public disclosure for {x['name']}.")
             for x in incident_rows],
            fetch=True,
        )
        for x, (aid,) in zip(incident_rows, ann_ids):
            x["aid"] = aid

        fact_values = []
        for x in incident_rows:
            coder = _pick(CODERS, x["name"])
            base = (x["iid"], x["aid"])

            def add(ftype, value, note):
                fact_values.append(base + (fact_type_ids[ftype], str(value), note, coder))

            add("RANSOMWARE", "Yes" if x["ransomware"] else "No", "From dataset flag")
            add("DATA_BREACH", "Yes" if x["databreach"] else "No", "From dataset flag")
            if x["records"] is not None:
                add("RECORDS_LOST", x["records"], "Reported in disclosure")
            if x["cost"] is not None:
                add("BREACH_COST_USD", x["cost"], "Estimated cost")
            if x["ops"] in ("0", "1"):
                add("OPERATIONAL_DISRUPTION", "Yes" if x["ops"] == "1" else "No", "From dataset flag")
            if x["info_type"] and x["info_type"] != "NA":
                add("INFORMATION_TYPE", x["info_type"], "Category from source")
            add("SEVERITY", "Severe" if x["severe"] else "Not severe", "Severity coding")

        fact_ids = psycopg2.extras.execute_values(
            cur,
            "INSERT INTO fact (incident_id, announcement_id, fact_type_id, value, confidence_level, coded_by) "
            "VALUES %s RETURNING fact_id",
            fact_values,
            fetch=True,
        )

        review_values = []
        for (fid,) in fact_ids:
            if _seed(str(fid)) % 2:
                continue
            review_values.append((
                fid,
                _pick(REVIEWERS, str(fid) + "r"),
                _pick(REVIEW_DECISIONS, str(fid)),
                "",
            ))
        if review_values:
            psycopg2.extras.execute_values(
                cur,
                "INSERT INTO fact_review (fact_id, reviewer_id, decision, comments) VALUES %s",
                review_values,
            )

        conn.commit()
        cur.close()

    return {
        "skipped": False,
        "replaced": bool(force),
        "rows": len(data_rows),
        "counts": {
            "companies": len(new_companies),
            "incidents": len(incident_rows),
            "announcements": len(incident_rows),
            "facts": len(fact_values),
            "reviews": len(review_values),
        },
    }
