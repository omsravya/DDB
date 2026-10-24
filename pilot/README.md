# Ransomware announcement pipeline: pilot

Proof that the two-step plan in Prof. Schuetz's email (acquisition pipeline, then fact
extraction) works end to end on real data, using only free public sources.

## What was run (24 Oct 2026)

| Step | What | Result |
|---|---|---|
| 1 | SEC filing histories for 314 companies (300 random + 14 known cyber filers) | 18 Item 1.05 8-K filings from 11 companies; 0 fetch failures |
| 2 | Download each filing, cut out the Item 1.05 section | 18/18 documents fetched, 18/18 sections found |
| 3 | Leak-site posts from ransomware.live, Jun 2023 to Oct 2026 | 25,792 posts; 7 matched to 5 of the 11 companies |
| 4 | Daily prices around each first filing (yfinance) | 11/11 tickers |
| 5 | LLM fact extraction (3 agents in parallel, fixed fact taxonomy, verbatim quote per fact) | 286 facts |
| 6 | Independent LLM verification (3 different agents, each checks a batch it did not extract) | 283 facts kept, 11 dropped, 8 added, ~40 fixed |
| 7 | Mechanical check: every quote is a verbatim substring of the filing, types/values valid | 0 problems |
| 8 | Load into SQLite with Schuetz's schema plus the event-study columns | `output/ransomware_pilot.sqlite` |

## Files

- `pipeline.py`: steps 1-4. `python3 pipeline.py --pilot` or `--full`. Caches every download under `cache/`.
- `reverse.py`: start from leak-site victims, find SEC registrants, scan their 8-K/6-Ks for incident language (catches disclosures filed under Item 8.01 / 7.01, and incidents never disclosed).
- `llm/FACT_SCHEMA.md`: the fact taxonomy (29 types incl. HIT_OR_NEAR_MISS mirroring the MISQ paper) and output format.
- `llm/input/`: the 18 filing texts. `llm/extracted/`: raw LLM output. `llm/verified/`: corrected output plus a `.changes.md` log per filing.
- `llm/check_facts.py`: mechanical checker. `llm/load_db.py`: SQLite loader.
- `output/item105_filings_pilot.csv`, `output/leak_matches_pilot.csv`, `output/leak_posts_all.csv`, `output/event_returns_pilot.csv`.

## Schema additions versus the current DDB (needed for an event study)

company: `cik`, `ticker`, `website`. announcement: `announcement_timestamp` (SEC acceptance time, decides event day),
`channel` (regulatory / darknet / news), `form_type`, `accession_number` (unique), `threat_actor_id`, `is_amendment`,
`summary`, `new_vs_prior`. fact: `source_quote`, `note`, `extraction_method`. New table `threat_actor`.

## What the full run needs

- SEC: nothing (free, 10 req/s cap; full ticker list ~8,000 companies ≈ 20 min for histories).
- ransomware.live: nothing.
- LLM extraction: a Claude or Gemini API key. ~2,000 tokens per filing; a few hundred filings cost a few dollars.
- Stock prices: yfinance works for a pilot; CRSP via WRDS for the paper.
