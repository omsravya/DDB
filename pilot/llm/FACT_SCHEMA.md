# Fact extraction schema (ransomware announcement database)

Each announcement (one SEC filing) yields a list of facts. A fact is one piece
of information the announcement reveals to the public. Facts are what should
move stock prices, so precision and provenance matter more than volume.

## Output format

One JSON file per input file, same basename, `.json` extension:

```json
{
  "file": "UNH_2024-02-22_8-K.txt",
  "facts": [
    {
      "fact_type": "INCIDENT_DISCOVERY_DATE",
      "value": "2024-02-21",
      "quote": "On February 21, 2024, UnitedHealth Group (the “Company”) identified a suspected nation-state associated cyber security threat actor had gained access to some of the Change Healthcare information technology systems.",
      "confidence": "high",
      "note": ""
    }
  ],
  "summary": "one or two sentences in plain words on what this filing reveals",
  "new_vs_prior": "for an amendment (8-K/A): what is new relative to the earlier filing, else empty"
}
```

Rules:
- `quote` must be copied VERBATIM from the input text (an exact substring, same punctuation and quote characters). A verifier will check this by string search. Keep it to one sentence, or the shortest span that supports the value.
- One fact per (fact_type, value). If the same fact type appears twice with different values (e.g. two dates), record both.
- Record only what the filing itself states. Do not infer from outside knowledge. Do not record things the filing says it does NOT know unless the fact type is one of the explicit "not determined" types below.
- `confidence`: "high" if stated explicitly, "medium" if clearly implied by the wording, "low" if a stretch. Prefer omitting a low-confidence fact unless it is important.
- `value` is short and normalized: dates as YYYY-MM-DD (or YYYY-MM if the filing only gives a month; put the filing's wording in `note`), yes/no as "yes"/"no", money as a number in USD, otherwise a few words.
- For the "yes"-type facts (RANSOMWARE, ENCRYPTION, CONTAINED, etc.) a value of "no" is allowed only when the filing explicitly denies it (e.g. "no evidence of ransomware"). Silence is not a "no": leave the fact out.
- If nothing in the text supports a fact type, leave it out. Empty lists are fine.

## Fact types (use these exact names)

Timing
- INCIDENT_DISCOVERY_DATE : date the company identified / became aware of the incident
- INCIDENT_START_DATE : date the intrusion began, if stated separately from discovery
- MATERIALITY_DETERMINATION_DATE : date the company concluded the incident was material
- CONTAINMENT_DATE : date systems were isolated / contained
- RESTORATION_DATE : date operations or systems were restored (fully or partly)

Nature of the attack
- RANSOMWARE : "yes" if the filing calls it ransomware or describes encryption for extortion
- ENCRYPTION : "yes" if files/systems were encrypted
- DATA_EXFILTRATION : "yes" / "no" / "under investigation" (whether data was taken)
- DATA_TYPE_AFFECTED : what kind of data (e.g. "personal information", "employee data", "emails")
- THREAT_ACTOR_ATTRIBUTION : who is blamed (e.g. "nation-state", "Midnight Blizzard", "criminal group")
- ATTACK_VECTOR : how they got in, if stated (e.g. "password spray", "third-party vendor")
- AFFECTED_UNIT : which subsidiary / system / business unit was hit

Impact
- OPERATIONAL_DISRUPTION : "yes" / "no" / "limited" (were business operations disrupted)
- DISRUPTION_DESCRIPTION : short description of what was disrupted (e.g. "online ordering in parts of the US")
- PROACTIVE_SHUTDOWN : "yes" if the company itself took systems offline as a precaution
- MATERIAL_IMPACT : "yes" / "no" / "not yet determined" (effect on financial condition / results)
- MATERIAL_IMPACT_DETAIL : short text on the financial effect, if any numbers or specifics given
- COST_ESTIMATE_USD : a dollar figure for costs, if given
- CUSTOMER_OR_THIRD_PARTY_IMPACT : whether customers, patients, partners were affected and how

Response
- CONTAINED : "yes" if the filing says the incident is contained / remediated
- EXTERNAL_EXPERTS_ENGAGED : "yes" if third-party forensic / cybersecurity firms were hired
- LAW_ENFORCEMENT_NOTIFIED : "yes" if law enforcement was notified or is involved
- REGULATOR_NOTIFIED : "yes" if regulators / government agencies were notified
- RANSOM_PAID : "yes" / "no" / "not stated"  (only record if the filing addresses it)
- INSURANCE_MENTIONED : "yes" if cyber insurance is mentioned
- INVESTIGATION_ONGOING : "yes" if the investigation is still ongoing

Disclosure stance
- DISCLOSURE_TRIGGER : why this filing is being made now (e.g. "materiality determined", "voluntary", "update to prior filing")
- HIT_OR_NEAR_MISS : "hit" if operations were actually disrupted; "near miss" if the company says it stopped the attack before disruption; "unclear" otherwise. This mirrors the hit / near-miss split in Schuetz et al. (MISQ 2025).

Catch-all
- OTHER : any other concrete, price-relevant piece of information; put the gist in `value` and explain in `note`
