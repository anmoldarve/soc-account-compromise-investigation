# SOC Account Compromise Investigation (KQL / Azure Data Explorer)

Simulated enterprise SOC investigation — Tier 1 to Tier 3 analyst workflow, built and queried entirely in Azure Data Explorer using KQL. No pre-labeled dataset: every anomaly was found by baselining normal user behavior and querying for deviations, the same approach real UEBA/Sentinel tooling uses under the hood.

**Author:** Anmol Darve
**Stack:** Azure Data Explorer, KQL (Kusto Query Language), Windows Security Event Log standard (4624/4625/4728/4663)
**Dataset:** 932 simulated enterprise log events across 11 users, 7 business applications, 5 business days

---

## What this project demonstrates

- Building a realistic enterprise log dataset (Windows Security Event ID standard) and ingesting it into Azure Data Explorer
- User & Entity Behavior baselining — profiling each user's normal login country/device, then querying for statistical outliers
- Full incident timeline reconstruction using KQL (`summarize`, `make_set()`, `prev()`, `datetime_diff()`)
- Geo-velocity / impossible-travel detection with exact time-gap calculation
- MITRE ATT&CK technique mapping per incident
- Formal SOC incident reporting — Executive Summary, Timeline, Findings, Root Cause, Business Impact, Remediation, Recommendations

## Incidents found

| # | Incident | User / Dept | Severity | Technique (MITRE) |
|---|---|---|---|---|
| 1 | Executive account compromise + data exfiltration | eclarke / Executive | Critical | T1078, T1213 |
| 2 | VPN brute force via Tor exit node | rpatel / IT | Critical | T1110, T1078 |
| 3 | Impossible travel / session hijacking | mchen / Engineering | High | T1078, T1550 |

## Key queries used

**Login-country baseline per user:**
```kql
Logs
| where EventID == "4624"
| summarize LoginCountries = make_set(Country), LoginCount = count() by Username
```

**Per-country breakdown (confirming the outlier):**
```kql
Logs
| where EventID == "4624"
| summarize CountryCount = count() by Username, Country
| sort by Username asc, CountryCount asc
```

**Exact time gap between geo-anomalous logins:**
```kql
Logs
| where Username == "mchen" and Country in ("USA", "Russia")
| project Timestamp, Country, Application
| order by Timestamp asc
| extend PrevTime = prev(Timestamp), PrevCountry = prev(Country)
| extend GapMinutes = datetime_diff('minute', Timestamp, PrevTime)
```

## Methodology

| Tier | Focus | Technique |
|---|---|---|
| Tier 1 — Triage | Scan for statistical anomalies | Aggregate/summarize logs by user, IP, and country to spot outliers |
| Tier 2 — Investigation | Build full incident timeline | Filter to the specific user/IP and reconstruct exact sequence of events |
| Tier 3 — Reporting | Formal write-up & response | Document IOCs, MITRE ATT&CK mapping, root cause, and remediation |

## Findings summary

1. **eclarke (CEO)** logged in from a country and device never seen before for this account, off-hours, then downloaded a confidential board document within 2 minutes — classified **Critical**.
2. **rpatel (IT)** VPN account was hit by 40+ rapid failed logins from a Tor exit-node IP, which succeeded, followed by file downloads from SharePoint — classified **Critical**.
3. **mchen (Engineering)** showed a login from Russia only 6 minutes after legitimate USA activity, with the real user resuming normal activity 16 minutes later — consistent with session/token theft rather than genuine travel — classified **High**.

All three incidents were independently confirmed through log evidence, cross-referenced against each user's historical baseline, and written up as formal incident reports with remediation and prevention recommendations.

---

*This is a simulated environment built for practice — not a real company incident.*
