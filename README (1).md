# Synergy-X

**Problem Statement:** Personalised Vulnerability Triage

**Team:** Ragunath M (Team Leader), Praveen G, Pranesh Y, Pragalathan T

---

## Problem

Small organisations — colleges, clinics, small manufacturers — often run a handful of public products but have no dedicated threat analyst on staff. Public vulnerability sources (NVD, CISA KEV, FIRST EPSS) publish thousands of records meant for a general audience, and a limited IT team can't quickly tell which of them actually touch their own services.

When everything looks urgent, real warnings get delayed, effort is wasted on irrelevant products, and teams eventually stop reading advisories altogether — leaving genuinely exploitable gaps unpatched. CVSS severity alone doesn't know an organisation's context; a global CVE table sorted only by CVSS is not personalised threat intelligence.

## Solution

Synergy-X reads a small organisation's tech profile, matches it against public vulnerability data, and returns a ranked **top-five** list of what to act on next — with plain-language reasons for each item.

**How it works:**
1. Load the organisation profile (tech stack, exposure, service, importance) alongside CVE/KEV/EPSS starter data.
2. Match products and versions against the profile.
3. Score matches using visible, explainable signals (KEV + EPSS + CVSS + confidence).
4. Generate a plain-language explanation for each ranked result.

**Boundaries:** No live feeds, scanning, or exploit code; no universal CPE parsing; the tool never claims an organisation is "secure" — only that a given set of items deserves attention.

**Key features:**
- Ranked top-5 vulnerabilities with plain-language reasoning
- Supports loading a second profile to see rankings change
- Every result traces back to its source record

## What Makes It Different

**The obvious approach:** dump every CVE for the vendors in use into one dashboard, sort by CVSS score, and let the IT team scroll and decide for themselves.

**Our approach:** match the organisation's actual profile (products, exposure, service importance), combine KEV + EPSS + CVSS + confidence into a ranked top five, and prove it with a mandatory **negative test** — a high-CVSS item that is correctly excluded or downranked.

## Tech Stack

| Layer | Technology | Why this choice |
|---|---|---|
| Frontend | Streamlit (Python) or plain CLI + HTML | Fast to build in 24h; shows result cards directly, no auth needed |
| Backend | Python + pandas | Transparent, rule-based matching and scoring — easy to explain, easy to debug |
| AI / Model | Optional template-based text generation (no paid API) | AI policy requires no paid dependency; deterministic fallback keeps output explainable |
| Data / Storage | Bundled CSV/JSON (`vulnerabilities.csv`, `profiles.json`) | Matches the "no live API dependency" rule; keeps the whole demo fully offline |

**Full stack summary:** Python, pandas · Streamlit or CLI + HTML · starter data pack (`vulnerabilities.csv`, `profiles.json`, `gold_set.csv`) · rule-based matching & scoring engine · optional template-based explanation text (no paid API) · public sources: NIST NVD, CISA KEV, FIRST EPSS

## Build Plan (24-Hour Window)

| Phase | Hours | Focus |
|---|---|---|
| Setup | 0–6 | Load data + match |
| Core Build | 6–12 | Rank + score |
| Integration | 12–17 | Explanation UI |
| Polish & Demo | 17–24 | Second profile + freeze |

**Already built:** starter CSV/JSON (`vulnerabilities.csv`, `profiles.json`, `gold_set.csv`)
**New for hackathon:** matching engine, scoring logic, explanation cards, negative-test view

**Biggest risk & fallback:** Vendor version formats are messy to compare cleanly. Fallback — mark unclear items as **"NEEDS VERIFICATION"** instead of guessing, and only fully solve numeric/exact version ranges.

## Expected Impact

| | |
|---|---|
| **Primary beneficiary** | Small orgs with no dedicated security analyst — colleges, clinics, small manufacturers |
| **Success metric** | % of top-5 items a non-expert finds relevant in <60s; correct exclusions on the negative test |
| **Target scale** | One IT team / one organisation profile at a time |

**Longer-term vision:** Live NVD/KEV/EPSS feeds, fuller CPE-based version parsing, scheduled re-scans, and a lightweight multi-profile dashboard for a whole campus or SMB network.

## Team & Roles

| Name | Role | Year |
|---|---|---|
| Ragunath M | Data & Matching Lead | ECE - II Year |
| Praveen G | Scoring & Ranking Lead | ECE - II Year |
| Pranesh Y | Explainability & UI Lead | ECE - II Year |
| Pragalathan T | Integration & Demo Lead | ECE - II Year |
