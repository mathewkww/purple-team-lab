# Security Readiness Platform

A portfolio-ready, **simulation-only** Streamlit platform with two analyst workspaces:

1. **Purple Team Lab** — intake advisory-derived threats, create remediation plans, and rehearse defensive telemetry.
2. **Red Team Studio** — step through safe attack stories based on MITRE ATT&CK and OWASP risks, with a live threat-model panel and disruption guidance.

It uses synthetic observations only. It does not provide exploit instructions, execute commands, scan hosts, send traffic, contact infrastructure, or change production controls.

The Threat Intake view has an explicit, user-triggered read-only import for the ten newest records in CISA's Known Exploited Vulnerabilities JSON feed. Imported items stay reviewable records and do not automatically start simulations.

## Threat readiness desk

The main page is an analyst workspace: select one of the ten latest KEV additions, read the source description and remediation action, assess applicability, and export a Markdown brief. KEV addition dates are not disclosure dates or proof of zero-day status. No asset inventory is connected, so exposure is explicitly assessed by the analyst rather than inferred.

The preparation checklist tracks inventory review, mitigation planning, and telemetry ownership. Assessments, notes, and run history are held only in the current Streamlit session; export the brief before leaving. Do not enter confidential incident details into this public portfolio demo.

Six baseline template runs generate synthetic telemetry at session startup. Additional rehearsals use an analyst-selected behavior template. They do not reproduce a specific CVE, validate deployed detection rules, or apply production controls.

## Red Team Studio

Red Team Studio uses four analyst-led tracks: public-facing application exposure (MITRE T1190), identity and SaaS account abuse (MITRE T1078), web authorization/API misuse (OWASP A01:2025), and software supply-chain integrity (OWASP A03:2025). Each track provides fictional stage observations, expected telemetry, decision gates, and disruption/denial prompts.

The live threat-model panel is session-local. It captures only an environment pattern, a service label, external exposure, and telemetry ownership to focus the review. It is a preparation aid, not a risk engine or source of operational instructions. Do not enter secrets, customer data, incident details, or other sensitive information in the public demo.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

## Portfolio deployment

Deploy this repository to Streamlit Community Cloud. Keep the demo data synthetic and use only public, approved advisory sources. A natural next step is a read-only scheduled connector for CISA KEV / vendor advisory feeds, with review and approval before creating any simulation.

Or run the same portfolio app as a container:

```powershell
docker build -t purple-team-lab .
docker run --rm -p 8501:8501 purple-team-lab
```
