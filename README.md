# Security Readiness Platform

A portfolio-ready, **simulation-only** Streamlit platform with three analyst workspaces:

1. **Purple Team Lab** — intake advisory-derived threats, create remediation plans, and rehearse defensive telemetry.
2. **Red Team Studio** — step through safe attack stories based on MITRE ATT&CK and OWASP risks, with a live threat-model panel and disruption guidance.
3. **Signal Context** — correlate fictional identity, SIEM, SOAR, and cloud telemetry into an evidence-led vertical investigation timeline, with replay, threat-model hypotheses, response validation and exportable analyst handoffs.
4. **Model Risk Studio** — investigate fictional LLM misuse traces across prompts, retrieval, policy gates and tool proposals, with OWASP, MITRE ATLAS and NIST-aligned risk and response guidance.

It uses synthetic observations only. It does not provide exploit instructions, execute commands, scan hosts, send traffic, contact infrastructure, or change production controls.

The Threat Intake view has an explicit, user-triggered read-only import for the ten newest records in CISA's Known Exploited Vulnerabilities JSON feed. Imported items stay reviewable records and do not automatically start simulations.

## Threat readiness desk

The main page is an analyst workspace: select one of the ten latest KEV additions, read the source description and remediation action, assess applicability, and export a Markdown brief. KEV addition dates are not disclosure dates or proof of zero-day status. No asset inventory is connected, so exposure is explicitly assessed by the analyst rather than inferred.

The preparation checklist tracks inventory review, mitigation planning, and telemetry ownership. Assessments, notes, and run history are held only in the current Streamlit session; export the brief before leaving. Do not enter confidential incident details into this public portfolio demo.

Six baseline template runs generate synthetic telemetry at session startup. Additional rehearsals use an analyst-selected behavior template. They do not reproduce a specific CVE, validate deployed detection rules, or apply production controls.

## Red Team Studio

Red Team Studio uses four analyst-led tracks: public-facing application exposure (MITRE T1190), identity and SaaS account abuse (MITRE T1078), web authorization/API misuse (OWASP A01:2025), and software supply-chain integrity (OWASP A03:2025). Each track provides fictional stage observations, expected telemetry, decision gates, and disruption/denial prompts.

The live threat-model panel is session-local. It captures only an environment pattern, a service label, external exposure, and telemetry ownership to focus the review. It is a preparation aid, not a risk engine or source of operational instructions. Do not enter secrets, customer data, incident details, or other sensitive information in the public demo.

## Signal Context

A reproducible, in-memory SQLite database contains 26 synthetic records: cloud-account/storage activity, cross-tenant API disclosure, and an authorized monitoring change. Three unrelated same-IP neighbors and one duplicate ingestion teach correlation hygiene. Source names (Entra ID, AWS CloudTrail, GCP Cloud Logging, Azure Activity, Splunk ES/SOAR, Microsoft Sentinel and Logic Apps) identify illustrative, simplified data shapes, not installed integrations or complete vendor schemas.

Correlation uses an explicit principal/session mapping and a bounded event-time window, with source/original-ID deduplication. Findings use only revealed, included records. Remove a source to observe coverage gaps; move the replay cursor to see how confidence and response validation evolve. SIEM alerts are derived findings, and queued SOAR actions do not count as verified containment. Framework links cover MITRE ATT&CK and OWASP API1:2023, A01:2025 and A09:2025. Labels are teaching assessments, not calibrated risk probabilities or confirmed actor attribution.

The workspace includes raw payload inspection, evidence lineage, competing explanations, recommended action owners, a session-local analyst notebook, JSON handoff export and a downloadable SQLite fixture. Nothing connects to production, performs attacks, changes controls, or calls a paid model API. For real use, implement authenticated read-only connectors, validated identity resolution, ingestion/integrity handling, secure retention and access controls before accepting operational data.

## Model Risk Studio

Model Risk Studio provides four fictional investigation traces: indirect retrieval injection, sensitive-context disclosure, agent tool-scope escalation, and unbounded consumption. It covers OWASP's 2025 LLM Top 10 at a high level, refers to MITRE ATLAS for adversarial ML technique modeling, and frames assurance around NIST AI RMF's Govern, Map, Measure and Manage functions. It does not execute prompts, call models, run classifiers, use customer data, or provide bypass or misuse instructions.

The trace replay deliberately distinguishes model/user input, a detection signal, a rejected policy decision, and verified external execution. Public vendor guidance informs the product patterns: structured input/output checks, tool-level controls, least privilege, human approval for consequential actions, evaluation/red-team feedback loops, real-time and asynchronous monitoring, protected audit trails, and rapid incident response. These are design patterns—not claims that the demo recreates OpenAI or Anthropic systems, nor guarantees that any control eliminates model risk.

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
