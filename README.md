# Purple Team Lab

A portfolio-ready, **simulation-only** Streamlit application demonstrating a purple-team workflow:

1. Intake analyst-submitted and advisory-derived threats.
2. Prioritize them using transparent, defensive risk signals.
3. Generate synthetic red-team telemetry mapped to MITRE ATT&CK.
4. Show blue-team detections, containment recommendations, and a coverage scorecard.

It does not run exploits, scan hosts, contact infrastructure, or change production controls.

The Threat Intake view has an explicit, user-triggered read-only import for the ten newest records in CISA's Known Exploited Vulnerabilities JSON feed. Imported items stay reviewable records and do not automatically start simulations.

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
