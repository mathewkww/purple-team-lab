"""Purple Team Lab — a safe, portfolio-ready threat-response simulator."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any
from urllib.request import Request, urlopen
import json

import pandas as pd
import streamlit as st


st.set_page_config(page_title="Purple Team Lab", page_icon="🟣", layout="wide")


SAMPLE_ADVISORIES: list[dict[str, Any]] = [
    {
        "title": "Public-facing application under active exploitation",
        "source": "CISA KEV (demonstration record)",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "cves": "CVE-2025-DEMO-0001",
        "products": "Demo Web Gateway 4.x",
        "summary": "Reports describe exploitation attempts against an internet-facing management interface.",
        "confidence": "High",
        "exploited": True,
        "patched": False,
        "technique": "T1190 — Exploit Public-Facing Application",
    },
    {
        "title": "Suspicious OAuth consent and token reuse campaign",
        "source": "Analyst observation (demonstration record)",
        "url": "",
        "cves": "",
        "products": "Cloud identity tenant",
        "summary": "Unusual consent grants followed by sign-ins from new locations and API access.",
        "confidence": "Medium",
        "exploited": False,
        "patched": False,
        "technique": "T1528 — Steal Application Access Token",
    },
]

SCENARIOS = {
    "Public-facing application exploitation": {
        "technique": "T1190 — Exploit Public-Facing Application",
        "signals": [
            ("web-gateway-01", "WAF", "Repeated blocked requests to an administrative endpoint", "medium"),
            ("web-gateway-01", "Web server", "Unusual child process spawned by the web service", "high"),
            ("web-gateway-01", "Network", "Outbound connection to rare external destination", "high"),
        ],
        "response": ["Isolate the affected workload", "Block destination at egress", "Preserve application and proxy logs", "Patch or disable the exposed interface"],
    },
    "OAuth token misuse": {
        "technique": "T1528 — Steal Application Access Token",
        "signals": [
            ("identity-tenant", "Identity", "New high-privilege OAuth consent grant", "high"),
            ("analyst@demo.local", "Identity", "Token use from a new geography", "medium"),
            ("cloud-api", "SaaS audit", "Burst of mailbox and file enumeration", "high"),
        ],
        "response": ["Revoke the application token", "Disable the suspicious service principal", "Require user reauthentication", "Review OAuth consent policy"],
    },
    "Credential access attempt": {
        "technique": "T1110 — Brute Force",
        "signals": [
            ("vpn-01", "Identity", "High-volume failed logins across multiple accounts", "medium"),
            ("vpn-01", "Identity", "Successful sign-in immediately after failures", "high"),
            ("laptop-023", "Endpoint", "New remote-access session from unrecognized address", "medium"),
        ],
        "response": ["Disable or reset impacted accounts", "Block the source address", "Require MFA challenge", "Review adjacent sign-ins for lateral movement"],
    },
}

CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def init_state() -> None:
    if "advisories" not in st.session_state:
        st.session_state.advisories = SAMPLE_ADVISORIES.copy()
    if "events" not in st.session_state:
        st.session_state.events = []
    if "runs" not in st.session_state:
        st.session_state.runs = []


def risk_score(advisory: dict[str, Any]) -> int:
    score = {"Low": 25, "Medium": 50, "High": 75}.get(advisory["confidence"], 50)
    return min(100, score + (20 if advisory["exploited"] else 0) + (10 if not advisory["patched"] else 0))


def simulate(name: str, advisory_title: str) -> None:
    scenario = SCENARIOS[name]
    now = datetime.now(timezone.utc)
    run_id = sha256(f"{name}{now.isoformat()}".encode()).hexdigest()[:8]
    events = []
    for index, (asset, source, detail, severity) in enumerate(scenario["signals"]):
        events.append(
            {
                "time": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "run": run_id,
                "asset": asset,
                "source": source,
                "event": detail,
                "severity": severity.upper(),
                "synthetic": True,
            }
        )
    st.session_state.events = events + st.session_state.events
    st.session_state.runs.insert(0, {"id": run_id, "scenario": name, "advisory": advisory_title, "technique": scenario["technique"], "response": scenario["response"], "time": now})


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_kev() -> list[dict[str, Any]]:
    """Read the public KEV JSON feed; it never executes or follows advisory content."""
    request = Request(CISA_KEV_JSON, headers={"User-Agent": "Purple-Team-Lab-Portfolio/1.0"})
    with urlopen(request, timeout=10) as response:  # nosec B310: fixed HTTPS CISA endpoint
        payload = json.loads(response.read().decode("utf-8"))
    return payload.get("vulnerabilities", [])


def import_recent_kev() -> int:
    items = fetch_kev()
    existing_cves = {item["cves"] for item in st.session_state.advisories if item["cves"]}
    added = 0
    for item in sorted(items, key=lambda x: x.get("dateAdded", ""), reverse=True)[:10]:
        cve = item.get("cveID", "")
        if not cve or cve in existing_cves:
            continue
        st.session_state.advisories.append({
            "title": item.get("vulnerabilityName", cve),
            "source": "CISA KEV",
            "url": CISA_KEV_JSON,
            "cves": cve,
            "products": f"{item.get('vendorProject', '')} {item.get('product', '')}".strip(),
            "summary": item.get("shortDescription", "No description supplied by feed."),
            "confidence": "High",
            "exploited": True,
            "patched": False,
            "technique": "T1190 — Exploit Public-Facing Application",
        })
        existing_cves.add(cve)
        added += 1
    return added


init_state()

st.title("🟣 Purple Team Lab")
st.caption("A simulation-only threat-intelligence, detection, and response showcase. No live exploitation or production controls.")

with st.sidebar:
    page = st.radio("Workspace", ["Command Center", "Threat Intake", "Simulation Lab", "Detection & Response"], label_visibility="collapsed")
    st.divider()
    st.caption("Portfolio MVP · synthetic telemetry only")

if page == "Command Center":
    risks = [risk_score(item) for item in st.session_state.advisories]
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Threat records", len(st.session_state.advisories))
    col2.metric("Active simulations", len(st.session_state.runs))
    col3.metric("Synthetic detections", len(st.session_state.events))
    col4.metric("Highest priority", f"{max(risks, default=0)}/100")
    st.subheader("Purple-team loop")
    st.markdown("**Intake → validate → simulate → detect → contain → measure → improve**")
    st.subheader("Threat priority")
    rows = [{"Threat": x["title"], "Risk": risk_score(x), "Exploited in wild": "Yes" if x["exploited"] else "No", "Technique": x["technique"]} for x in st.session_state.advisories]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

elif page == "Threat Intake":
    st.header("Threat intake")
    st.write("Capture a novel threat, an advisory you found, or a curated-feed item. Every item remains a draft until explicitly used for a safe simulation.")
    with st.expander("Curated feed: CISA KEV", expanded=False):
        st.write("Import the ten most recently added, known-exploited vulnerabilities from CISA's public JSON feed. They are added as reviewable records; advisory text is never executed.")
        if st.button("Import recent KEV records"):
            try:
                count = import_recent_kev()
                st.success(f"Imported {count} new KEV record(s).")
            except Exception as exc:
                st.error(f"The feed could not be reached: {exc}")
    with st.form("intake", clear_on_submit=True):
        title = st.text_input("Threat title *", placeholder="e.g., Suspicious edge-device exploitation report")
        source = st.text_input("Source", placeholder="Your research, vendor advisory, CISA KEV")
        url = st.text_input("Advisory URL")
        cves = st.text_input("CVE IDs", placeholder="CVE-YYYY-NNNN")
        products = st.text_input("Affected products / assets")
        summary = st.text_area("Defensive summary *", placeholder="Describe observed behavior, exposure, and why it matters. Do not paste exploit instructions.")
        c1, c2, c3 = st.columns(3)
        confidence = c1.selectbox("Confidence", ["Low", "Medium", "High"], index=1)
        exploited = c2.checkbox("Exploited in the wild")
        patched = c3.checkbox("Patch available")
        technique = st.selectbox("Closest ATT&CK technique", [x["technique"] for x in SCENARIOS.values()])
        submitted = st.form_submit_button("Add as reviewable threat")
    if submitted:
        if not title or not summary:
            st.error("A title and defensive summary are required.")
        else:
            st.session_state.advisories.insert(0, {"title": title, "source": source or "Manual analyst submission", "url": url, "cves": cves, "products": products, "summary": summary, "confidence": confidence, "exploited": exploited, "patched": patched, "technique": technique})
            st.success("Threat added. It is ready for a controlled simulation.")
    st.subheader("Intelligence queue")
    for item in st.session_state.advisories:
        with st.expander(f"{item['title']} · priority {risk_score(item)}/100"):
            st.write(item["summary"])
            st.caption(f"Source: {item['source']} | CVEs: {item['cves'] or 'Not assigned'} | Products: {item['products'] or 'Not specified'}")
            if item["url"]:
                st.link_button("Open source advisory", item["url"])

elif page == "Simulation Lab":
    st.header("Red agent: safe attack emulation")
    st.info("This generates synthetic telemetry only. It does not execute commands, scan systems, or contact external infrastructure.")
    scenario_name = st.selectbox("Simulation scenario", list(SCENARIOS))
    advisory_title = st.selectbox("Linked threat record", [item["title"] for item in st.session_state.advisories])
    scenario = SCENARIOS[scenario_name]
    st.write(f"**ATT&CK mapping:** {scenario['technique']}")
    st.write("**Synthetic signals:**")
    for _, source, detail, severity in scenario["signals"]:
        st.write(f"- `{severity.upper()}` · {source}: {detail}")
    if st.button("Run controlled simulation", type="primary"):
        simulate(scenario_name, advisory_title)
        st.success("Simulation complete. Blue-team telemetry is available in Detection & Response.")

else:
    st.header("Blue agent: detection, response, and disruption")
    if not st.session_state.events:
        st.info("Run a controlled simulation to generate safe telemetry.")
    else:
        events = pd.DataFrame(st.session_state.events)
        st.subheader("Detected synthetic telemetry")
        st.dataframe(events[["time", "asset", "source", "event", "severity", "run"]], use_container_width=True, hide_index=True)
        latest = st.session_state.runs[0]
        st.subheader(f"Response plan · run {latest['id']}")
        st.caption(f"{latest['scenario']} · {latest['technique']} · linked to {latest['advisory']}")
        for action in latest["response"]:
            st.checkbox(action, key=f"{latest['id']}-{action}")
        st.divider()
        st.subheader("Purple-team scorecard")
        detection_rate = 100 if st.session_state.events else 0
        c1, c2, c3 = st.columns(3)
        c1.metric("Detection coverage", f"{detection_rate}%")
        c2.metric("Mean time to detect", "< 1 min (simulated)")
        c3.metric("Containment actions proposed", len(latest["response"]))
        st.caption("Metrics are illustrative and deliberately labeled simulated for honest portfolio presentation.")
