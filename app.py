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

st.markdown(
    """
    <style>
      @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Inter:wght@400;500;600;700&display=swap');
      :root { --ink:#f4f7fb; --muted:#91a0b7; --line:#263246; --panel:#121b29; --panel-2:#182338; --purple:#9b7cff; --cyan:#36d3c6; --critical:#ff657c; --warning:#ffb75d; }
      .stApp { background: radial-gradient(circle at 78% -10%, #20214a 0, transparent 28%), #09111d; color:var(--ink); font-family:Inter, sans-serif; }
      [data-testid="stSidebar"] { background:#0b1422; border-right:1px solid var(--line); }
      [data-testid="stSidebar"] > div:first-child { padding-top:1.2rem; }
      [data-testid="stSidebar"] .stRadio label { color:#aab7ca; border-radius:7px; padding:8px 9px; font-size:.87rem; }
      [data-testid="stSidebar"] .stRadio label:hover { background:#182338; color:#fff; }
      [data-testid="stSidebar"] [data-checked="true"] { background:linear-gradient(90deg, rgba(155,124,255,.20), transparent); color:#fff!important; }
      .block-container { max-width:1440px; padding:1.2rem 2.4rem 3.5rem; }
      .topbar { display:flex; align-items:center; justify-content:space-between; padding:0 0 1.25rem; border-bottom:1px solid var(--line); margin-bottom:1.7rem; }
      .brand { display:flex; gap:12px; align-items:center; font-size:1.08rem; font-weight:700; letter-spacing:-.02em; }
      .brand-mark { width:30px; height:30px; display:grid; place-items:center; border-radius:8px; background:linear-gradient(135deg,#b69cff,#684ee9); box-shadow:0 6px 20px rgba(129,94,255,.35); color:white; }
      .env { color:#bdc7d5; background:#131e2e; border:1px solid #2c3a4f; border-radius:20px; padding:5px 11px; font-size:.75rem; font-family:'DM Mono',monospace; }
      .live { color:#8ff0c4; font-size:.75rem; font-weight:600; } .live:before { content:'●'; color:var(--cyan); margin-right:6px; }
      h1,h2,h3 { color:var(--ink)!important; letter-spacing:-.035em; } h1 { font-size:1.7rem!important; margin-bottom:.2rem!important; } h2 { font-size:1.22rem!important; margin-top:1.7rem!important; }
      p, .stCaption { color:var(--muted)!important; }
      [data-testid="stMetric"] { background:linear-gradient(145deg, rgba(24,35,56,.95), rgba(15,24,39,.95)); border:1px solid #28364d; border-radius:10px; padding:1rem 1.05rem; min-height:105px; box-shadow:0 16px 32px rgba(0,0,0,.14); }
      [data-testid="stMetricLabel"] { color:#91a0b7!important; font-size:.77rem!important; text-transform:uppercase; letter-spacing:.08em; } [data-testid="stMetricValue"] { color:#f8fbff!important; font-size:1.72rem!important; }
      [data-testid="stDataFrame"] { border:1px solid #28364d; border-radius:10px; overflow:hidden; }
      .stButton > button { background:#8b6bfa; border:0; border-radius:7px; color:white; font-weight:600; box-shadow:none; } .stButton > button:hover { background:#a58bff; border:0; color:white; }
      .stTextInput input, .stTextArea textarea, [data-baseweb="select"] > div { background:#0e1725!important; border-color:#2c3a4f!important; color:#eef3fb!important; border-radius:7px!important; }
      [data-testid="stExpander"] { border:1px solid #2a3951!important; border-radius:9px!important; background:#101a2a!important; }
      .section-kicker { color:#9e8cff; text-transform:uppercase; letter-spacing:.11em; font-size:.69rem; font-weight:700; margin-bottom:.36rem; }
      .insight-card { background:linear-gradient(125deg,rgba(155,124,255,.15),rgba(18,27,41,.7) 50%); border:1px solid #3a3964; border-radius:10px; padding:1.05rem 1.15rem; min-height:128px; }
      .insight-card b { color:#fff; font-size:1.02rem; } .insight-card span { color:#9eacc0; font-size:.84rem; display:block; margin-top:.45rem; line-height:1.45; }
      .sidebar-brand { padding:0 .65rem 1.25rem; font-weight:700; color:#f6f8ff; letter-spacing:-.02em; } .sidebar-brand small { display:block; margin-top:4px; color:#7890ae; font: .68rem 'DM Mono',monospace; letter-spacing:.06em; }
      .stAlert { border-radius:8px; }
    </style>
    <div class="topbar">
      <div class="brand"><span class="brand-mark">✦</span> Purple Team <span style="color:#8291a7;font-weight:500">/ Security Operations</span></div>
      <div style="display:flex;align-items:center;gap:14px"><span class="live">SYSTEMS NOMINAL</span><span class="env">DEMO ENVIRONMENT</span></div>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown('<div class="sidebar-brand">PURPLE TEAM LAB<small>THREAT OPERATIONS CONSOLE</small></div>', unsafe_allow_html=True)
    page = st.radio("Workspace", ["Command Center", "Threat Intake", "Simulation Lab", "Detection & Response"], label_visibility="collapsed")
    st.divider()
    st.caption("SCOPE: SYNTHETIC TELEMETRY ONLY")
    st.caption("MODE: SAFE SIMULATION")

if page == "Command Center":
    st.markdown('<div class="section-kicker">Executive overview</div>', unsafe_allow_html=True)
    st.title("Exposure command center")
    st.caption("Prioritized threat intelligence and detection readiness across your simulation environment.")
    risks = [risk_score(item) for item in st.session_state.advisories]
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Open threat records", len(st.session_state.advisories))
    col2.metric("Simulations executed", len(st.session_state.runs))
    col3.metric("Signals correlated", len(st.session_state.events))
    col4.metric("Critical exposure", f"{max(risks, default=0)}/100")
    st.write("")
    card1, card2, card3 = st.columns(3)
    card1.markdown('<div class="insight-card"><div class="section-kicker">Priority path</div><b>Public-facing gateway</b><span>Active-exploitation signal detected. Validate exposure and containment coverage.</span></div>', unsafe_allow_html=True)
    card2.markdown('<div class="insight-card"><div class="section-kicker">Detection posture</div><b>Coverage ready</b><span>Three safe adversary scenarios are available for replay and response validation.</span></div>', unsafe_allow_html=True)
    card3.markdown('<div class="insight-card"><div class="section-kicker">Operations loop</div><b>Intake → Response</b><span>Threat records are reviewed before they become simulation scenarios.</span></div>', unsafe_allow_html=True)
    st.subheader("Prioritized exposure queue")
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
