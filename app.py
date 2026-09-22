"""Purple Team Lab — a safe, portfolio-ready threat-response simulator."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any
from urllib.request import Request, urlopen
import json

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from dashboard import render_dashboard


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
    if "baseline_seeded" not in st.session_state:
        st.session_state.baseline_seeded = False
    if "page" not in st.session_state:
        st.session_state.page = "Command Center"


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
    st.session_state.runs.insert(0, {
        "id": run_id,
        "scenario": name,
        "advisory": advisory_title,
        "technique": scenario["technique"],
        "response": scenario["response"],
        "time": now,
        "status": "Detection validated",
        "signals": len(events),
        "summary": f"Blue team correlated {len(events)} synthetic signals and proposed {len(scenario['response'])} containment actions.",
    })


def scenario_for(advisory: dict[str, Any]) -> str:
    technique = advisory.get("technique", "")
    if "T1528" in technique or "token" in advisory.get("title", "").lower():
        return "OAuth token misuse"
    if "T1110" in technique or "credential" in advisory.get("title", "").lower():
        return "Credential access attempt"
    return "Public-facing application exploitation"


def run_recent_briefing() -> int:
    """Generate a safe, telemetry-only readiness test from the newest intake records."""
    kev_records = [item for item in st.session_state.advisories if item.get("source") == "CISA KEV"]
    candidates = (kev_records or st.session_state.advisories)[:3]
    for advisory in reversed(candidates):
        simulate(scenario_for(advisory), advisory["title"])
    return len(candidates)


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


def latest_kev_snapshot(limit: int = 10) -> list[dict[str, Any]]:
    """Normalize the latest CISA KEV entries for defensive display and testing."""
    items = sorted(fetch_kev(), key=lambda x: x.get("dateAdded", ""), reverse=True)[:limit]
    return [{
        "title": item.get("vulnerabilityName", item.get("cveID", "Unidentified advisory")),
        "cve": item.get("cveID", "Not assigned"),
        "added": item.get("dateAdded", "Unknown"),
        "product": f"{item.get('vendorProject', '')} {item.get('product', '')}".strip() or "Affected product not specified",
        "patch": item.get("requiredAction", "Apply the vendor's current security update and validate exposure."),
        "description": item.get("shortDescription", ""),
        "notes": item.get("notes", ""),
        "due": item.get("dueDate", "Not supplied"),
        "ransomware": item.get("knownRansomwareCampaignUse", "Unknown"),
        "source": "CISA KEV",
        "technique": "T1190 — Exploit Public-Facing Application",
    } for item in items]


def run_advisory_campaign(advisories: list[dict[str, Any]]) -> int:
    """Run safe synthetic tests only; advisory data is never used as executable input."""
    for advisory in reversed(advisories):
        simulate(scenario_for(advisory), advisory["title"])
    return len(advisories)


def seed_baseline_simulations() -> None:
    """Create a portfolio baseline of synthetic tests for a useful first-view dashboard."""
    if st.session_state.baseline_seeded:
        return
    baseline_tests = [
        ("Public-facing application exploitation", "Baseline: public-facing gateway readiness"),
        ("OAuth token misuse", "Baseline: identity consent and token readiness"),
        ("Credential access attempt", "Baseline: authentication abuse readiness"),
        ("Public-facing application exploitation", "Baseline: web telemetry correlation replay"),
        ("OAuth token misuse", "Baseline: privileged API investigation replay"),
        ("Credential access attempt", "Baseline: account takeover containment replay"),
    ]
    for scenario, title in reversed(baseline_tests):
        simulate(scenario, title)
    st.session_state.baseline_seeded = True


def operational_summary() -> dict[str, Any]:
    """Summarize completed safe simulations for command-center decision support."""
    runs = st.session_state.runs
    events = st.session_state.events
    actions = [action for run in runs for action in run["response"]]
    high_signals = sum(event["severity"] == "HIGH" for event in events)
    coverage = len({run["technique"] for run in runs})
    return {
        "coverage": coverage,
        "actions": len(set(actions)),
        "high_signals": high_signals,
        "remediations": [
            "Patch or disable internet-facing administration paths; validate WAF, web-server, and egress telemetry before reopening exposure.",
            "Revoke suspicious OAuth tokens, restrict privileged consent, and require reauthentication for impacted identities.",
            "Apply MFA challenges and account-reset playbooks for anomalous sign-in sequences; retain identity and endpoint evidence.",
        ],
    }


def render_live_pipeline(advisory_count: int, simulation_count: int, signal_count: int) -> None:
    """Interactive local-only pipeline renderer for the command center."""
    markup = f"""
    <!doctype html><html><head><style>
      * {{ box-sizing:border-box }} body {{ margin:0; background:transparent; color:#edf3fb; font-family:Inter,Arial,sans-serif; }}
      .shell {{ background:linear-gradient(135deg,#101b2b,#0b1421); border:1px solid #293a53; border-radius:12px; padding:18px; overflow:visible; }}
      .head {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:17px; }} .kicker {{ color:#a48eff; font-size:10px; font-weight:700; letter-spacing:1.4px; }} h2 {{ margin:4px 0 0; font-size:17px; }} .live {{ color:#81edbf; font-size:11px; font-weight:700; }} .live:before {{ content:'●'; color:#38d5c5; margin-right:5px; }}
      .pipeline {{ display:flex; align-items:stretch; width:100%; min-width:0; position:relative; }}
      .stage {{ position:relative; z-index:2; flex:1 1 0; min-width:0; min-height:106px; padding:13px 10px; text-align:left; background:#152237; color:#eff5ff; border:1px solid #30425d; border-radius:9px; cursor:pointer; transition:.2s ease; overflow-wrap:anywhere; }}
      .stage:hover,.stage.active {{ border-color:#9b7cff; background:#1c2a45; transform:translateY(-2px); }} .stage:focus {{ outline:2px solid #a58bff; outline-offset:2px; }}
      .num {{ color:#a692ff; font-size:10px; font-weight:700; letter-spacing:1px; }} .name {{ display:block; margin-top:8px; font-size:13px; font-weight:700; }} .count {{ display:block; margin-top:7px; color:#91a5bf; font-size:11px; }}
      .line {{ align-self:center; flex:0 0 clamp(12px,2vw,28px); height:2px; background:#3a4b65; position:relative; }} .line:after {{ content:''; position:absolute; top:-3px; left:0; height:8px; width:8px; border-radius:50%; background:#a58bff; box-shadow:0 0 12px #a58bff; animation:flow 2.8s linear infinite; }}
      .line:nth-of-type(4):after {{ animation-delay:.55s }} .line:nth-of-type(6):after {{ animation-delay:1.1s }} .line:nth-of-type(8):after {{ animation-delay:1.65s }} .line:nth-of-type(10):after {{ animation-delay:2.2s }}
      .detail {{ margin-top:15px; padding-top:13px; border-top:1px solid #26374f; color:#a9b8ca; font-size:12px; min-height:33px; }} .detail b {{ color:#f4f7fb; }}
      @keyframes flow {{ from {{ left:0 }} to {{ left:calc(100% - 8px) }} }} @media(max-width:760px) {{ .shell {{ padding:14px; }} .stage {{ padding:10px 6px; min-height:94px; }} .num {{ font-size:9px; }} .name {{ margin-top:6px; font-size:12px; }} .count {{ margin-top:5px; font-size:10px; }} .line {{ flex-basis:10px; }} .line:after {{ animation-duration:2.2s }} }} @media(max-width:500px) {{ .shell {{ padding:11px; }} .head {{ margin-bottom:12px; }} h2 {{ font-size:15px; }} .live {{ font-size:9px; }} .stage {{ padding:8px 4px; min-height:86px; }} .name {{ font-size:11px; }} .count {{ font-size:9px; }} .line {{ flex-basis:7px; }} }} @media(prefers-reduced-motion:reduce) {{ * {{ animation:none!important; transition:none!important }} }}
    </style></head><body><div class="shell">
      <div class="head"><div><div class="kicker">LIVE PROCESS FLOW</div><h2>Threat-to-response pipeline</h2></div><div class="live">SESSION ACTIVE</div></div>
      <div class="pipeline">
        <button class="stage active" data-stage="Advisory intake" data-detail="Normalizes public advisories and analyst submissions into reviewable threat records."><span class="num">01</span><span class="name">Intake</span><span class="count">{advisory_count} records</span></button><div class="line"></div>
        <button class="stage" data-stage="Validation" data-detail="Checks source context, exploitation status, product scope, and safe ATT&CK mapping."><span class="num">02</span><span class="name">Validate</span><span class="count">Source-gated</span></button><div class="line"></div>
        <button class="stage" data-stage="Safe emulation" data-detail="Creates synthetic signals only. No exploitation, scanning, external traffic, or production actions occur."><span class="num">03</span><span class="name">Emulate</span><span class="count">{simulation_count} runs</span></button><div class="line"></div>
        <button class="stage" data-stage="Detection" data-detail="Correlates simulated identity, endpoint, network, and application telemetry into a validated detection path."><span class="num">04</span><span class="name">Detect</span><span class="count">{signal_count} signals</span></button><div class="line"></div>
        <button class="stage" data-stage="Containment" data-detail="Generates reviewable containment recommendations such as isolation, blocking, revocation, and evidence preservation."><span class="num">05</span><span class="name">Respond</span><span class="count">Playbook-led</span></button><div class="line"></div>
        <button class="stage" data-stage="Coverage improvement" data-detail="Records outcomes in the simulation timeline so detection coverage and response readiness can be improved."><span class="num">06</span><span class="name">Improve</span><span class="count">Continuous</span></button>
      </div><div class="detail" id="detail" aria-live="polite"><b>Advisory intake:</b> Normalizes public advisories and analyst submissions into reviewable threat records.</div>
    </div><script>document.querySelectorAll('.stage').forEach(b=>b.addEventListener('click',()=>{{document.querySelectorAll('.stage').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.getElementById('detail').innerHTML='<b>'+b.dataset.stage+':</b> '+b.dataset.detail}}));</script></body></html>
    """
    components.html(markup, height=270, scrolling=False)


init_state()
seed_baseline_simulations()

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
      [data-testid="stCaptionContainer"] { color:#b0bdd0; }
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
      [data-testid="stSidebar"] .stButton > button { width:100%; justify-content:flex-start; background:transparent; color:#aab7ca; border:1px solid transparent; box-shadow:none; font-size:.86rem; font-weight:500; padding:.52rem .68rem; }
      [data-testid="stSidebar"] .stButton > button:hover { background:#182338; border-color:#2a3a53; color:#fff; }
      [data-testid="stSidebar"] .stButton > button[kind="primary"] { background:linear-gradient(90deg,rgba(137,104,250,.26),rgba(137,104,250,.06)); border-color:#5e4db1; color:#fff; }
      .run-card { background:linear-gradient(130deg,rgba(24,35,56,.96),rgba(13,22,35,.94)); border:1px solid #2a3951; border-radius:10px; padding:1rem 1.1rem; margin-bottom:.7rem; }
      .run-meta { color:#94a6bd; font:.72rem 'DM Mono',monospace; text-transform:uppercase; letter-spacing:.04em; } .run-status { color:#8ff0c4; font-size:.76rem; font-weight:700; float:right; }
      .workflow-card { background:linear-gradient(135deg,rgba(22,34,53,.96),rgba(13,22,35,.95)); border:1px solid #2b3b55; border-radius:11px; padding:1.1rem 1.15rem; min-height:144px; }
      .workflow-step { width:22px; height:22px; display:inline-grid; place-items:center; border-radius:50%; background:#785bea; color:#fff; font:.7rem 'DM Mono',monospace; font-weight:700; margin-right:7px; }
      .workflow-card b { color:#fff; font-size:1rem; } .workflow-card p { margin:.55rem 0 0; color:#9cabbe; font-size:.84rem; line-height:1.5; }
      .action-card { background:rgba(255,183,93,.08); border-left:3px solid #ffb75d; border-radius:6px; padding:.72rem .85rem; margin:.55rem 0; color:#d9e2ee; font-size:.86rem; line-height:1.45; }
      .muted-panel { background:rgba(18,27,41,.82); border:1px solid #2a3951; border-radius:10px; padding:1rem 1.1rem; }
      .stAlert { border-radius:8px; }
      /* Keep widget text independent of prose colors, including nested Markdown. */
      :root { --muted:#b0bdd0; }
      [data-testid="stHeader"] { background:#090e18; color:#e6edf7; }
      .block-container { padding-top:3.5rem; max-width:1500px; }
      h1 { font-size:2.25rem!important; line-height:1.15!important; }
      h3 { font-size:1.2rem!important; margin-top:.5rem!important; }
      .stButton > button, .stDownloadButton > button, .stLinkButton > a,
      .stFormSubmitButton > button { background:#19253a; color:#e6edf7!important; border:1px solid #364660; border-radius:9px; padding:.6rem .8rem; }
      .stButton > button p, .stDownloadButton > button p, .stLinkButton > a p,
      .stFormSubmitButton > button p { color:inherit!important; font-weight:600; line-height:1.4; }
      .stButton > button [data-testid="stMarkdownContainer"], .stButton > button p { white-space:normal!important; overflow:visible!important; text-overflow:clip!important; }
      .stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] { background:#bba5ff; border-color:#bba5ff; color:#170e32!important; }
      .stButton > button:hover, .stDownloadButton > button:hover, .stLinkButton > a:hover { background:#283855; color:#fff!important; border-color:#bba5ff; }
      .stButton > button[kind="primary"]:hover { background:#d0bfff; color:#170e32!important; }
      button:focus-visible, a:focus-visible { outline:2px solid #c4b5fd!important; outline-offset:3px; }
      .stButton > button:disabled { color:#b0bdd0!important; background:#192030!important; }
      [data-testid="stSidebar"] .stButton > button[kind="primary"] { color:#eee8ff!important; }
      [data-testid="stWidgetLabel"] p, [data-testid="stExpander"] summary p { color:#e6edf7!important; }
      [data-baseweb="tab"] { color:#bac7da!important; }
      [data-baseweb="tab"][aria-selected="true"] { color:#d3c4ff!important; }
      .desk-eyebrow { color:#c4afff; font-size:.7rem; letter-spacing:.14em; font-weight:700; margin-bottom:.6rem; }
      .desk-card { border:1px solid #2b3950; background:linear-gradient(125deg,#172237,#101826); border-radius:12px; padding:1rem; min-height:130px; margin:.25rem 0 .4rem; }
      .desk-card.violet { border-top:2px solid #b499ff; }
      .desk-card.amber { border-top:2px solid #eab76b; }
      .desk-card.teal { border-top:2px solid #63d5c6; }
      .desk-label { color:#b0bdd0; font-size:.66rem; font-weight:650; letter-spacing:.07em; margin-bottom:.55rem; }
      .desk-value { color:#f2f5fc; font-size:1.5rem; font-weight:650; letter-spacing:-.025em; line-height:1.25; overflow-wrap:anywhere; }
      .desk-copy { color:#bac7da; font-size:.8rem; line-height:1.5; margin-top:.65rem; }
      .desk-guide { display:flex; flex-wrap:wrap; align-items:center; gap:14px 24px; padding:14px 18px; border:1px solid #303756; border-radius:10px; background:#18182c; margin:.7rem 0; color:#d3c4ff; font-size:.8rem; }
      .desk-guide b { color:#faf5ff; }
      .desk-badge { display:inline-block; background:#3b2b20; color:#ffcf91; padding:5px 9px; border:1px solid #785737; border-radius:5px; font-size:.62rem; font-weight:700; letter-spacing:.05em; margin:0 5px 8px 0; }
      .desk-badge.neutral { color:#c6d4e6; background:#1a2638; border-color:#3b4a62; }
      .desk-footer { display:flex; flex-wrap:wrap; gap:10px 24px; color:#b6c5da; border-top:1px solid #2b3950; padding:20px 0; font-size:.85rem; margin-top:24px; }
      .desk-footer b { color:#d3c4ff; }
      @media(max-width:800px) { .block-container { padding:3.5rem 1rem 2rem; } .topbar { flex-wrap:wrap; gap:12px; } h1 { font-size:1.8rem!important; } }
    </style>
    <div class="topbar">
      <div class="brand"><span class="brand-mark">✦</span> Purple Team <span style="color:#8291a7;font-weight:500">/ Security Operations</span></div>
      <div style="display:flex;align-items:center;gap:14px"><span class="env">PUBLIC INTELLIGENCE / DEMO LAB</span></div>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown('<div class="sidebar-brand">PURPLE TEAM LAB<small>THREAT OPERATIONS CONSOLE</small></div>', unsafe_allow_html=True)
    navigation = [("Command Center", "◫"), ("Threat Intake", "◌"), ("Simulation Lab", "◈"), ("Detection & Response", "◉"), ("Recent Simulations", "◷")]
    for destination, icon in navigation:
        if st.button(f"{icon}  {destination}", key=f"nav-{destination}", type="primary" if st.session_state.page == destination else "secondary"):
            st.session_state.page = destination
    page = st.session_state.page
    st.divider()
    st.caption("SCOPE: SYNTHETIC TELEMETRY ONLY")
    st.caption("MODE: SAFE SIMULATION")

if page == "Command Center":
    render_dashboard(latest_kev_snapshot, fetch_kev, simulate, SCENARIOS, render_live_pipeline)

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

elif page == "Recent Simulations":
    st.markdown('<div class="section-kicker">Readiness validation</div>', unsafe_allow_html=True)
    st.title("Recent simulations")
    st.caption("A defensible audit trail for synthetic tests sourced from reviewed threat intelligence.")
    left, right = st.columns([3, 1])
    with left:
        st.markdown("Run the latest intake through safe behavior emulation. No exploit code, external traffic, or production changes are involved.")
    with right:
        if st.button("Run latest briefing", type="primary", use_container_width=True):
            count = run_recent_briefing()
            st.success(f"Completed {count} telemetry-only readiness simulation(s).")
    if not st.session_state.runs:
        st.info("No simulations have been recorded yet. Run the latest briefing or start a focused scenario from Simulation Lab.")
    else:
        c1, c2, c3 = st.columns(3)
        c1.metric("Completed", len(st.session_state.runs))
        c2.metric("Validated", sum(run["status"] == "Detection validated" for run in st.session_state.runs))
        c3.metric("Signals exercised", sum(run["signals"] for run in st.session_state.runs))
        st.subheader("Simulation timeline")
        for run in st.session_state.runs:
            timestamp = run["time"].strftime("%Y-%m-%d %H:%M UTC")
            st.markdown(f'''<div class="run-card"><span class="run-status">● {run["status"].upper()}</span><b>{run["scenario"]}</b><div class="run-meta">{timestamp} · {run["technique"]} · RUN {run["id"]}</div><p style="margin:.6rem 0 .2rem">{run["summary"]}</p><div class="run-meta">THREAT INPUT: {run["advisory"]}</div></div>''', unsafe_allow_html=True)

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
