"""Safe, analyst-led adversary emulation workspace for the platform."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

import streamlit as st


ATTACK_TRACKS = {
    "Internet-facing application exposure": {
        "tag": "T1190 · INITIAL ACCESS",
        "focus": "Exploit public-facing application",
        "basis": "MITRE ATT&CK · CISA KEV context",
        "why": "Internet-exposed services and appliances should be matched to inventory and patch posture as soon as known exploitation is reported.",
        "source": "https://attack.mitre.org/techniques/T1190/",
        "stages": [
            ("Exposure signal", "A synthetic external-service inventory change is observed.", "Compare internet-facing services to the reviewed asset inventory."),
            ("Suspicious request pattern", "Synthetic WAF events show repeated anomalous requests to an administrative route.", "Rate-limit or block the pattern while preserving WAF and proxy evidence."),
            ("Post-access indicator", "A synthetic web-service child-process alert and rare egress connection are correlated.", "Isolate the workload, block egress, and collect application, process, and proxy logs."),
            ("Recovery decision", "The scenario reaches a containment checkpoint; no action is performed by this app.", "Patch or disable the exposed interface, validate service health, then review monitoring coverage."),
        ],
        "denials": ["Restrict management interfaces to approved networks", "Use a WAF or reverse proxy control with reviewed rules", "Segment public workloads from internal services", "Prioritize vendor remediation for matching versions"],
        "signals": ["WAF request anomaly", "Web-service process tree", "DNS / egress connection", "Asset exposure record"],
    },
    "Identity and SaaS account abuse": {
        "tag": "T1078 · IDENTITY",
        "focus": "Valid accounts and suspicious consent",
        "basis": "MITRE ATT&CK · authentication resilience",
        "why": "Identity-led intrusion often appears as a sequence of new sign-in context, elevated consent, and unusual access rather than a single endpoint alert.",
        "source": "https://attack.mitre.org/techniques/T1078/",
        "stages": [
            ("Identity context shift", "A synthetic sign-in occurs from a new device and geography.", "Challenge the session with phishing-resistant MFA and compare it to a normal user baseline."),
            ("Privilege change", "A synthetic high-privilege application consent is recorded.", "Require approval for privileged consent and alert the identity response owner."),
            ("Collection indicator", "Synthetic SaaS audit events show an unusual burst of mailbox and file enumeration.", "Revoke suspicious tokens, suspend the service principal, and scope affected data."),
            ("Recovery decision", "The scenario reaches a containment checkpoint; no tenant settings are changed.", "Rotate or revoke credentials, force reauthentication, and validate conditional-access coverage."),
        ],
        "denials": ["Require phishing-resistant MFA for privileged roles", "Restrict user consent and review admin-consent workflows", "Use short-lived tokens and conditional access", "Alert on consent, token, and high-risk sign-in sequences"],
        "signals": ["Identity provider sign-in", "OAuth consent audit", "SaaS activity audit", "Token revocation event"],
    },
    "Web authorization and API misuse": {
        "tag": "OWASP A01:2025 · APPLICATION",
        "focus": "Broken access control and API authorization drift",
        "basis": "OWASP Top 10 2025",
        "why": "OWASP identifies broken access control as the leading web application risk; authorization failures should be assessed with safe, approved tests and server-side telemetry.",
        "source": "https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/",
        "stages": [
            ("Authorization test plan", "A synthetic test case is queued against a non-production object-ownership rule.", "Define permitted roles, objects, and expected deny decisions before testing."),
            ("Denied-request pattern", "Synthetic application logs show repeated authorization denials across object identifiers.", "Rate-limit the client and preserve request metadata without logging secrets or personal data."),
            ("Control gap signal", "A synthetic monitoring rule flags inconsistent authorization outcomes.", "Route the finding to the API owner; validate authorization in trusted server-side code."),
            ("Recovery decision", "The scenario reaches a design-review checkpoint; no application traffic is sent.", "Apply deny-by-default and ownership checks, then add regression tests and alerts."),
        ],
        "denials": ["Enforce authorization in trusted server-side services", "Deny by default and validate object ownership", "Rate-limit API and controller access", "Add authorization tests to CI and alert on repeated denials"],
        "signals": ["API authorization decision", "Application audit log", "Rate-limit event", "CI authorization test"],
    },
    "Software supply-chain integrity": {
        "tag": "OWASP A03:2025 · SUPPLY CHAIN",
        "focus": "Build and dependency integrity failure",
        "basis": "OWASP Top 10 2025",
        "why": "Software supply-chain failures are a current OWASP risk category. A mature program should rehearse provenance, anomalous build behavior, and recovery without interacting with production pipelines.",
        "source": "https://top10.owasp.org/2025/0x00_2025-Introduction/",
        "stages": [
            ("Dependency change", "A synthetic dependency update appears outside the normal release window.", "Require reviewed provenance, a change record, and an approved package source."),
            ("Build anomaly", "A synthetic build audit event shows an unexpected privileged step.", "Pause the release, restrict runner credentials, and preserve build metadata."),
            ("Artifact review", "A synthetic policy check flags an artifact without expected attestation.", "Quarantine the artifact and compare hashes, attestations, and signing policy."),
            ("Recovery decision", "The scenario reaches a release-control checkpoint; no pipeline is changed.", "Rebuild from a trusted source, rotate affected credentials, and document control improvements."),
        ],
        "denials": ["Require signed, attested artifacts before deployment", "Use least-privileged ephemeral build credentials", "Restrict package sources and pin reviewed dependencies", "Separate build, approval, and deploy responsibilities"],
        "signals": ["Dependency provenance", "Build-runner audit", "Artifact attestation", "Deployment policy decision"],
    },
}


def _card(label: str, value: str, detail: str, tone: str = "") -> None:
    st.markdown(
        f'<div class="red-card {tone}"><div class="desk-label">{escape(label)}</div>'
        f'<div class="red-value">{escape(value)}</div><div class="desk-copy">{escape(detail)}</div></div>',
        unsafe_allow_html=True,
    )


def _session_key(name: str) -> str:
    return f"red_{name}"


def render_red_team_studio() -> None:
    """Render a guided, synthetic simulation with just-in-time defensive modelling."""
    st.session_state.setdefault(_session_key("runs"), [])
    st.session_state.setdefault(_session_key("stage"), 0)
    st.session_state.setdefault(_session_key("track"), next(iter(ATTACK_TRACKS)))
    st.session_state.setdefault(_session_key("scope"), {})

    st.markdown('<div class="desk-eyebrow">RED TEAM STUDIO / SAFE ADVERSARY EMULATION</div>', unsafe_allow_html=True)
    st.title("Follow the attack story. Prepare the denial.")
    st.markdown("A guided, telemetry-only rehearsal for current attack patterns. It models defensive decisions in real time; it never sends traffic, runs payloads, scans targets, or changes production controls.")
    st.caption("SIMULATION-ONLY · NO EXPLOIT CODE · NO EXTERNAL ACTIVITY · USE APPROVED NON-PRODUCTION TESTING FOR VALIDATION")

    active_track = st.session_state[_session_key("track")]
    track = ATTACK_TRACKS[active_track]
    stage_index = st.session_state[_session_key("stage")]
    runs = st.session_state[_session_key("runs")]
    steps_complete = min(stage_index, len(track["stages"]))

    k1, k2, k3, k4 = st.columns(4)
    with k1: _card("ATTACK TRACKS", str(len(ATTACK_TRACKS)), "ATT&CK and OWASP-informed", "red-accent")
    with k2: _card("CURRENT TRACK", f"{steps_complete}/{len(track['stages'])}", "Synthetic stages completed", "amber")
    with k3: _card("REHEARSALS", str(len(runs)), "Session-only audit entries", "violet")
    with k4: _card("CONTROL PROMPTS", str(len(track["denials"])), "Disruptions to validate", "teal")

    choose, model = st.columns([1.45, 1], gap="large")
    with choose:
        st.subheader("1. Choose an attack pattern")
        selected = st.selectbox("Simulation track", list(ATTACK_TRACKS), index=list(ATTACK_TRACKS).index(active_track))
        if selected != active_track:
            st.session_state[_session_key("track")] = selected
            st.session_state[_session_key("stage")] = 0
            st.rerun()
        track = ATTACK_TRACKS[selected]
        st.markdown(f'<div class="red-track"><span>{escape(track["tag"])}</span><b>{escape(track["focus"])}</b><p>{escape(track["why"])}</p></div>', unsafe_allow_html=True)
        st.link_button(f"Read authoritative context: {track['basis']} ↗", track["source"])

    with model:
        st.markdown('<div class="threat-model-head">LIVE THREAT MODEL</div>', unsafe_allow_html=True)
        st.caption("This side panel changes the next defensive questions as you progress. Inputs remain in this browser session.")
        environment = st.selectbox("Environment pattern", ["Internet-facing application", "Identity and SaaS", "Cloud build pipeline", "Mixed / not yet scoped"], key=_session_key("environment"))
        crown_jewel = st.text_input("Business service or crown jewel", placeholder="e.g., customer portal, finance SaaS", key=_session_key("crown"))
        exposure = st.checkbox("Potential internet or external exposure", key=_session_key("external"))
        logging = st.checkbox("Relevant telemetry owner identified", key=_session_key("logging"))
        st.session_state[_session_key("scope")] = {"environment": environment, "crown_jewel": crown_jewel, "exposure": exposure, "logging": logging}
        model_score = 45 + (25 if exposure else 0) + (15 if not logging else 0) + (10 if environment != "Mixed / not yet scoped" else 0)
        _card("READINESS PROMPT", f"{min(100, model_score)}/100", "A planning cue—not a risk score for your organization.", "amber")
        if not crown_jewel:
            st.info("Name the affected service to make the rehearsal reviewable. Do not enter incident details or secrets in this public demo.")
        elif not logging:
            st.warning("Assign a telemetry owner before using this rehearsal as a detection-readiness exercise.")
        else:
            st.success("Scope and telemetry ownership are captured for this browser session.")

    st.divider()
    st.markdown('<div class="desk-eyebrow">2. GUIDE THE SIMULATED ATTACK PATH</div>', unsafe_allow_html=True)
    left, right = st.columns([1.65, 1], gap="large")
    with left:
        st.subheader(track["focus"])
        st.caption("Each step is an invented observation for discussion and detection design, not a live attack or a test against any system.")
        for index, (stage, event, action) in enumerate(track["stages"]):
            state = "complete" if index < steps_complete else "active" if index == steps_complete else "pending"
            marker = "✓" if state == "complete" else f"{index + 1:02}"
            st.markdown(
                f'<div class="attack-step {state}"><div class="attack-marker">{marker}</div><div><div class="attack-stage">{escape(stage)}</div>'
                f'<div class="attack-event">{escape(event)}</div><div class="attack-action">DEFENSIVE MOVE · {escape(action)}</div></div></div>',
                unsafe_allow_html=True,
            )
        advance, reset = st.columns([3, 1])
        with advance:
            if stage_index < len(track["stages"]):
                if st.button(f"Play next simulated observation · {track['stages'][stage_index][0]}", type="primary", use_container_width=True):
                    now = datetime.now(timezone.utc)
                    runs.insert(0, {"track": selected, "stage": track["stages"][stage_index][0], "time": now, "service": crown_jewel or "Unscoped service"})
                    st.session_state[_session_key("stage")] = stage_index + 1
                    st.session_state[_session_key("notice")] = f"Synthetic observation added: {track['stages'][stage_index][0]}. The disruption panel has been updated."
                    st.rerun()
            else:
                st.button("Attack path complete — review disruptions", disabled=True, use_container_width=True)
        with reset:
            if st.button("Reset", use_container_width=True):
                st.session_state[_session_key("stage")] = 0
                st.rerun()

    with right:
        st.markdown('<div class="threat-model-head">DISRUPTION & DENIAL OPTIONS</div>', unsafe_allow_html=True)
        st.caption("Recommendations are review prompts. This application cannot and does not implement controls.")
        for index, denial in enumerate(track["denials"]):
            done = st.checkbox(denial, key=f"red-denial-{selected}-{index}")
            if done:
                st.caption("Marked for validation in this session")
        st.markdown("#### Expected evidence")
        for signal in track["signals"]:
            st.markdown(f"- {signal}")
        st.markdown("#### Decision gate")
        if steps_complete < 2:
            st.write("Confirm scope, owner, and expected telemetry before treating this as a detection rehearsal.")
        elif steps_complete < len(track["stages"]):
            st.write("At this point, a response lead should decide whether to preserve evidence, contain the affected service, and start business-impact assessment.")
        else:
            st.write("Close only after recovery controls, telemetry coverage, ownership, and an approved follow-up test are recorded outside this demo.")

    if st.session_state.get(_session_key("notice")):
        st.success(st.session_state.pop(_session_key("notice")))

    st.divider()
    st.markdown('<div class="desk-eyebrow">SIMULATION LOG</div>', unsafe_allow_html=True)
    if not runs:
        st.info("Start the first synthetic observation to create a session-only rehearsal log.")
    else:
        st.caption("The log contains fictional telemetry-stage records only. Export or record decisions in your approved operational system.")
        for run in runs[:6]:
            st.markdown(
                f'<div class="red-log"><b>{escape(run["stage"])}</b><span>{escape(run["track"])}</span>'
                f'<small>{run["time"].strftime("%H:%M:%S UTC")} · {escape(run["service"])}</small></div>',
                unsafe_allow_html=True,
            )

    st.markdown('<div class="desk-footer"><b>How to use this professionally</b><span>Select an approved scenario, identify the owner and telemetry, review disruption options, then validate with authorized procedures in a non-production or sanctioned environment.</span></div>', unsafe_allow_html=True)
