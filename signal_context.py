"""Signal Context: evidence-first, synthetic security investigation workspace."""
import json
from html import escape

import streamlit as st

from signal_data import CASES, correlate, database, findings, response_status


def describe(event):
    """Explain only the selected event, without borrowing future evidence."""
    d, action, outcome = event["details"], event["action"], event["outcome"]
    descriptions = {
        "SignIn": f'Authentication {outcome}; MFA is {d.get("mfa", "unknown")}. ' + ("The device is new to this fixture's account history. This is a lead, not proof of compromise." if d.get("new_device") else "The device is known in this fixture. That does not by itself prove the session is trustworthy."),
        "AssumeRole": f'The session obtained the {d.get("role", "recorded")} role. Review its effective permissions and the federation mapping.',
        "ListObjects": f'The session enumerated {d.get("objects_listed", 0)} object names. Listing can precede collection, but is also normal application behavior.',
        "GetObject": (f'The session read {d.get("object", "an object")} ({d.get("bytes", 0):,} bytes). A successful read supports data access, not proof of onward exfiltration.' if outcome == "success" else "The storage request was denied. This establishes the outcome of this request, not universal containment."),
        "AuthorizationDecision": f'The request was allowed with subject {d.get("subject_tenant")} and object owner {d.get("object_tenant")}; object-level authorization is recorded as {d.get("object_check")}. Correlate the request ID with the response.',
        "ApiRequest": f'API request {d.get("request_id")} returned HTTP {d.get("status")}. ' + ("The audit record explicitly reports an object response. Join ownership evidence before concluding cross-tenant disclosure." if d.get("returned_object") else "Status alone does not establish whether a sensitive object was returned."),
        "DiagnosticSettingsWrite": f'Monitoring configuration changed under {d.get("change_id")}. Determine whether the change was approved and whether delivery continued.',
        "ChangeTicketLookup": f'Change {d.get("change_id")} lookup: approved={d.get("approved")}, actor match={d.get("actor_match")}, resource match={d.get("resource_match")}, within window={d.get("within_window")}. This is defender enrichment, not actor activity.',
        "LogDeliveryCheck": f'A post-change test reports received_test_event={d.get("received_test_event")}. It checks one delivery path, not complete logging coverage.',
        "CaseDisposition": f'The defender recorded disposition: {d.get("disposition")}. Review the referenced evidence rather than accepting the label alone.',
    }
    if event["kind"] == "SIEM alert":
        return "A detection rule raised an alert using " + ", ".join(d.get("evidence_ids", [])) + ". This is derived evidence, not an additional attacker action or an independent confirmation."
    if action in ("RevokeSession", "RestrictEndpoint"):
        return ("The defender queued a response. A queued job has not yet established enforcement." if outcome == "queued" else "The response system reports completion. Seek a subsequent access or enforcement check to validate the effect.")
    return descriptions.get(action, "Review the source record and its outcome before interpreting intent.")


def move_cursor(key, delta, maximum):
    st.session_state[key] = max(1, min(maximum, st.session_state.get(key, maximum) + delta))


def save_notebook(case_id, field, widget_key):
    st.session_state.sc_notebooks.setdefault(case_id, {})[field] = st.session_state[widget_key]


def render_signal_context():
    if "sc_notebooks" not in st.session_state:
        st.session_state.sc_notebooks = {}
    st.markdown("""<style>
    [data-testid="stCaptionContainer"] p{color:#b3c0d4!important}
    .sc-intro{padding:22px 25px;border:1px solid #354761;border-radius:14px;background:linear-gradient(115deg,#18223a,#101b29);margin:6px 0 22px}
    .sc-kicker{font-size:11px;font-weight:700;letter-spacing:1.8px;color:#bca8ff;text-transform:uppercase}
    .sc-intro h2{margin:7px 0!important;color:#f0f4ff!important;font-size:26px!important}
    .sc-intro p{color:#c2cde0;margin:4px 0;line-height:1.6}
    .sc-event{position:relative;margin:0 0 0 9px;padding:0 0 24px 25px;border-left:2px solid #344762}
    .sc-event:before{content:'';position:absolute;left:-6px;top:7px;width:10px;height:10px;border-radius:50%;background:#9d8cff;box-shadow:0 0 0 4px #101927}
    .sc-event.response:before{background:#51d9c1}.sc-event.alert:before{background:#f8c46c}
    .sc-event.selected .sc-card{border-color:#b59cff;background:#202940}
    .sc-card{padding:15px 17px;background:#111c2c;border:1px solid #30435e;border-radius:10px;overflow-wrap:anywhere}
    .sc-meta{font-size:11px;color:#b6c6dc;letter-spacing:.5px;margin-bottom:8px}
    .sc-title{font-size:16px;font-weight:650;color:#f0f4ff;margin-bottom:6px}
    .sc-body{font-size:13px;color:#c3cfe1;line-height:1.6}
    .sc-outcome{display:inline-block;font-size:11px;margin-top:9px;padding:3px 8px;border:1px solid #4a5f7b;border-radius:5px;color:#e4ebf8}
    .sc-note{padding:14px 16px;border-left:3px solid #8e79eb;background:#152034;color:#d4dff0;border-radius:0 8px 8px 0;margin-bottom:16px;line-height:1.6}
    @media(prefers-reduced-motion:no-preference){.sc-event.selected:before{animation:sc-pulse 2s ease-in-out infinite}@keyframes sc-pulse{50%{box-shadow:0 0 0 7px #9d8cff22}}}
    </style><div class="sc-intro"><div class="sc-kicker">Signal Context / Evidence-led investigation</div><h2>Turn scattered events into an evidence story.</h2><p>Follow a session across identity, cloud, SIEM and SOAR. Test a threat hypothesis, inspect its evidence, and decide what to verify or disrupt next.</p></div>""", unsafe_allow_html=True)
    st.caption("TRAINING DATA · 23 September 2026 · Fictional identities and assets · Illustrative source formats, not connected vendor tools · No production actions")

    case_id = st.selectbox("Choose an investigation", list(CASES), format_func=lambda k: CASES[k]["name"], key="sc_case")
    case = CASES[case_id]
    st.markdown(f'### {case["question"]}')
    st.write(case["lesson"])

    conn = database()
    try:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        all_events, all_duplicates = correlate(conn, case_id)
        db_bytes = conn.serialize()
        normalized = [dict(row) for row in conn.execute("SELECT id,time,source,kind,actor,session,action,outcome,origin FROM events ORDER BY time,id")]
        with st.expander("Evidence coverage · remove a source to see what becomes unknowable"):
            sources = st.multiselect("Available sources", case["sources"], default=case["sources"], key=f"sc_sources_{case_id}")
            st.caption("Source removal is an instructional ablation test, not a disconnection of a real integration. Findings and response validation use only included, revealed events.")
        events, duplicates = correlate(conn, case_id, sources)
    finally:
        conn.close()

    if not events:
        st.info("No evidence is visible. Select at least one source above to investigate.")
        return
    cursor_key = f"sc_cursor_{case_id}"
    if cursor_key not in st.session_state or st.session_state[cursor_key] > len(events):
        st.session_state[cursor_key] = len(events)
    b1, b2, b3 = st.columns([1, 1, 4])
    b1.button("← Earlier", key="sc_previous", on_click=move_cursor, args=(cursor_key, -1, len(events)), disabled=st.session_state[cursor_key] <= 1, use_container_width=True)
    b2.button("Next event →", key="sc_next", on_click=move_cursor, args=(cursor_key, 1, len(events)), disabled=st.session_state[cursor_key] >= len(events), use_container_width=True)
    with b3:
        if len(events) > 1:
            cursor = st.slider("Evidence revealed", 1, len(events), key=cursor_key)
        else:
            cursor = 1
            st.caption("1 event available from the selected sources")
    visible = events[:cursor]
    deductions = findings(visible)
    status, status_detail = response_status(visible)
    st.caption(f'Replay through {visible[-1]["time"][11:19]} UTC · {cursor} of {len(events)} filtered events revealed · Findings never use later events. Start at 1 to work the case progressively.')
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Events revealed", len(visible))
    m2.metric("Sources", len({e["source"] for e in visible}))
    m3.metric("Assessments", len(deductions))
    m4.metric("SIEM alerts", sum(e["kind"] == "SIEM alert" for e in visible))

    investigation, data_tab, notebook = st.tabs(["Investigation timeline", "Data & correlation", "Actions & handoff"])
    with investigation:
        left, right = st.columns([1.35, 1], gap="large")
        with left:
            st.subheader("What happened, in order")
            st.caption("Purple: observed activity · Amber: derived SIEM alert · Teal: defender response. No human threat-actor attribution is established.")
            selected = st.selectbox("Inspect an evidence record", [e["id"] for e in visible], index=len(visible)-1, format_func=lambda eid: next(f'{e["id"]} · {e["action"]} · {e["source"]}' for e in visible if e["id"] == eid), key=f"sc_inspect_{case_id}_{len(visible)}_{','.join(sources)}")
            for event in visible:
                cls = "response" if event["kind"] == "SOAR response" else "alert" if event["kind"] == "SIEM alert" else "activity"
                if event["id"] == selected:
                    cls += " selected"
                meta = f'{event["time"][11:19]} UTC  /  {event["id"]}  /  {event["source"]}  /  {event["kind"]}'
                st.markdown(f'<div class="sc-event {cls}"><div class="sc-card"><div class="sc-meta">{escape(meta)}</div><div class="sc-title">{escape(event["action"])}</div><div class="sc-body">{escape(describe(event))}</div><span class="sc-outcome">{escape(event["outcome"].upper())}</span></div></div>', unsafe_allow_html=True)
        with right:
            st.subheader("Threat-model lens")
            st.caption("A live interpretation of the revealed evidence—not a prediction engine.")
            st.markdown(f'<div class="sc-note"><strong>Protect: {escape(case["service"])}</strong><br>Trust boundary: {escape(case["boundary"])}</div>', unsafe_allow_html=True)
            for finding in deductions:
                with st.container(border=True):
                    st.markdown(f'**{finding["title"]}**')
                    st.caption(f'{finding["confidence"]} evidence confidence · {finding["mapping"]}')
                    st.write(finding["explanation"])
                    st.caption("Supporting records: " + " · ".join(finding["evidence"]))
                    st.markdown("**Challenge the hypothesis**")
                    st.write(finding["alternative"])
            if not deductions:
                st.info("Insufficient evidence for a modeled finding. A source may be missing, or the relevant event has not yet been revealed. No finding does not mean no threat.")
            with st.expander("How to read confidence"):
                st.write("Low: an ambiguous observation. Moderate: a suspicious sequence supported across events. High: direct evidence supports the narrowly stated assessment—not necessarily malicious intent. These deterministic teaching labels are not calibrated probabilities.")
                st.write("STRIDE prompts: cloud identity → spoofing and information disclosure; cross-tenant API → information disclosure and privilege boundaries; monitoring changes → tampering and repudiation. These are modeling questions, not additional detected attacks.")
            st.markdown(f'**Response validation · {status}**')
            st.write(status_detail)
            st.markdown("**Visibility gap to investigate**")
            st.write(case["blind_spot"])
            st.markdown("**Selected evidence**")
            record = next(e for e in visible if e["id"] == selected)
            st.caption(f'{record["id"]} · {record["actor"]} · {record["session"]} · {record["asset"]}')
            refs = record["details"].get("evidence_ids", [])
            if refs:
                missing = [eid for eid in refs if eid not in {e["id"] for e in visible}]
                st.write("Evidence lineage: " + " + ".join(refs) + " → " + record["id"])
                if missing:
                    st.warning("Referenced evidence not visible: " + ", ".join(missing) + ". Do not treat the alert or playbook label as independent proof.")
            with st.expander("Inspect original sample payload"):
                st.json(record["raw"])
            for label, url in case["references"].items():
                st.markdown(f'[{label}]({url})')

    with data_tab:
        st.subheader("Explainable correlation, not a black box")
        st.write(f'This in-memory SQLite database contains {total} synthetic records across three cases, including three unrelated same-IP neighbors and one duplicate ingestion. Your full case has {len(all_events)} unique records before source filtering.')
        st.code(f'actor = {case["actor"]}\nsession = {case["session"]}\nwindow = {case["start"]} … {case["end"]}\ndeduplicate = (source, original_event_id)\norder = event_time, event_id', language="text")
        st.write(case["join_note"])
        st.caption(f'{duplicates} duplicate ingestion(s) suppressed for selected sources; {all_duplicates} in the full case. Duplicate counts describe the fixture, not a newly detected attack. IP address alone is never a join key.')
        st.info("Source adapters normalize illustrative fields into one schema. SIEM evidence references and SOAR outcomes remain distinct from original activity. Production connectors, ingestion delays, identity resolution, integrity checks and access controls are not implemented.")
        st.dataframe(normalized, hide_index=True, use_container_width=True)
        st.download_button("Download sample SQLite database", db_bytes, "signal-context-synthetic.sqlite", "application/vnd.sqlite3", key="sc_download_db")

    with notebook:
        st.subheader("Turn interpretation into an analyst handoff")
        st.caption("Recommendations only. Checking a box does not execute a response or validate a fix. Notes stay in this browser session; do not enter real incident data.")
        decisions = []
        saved = st.session_state.sc_notebooks.get(case_id, {})
        for i, (owner, action) in enumerate(case["actions"]):
            widget_key = f"sc_action_{case_id}_{i}"
            if widget_key not in st.session_state:
                st.session_state[widget_key] = saved.get(f"action_{i}", False)
            checked = st.checkbox(f"{owner} · {action}", key=widget_key, on_change=save_notebook, args=(case_id, f"action_{i}", widget_key))
            decisions.append(dict(owner=owner, recommendation=action, reviewed=checked))
        notes_key = f"sc_notes_{case_id}"
        if notes_key not in st.session_state:
            st.session_state[notes_key] = saved.get("notes", "")
        analyst_notes = st.text_area("Analyst reasoning / next evidence to collect", placeholder="What is observed? What remains a hypothesis? What evidence would change your decision?", key=notes_key, on_change=save_notebook, args=(case_id, "notes", notes_key))
        st.markdown("**Suggested handoff**")
        st.write(f'{case["name"]}: {len(visible)} revealed records from {len({e["source"] for e in visible})} sources. Response state: {status}.')
        for finding in deductions:
            st.write(f'{finding["title"]} — {finding["confidence"]} confidence; evidence: {", ".join(finding["evidence"])}.')
        if not deductions:
            st.write("No evidence-supported assessment at the current replay point. Collect the missing sources or reveal the next event before escalating a conclusion.")
        report = dict(workspace="Signal Context", synthetic=True, case=case["name"], replay_through=visible[-1]["time"], selected_sources=sources, correlation=dict(actor=case["actor"], session=case["session"], start=case["start"], end=case["end"]), events=visible, findings=deductions, response=dict(status=status, explanation=status_detail), recommendations=decisions, analyst_notes=analyst_notes, visibility_gap=case["blind_spot"], references=case["references"])
        st.download_button("Export evidence & analyst handoff", json.dumps(report, indent=2), f"signal-context-{case_id}-handoff.json", "application/json", key="sc_export")
