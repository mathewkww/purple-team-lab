"""Model Risk Studio — synthetic, evidence-led LLM misuse investigations."""
from __future__ import annotations

import json
from html import escape

import streamlit as st


OWASP_LINK = "https://genai.owasp.org/llmrisk/"
ATLAS_LINK = "https://atlas.mitre.org/"
NIST_LINK = "https://www.nist.gov/itl/ai-risk-management-framework"
OPENAI_LINK = "https://developers.openai.com/api/docs/guides/agents/guardrails-approvals"
ANTHROPIC_LINK = "https://www.anthropic.com/responsible-scaling-policy"

TAXONOMY = [
    ("LLM01", "Prompt injection", "Untrusted instructions alter an application's intended behavior.", "Prompt / context"),
    ("LLM02", "Sensitive information disclosure", "Outputs or connected context disclose secrets, personal data, or confidential content.", "Data & knowledge"),
    ("LLM03", "Supply chain", "Models, adapters, libraries, datasets, or providers introduce integrity risk.", "Model operations"),
    ("LLM04", "Data and model poisoning", "Training, fine-tuning, or retrieval inputs influence behavior or introduce backdoors.", "Data & knowledge"),
    ("LLM05", "Improper output handling", "An application treats generated text or structure as trusted execution input.", "Actions & outputs"),
    ("LLM06", "Excessive agency", "A model has tools, permissions, or autonomy beyond its justified task.", "Actions & outputs"),
    ("LLM07", "System prompt leakage", "Protected instructions or operational details appear in an output.", "Prompt / context"),
    ("LLM08", "Vector and embedding weaknesses", "Retrieval access, isolation, provenance, or embedding behavior weakens a knowledge boundary.", "Data & knowledge"),
    ("LLM09", "Misinformation", "An output is ungrounded, stale, manipulated, or overconfident for the decision context.", "Actions & outputs"),
    ("LLM10", "Unbounded consumption", "Requests, automation, or resource use lack meaningful ceilings or abuse controls.", "Model operations"),
]

CASES = {
    "retrieval": {
        "name": "Indirect retrieval injection", "status": "Needs containment review", "severity": "High",
        "question": "Did untrusted retrieved content influence a privileged agent action?",
        "pattern": "Public pattern: indirect instructions in documents or web content can be interpreted by an LLM when retrieved. This case is fictionalized; no attack prompt is included.",
        "mappings": "OWASP LLM01 / LLM06 / LLM08 · MITRE ATLAS prompt-injection techniques",
        "assets": "Employee benefits retrieval assistant", "boundary": "External document → retrieval index → model context → draft-action tool",
        "events": [
            ("09:00:00", "Retrieval", "Knowledge document indexed", "hr-benefits-2026.pdf", "Normal ingestion event. Provenance is external.", "observed"),
            ("09:02:00", "Model trace", "Untrusted-content marker raised", "retrieved_chunk=hr-benefits-2026.pdf#p14", "The classifier observed instruction-like text in retrieved context; it does not prove malicious intent.", "signal"),
            ("09:02:01", "Policy gate", "Tool proposal blocked", "tool=draft_email; recipient_scope=all-employees", "A tool guardrail rejected a request that exceeded the allowed recipient scope.", "blocked"),
            ("09:03:15", "Investigation", "Evidence preserved", "trace=run-104; document_hash=demo-c88", "Retain the retrieval snapshot, policy decision and authorization context for review.", "response"),
        ],
        "detections": [("Untrusted context attempted to influence an action", "High", "Trace spans an external document marker and an out-of-scope draft-email proposal.", "Cite retrieval provenance, classify instruction-like content, and compare proposed tool arguments to the approved task scope."), ("No outbound message evidence", "High", "The action was blocked before execution.", "Do not report data disclosure or a sent message without delivery/audit evidence.")],
        "responses": [("Immediate", "Disable the affected document from retrieval; preserve the trace and document hash."), ("Contain", "Keep tool approvals and recipient allow-lists enforced at the tool boundary."), ("Improve", "Separate untrusted content from instructions; add adversarial retrieval cases to evaluations."), ("Owner", "RAG owner + security engineering")],
        "gaps": "A block proves the policy decision, not that every possible retrieval path or downstream system was protected.",
        "reference": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    },
    "data": {
        "name": "Sensitive-context disclosure attempt", "status": "Investigate exposure", "severity": "High",
        "question": "Did an LLM response expose protected connected data or only echo a user-provided value?",
        "pattern": "Public pattern: sensitive-data risk sits in both the model and the connected application context. The trace is fictional and intentionally redacted.",
        "mappings": "OWASP LLM02 / LLM07 · NIST AI RMF GenAI risk management",
        "assets": "Support copilot with CRM retrieval", "boundary": "Customer request → scoped CRM retrieval → model output → support console",
        "events": [
            ("10:00:00", "Identity", "Support role authenticated", "role=support-tier-1", "Observed identity context is limited to support-tier-1.", "observed"),
            ("10:00:05", "Retrieval", "Cross-account result rejected", "account_scope=customer-41; record_scope=customer-87", "A deterministic scope check rejected a mismatched record before model context assembly.", "blocked"),
            ("10:00:06", "Output gate", "Sensitive-entity candidate redacted", "entity_type=account_identifier; source=unconfirmed", "A classifier flag triggered redaction and review. It is a candidate signal, not proof that sensitive data was displayed.", "signal"),
            ("10:03:00", "Case management", "Customer session reviewed", "delivery_audit=no-export-event", "The sample delivery audit has no export event; retain the limitation.", "response"),
        ],
        "detections": [("Cross-account retrieval prevented", "High", "The retrieval scope check logged customer-41 versus customer-87 and rejected the result.", "Log subject, object, retrieval filters, and the decision—without storing unnecessary prompt contents."), ("Disclosure unconfirmed", "Moderate", "An output signal exists, but the redaction event and absent export signal do not establish display or disclosure.", "Verify UI delivery and downstream audit logs; distinguish model-generated text from user-provided content.")],
        "responses": [("Immediate", "Preserve the decision trace and validate customer/object scoping rules."), ("Contain", "Keep least-privilege retrieval and output redaction enabled; pause the affected workflow if delivery evidence is uncertain."), ("Improve", "Add privacy-focused evals, data minimization checks, and retention limits for traces."), ("Owner", "Application owner + privacy/security")],
        "gaps": "The sample does not establish what a user saw, copied, or received outside the application.",
        "reference": "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
    },
    "agency": {
        "name": "Agent tool-scope escalation", "status": "Control effectiveness review", "severity": "Medium",
        "question": "Did a model attempt to cross a read-to-write boundary, and was a human approval required?",
        "pattern": "Public pattern: agents require controls at the action boundary. This fictional trace demonstrates a rejected change request, not an executed infrastructure action.",
        "mappings": "OWASP LLM05 / LLM06 · NIST Govern / Map / Measure / Manage",
        "assets": "Cloud operations assistant", "boundary": "Natural-language request → plan → change-management tool → human approval",
        "events": [
            ("11:00:00", "Agent plan", "Read-only inventory lookup", "tool=asset_search; mode=read", "A permitted read-only lookup completed.", "observed"),
            ("11:00:12", "Agent plan", "Write proposal generated", "tool=network_rule_change; target=production", "The model proposed a high-impact change. A proposal is not an action.", "signal"),
            ("11:00:13", "Approval gate", "Human approval required", "risk=high; reason=production-write", "The workflow paused before the side effect. No approval was supplied in this trace.", "blocked"),
            ("11:05:00", "Evaluation", "Policy scenario captured", "eval_case=write-boundary-04", "The trace can become a regression test for approval and tool-argument guardrails.", "response"),
        ],
        "detections": [("Read-to-write boundary reached", "High", "A production write proposal followed a read-only workflow and was routed to approval.", "Detect tool names, arguments, target environment, calling identity, approval state, and execution outcome."), ("No production change evidence", "High", "Approval was required and no execution event exists in the sample.", "Never infer an infrastructure change from planning text alone.")],
        "responses": [("Immediate", "Keep the request paused; verify the intended change against an approved engagement or change window."), ("Contain", "Fail closed on missing approval; restrict tool credentials by environment and action."), ("Improve", "Use tool-specific validation, reversible defaults, evaluation traces, and periodic red-team exercises."), ("Owner", "Platform engineering + change authority")],
        "gaps": "This trace does not prove whether alternate credentials or a different tool path could bypass the approval boundary.",
        "reference": "https://developers.openai.com/api/docs/guides/agents/guardrails-approvals",
    },
    "consumption": {
        "name": "Unbounded consumption and abuse signal", "status": "Rate-limit review", "severity": "Medium",
        "question": "Is elevated model use legitimate demand, automation abuse, or a control-capacity issue?",
        "pattern": "Public pattern: request volume, token use, and tool recursion require explicit ceilings. The counts below are synthetic, not billing or production data.",
        "mappings": "OWASP LLM10 · NIST Measure / Manage",
        "assets": "Research summarization assistant", "boundary": "User/API key → model gateway → token and concurrency budget",
        "events": [
            ("12:00:00", "Gateway", "Burst threshold exceeded", "api_key=demo-key-7; requests=48/min", "A configured per-key burst threshold was exceeded.", "signal"),
            ("12:00:04", "Runtime", "Tool-loop budget stopped", "agent_steps=8; max_steps=8", "The orchestrator halted a loop at its declared ceiling.", "blocked"),
            ("12:00:10", "Gateway", "Rate limit applied", "retry_after=60s", "The gateway reported limiting. This does not identify user intent.", "response"),
            ("12:15:00", "Investigation", "Usage context requested", "owner=research-ops", "Link usage, identity, workload, and budget signals before classifying abuse.", "observed"),
        ],
        "detections": [("Usage control triggered", "High", "Burst, loop budget, and rate-limit records agree on the same synthetic workload.", "Correlate request rate, token counts, tool depth, API key, tenant, retries, and downstream errors."), ("Abuse unconfirmed", "Low", "The evidence shows controls reacting, not a malicious actor or compromised key.", "Validate owner activity and credential history before suspension or attribution.")],
        "responses": [("Immediate", "Preserve gateway and orchestration traces; notify the workload owner."), ("Contain", "Apply per-tenant/key concurrency, token, spend, and tool-depth ceilings with safe retry behavior."), ("Improve", "Alert on budget anomalies, evaluate false positives, and rotate or constrain a key only after review."), ("Owner", "AI platform operations + service owner")],
        "gaps": "A rate-limit event alone cannot distinguish expected batch work, a defect, or malicious automation.",
        "reference": "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/",
    },
}


def visible_events(case_id: str, revealed: int):
    return CASES[case_id]["events"][:revealed]


def detection_status(events):
    states = [event[5] for event in events]
    if "blocked" in states:
        return "Preventive control observed", "A gate rejected or paused a proposed action. Validate coverage and alternate paths before declaring full containment."
    if "signal" in states:
        return "Detection signal only", "A classifier or threshold triggered. Preserve context and seek a policy decision or delivery/execution audit before escalation."
    return "Baseline evidence", "Only baseline activity is visible at this replay point. Absence of a signal is not evidence of safety."


def event_explanation(event):
    _, layer, action, detail, explanation, state = event
    labels = {"observed": "Observed event", "signal": "Detection signal", "blocked": "Preventive decision", "response": "Investigation action"}
    return labels[state], f"{action}: {explanation}", detail


def step_cursor(key, delta, upper):
    st.session_state[key] = max(1, min(upper, st.session_state.get(key, upper) + delta))


def render_model_risk_studio():
    st.markdown("""<style>
    .mr-hero{padding:23px 26px;border:1px solid #42506b;border-radius:14px;background:linear-gradient(115deg,#182238,#101a2a);margin:6px 0 21px}
    .mr-kicker{color:#75d9d0;font-size:11px;font-weight:750;letter-spacing:1.7px;text-transform:uppercase}.mr-hero h2{margin:7px 0!important;color:#f3f6fd!important;font-size:27px!important}.mr-hero p{color:#c4d0e1;margin:0;line-height:1.65}
    .mr-lane{position:relative;margin:0 0 0 9px;padding:0 0 22px 25px;border-left:2px solid #354863}.mr-lane:before{content:'';position:absolute;left:-6px;top:7px;width:10px;height:10px;border-radius:50%;background:#8e7bff;box-shadow:0 0 0 4px #101927}.mr-lane.signal:before{background:#f7be62}.mr-lane.blocked:before{background:#55d9bd}.mr-lane.response:before{background:#72a9ff}
    .mr-card{padding:14px 16px;background:#111c2c;border:1px solid #30435e;border-radius:10px}.mr-meta{font-size:11px;color:#afc2da;letter-spacing:.4px;margin-bottom:7px}.mr-title{color:#f0f4ff;font-weight:650;font-size:15px}.mr-copy{color:#c5d0e1;font-size:13px;line-height:1.6;margin-top:6px}.mr-detail{display:inline-block;margin-top:8px;padding:3px 7px;border:1px solid #405674;border-radius:5px;color:#c4d1e4;font:11px monospace;overflow-wrap:anywhere}.mr-callout{padding:14px 16px;border-left:3px solid #65d7c5;border-radius:0 8px 8px 0;background:#132237;color:#d7e2ef;line-height:1.6;margin-bottom:14px}
    </style><div class="mr-hero"><div class="mr-kicker">Model Risk Studio / LLM misuse investigations</div><h2>Translate model behavior into an accountable safety decision.</h2><p>Replay fictional traces across prompts, retrieval, tools, policies and delivery. Separate a model signal from an executed action, and turn findings into controls, evaluations and human review.</p></div>""", unsafe_allow_html=True)
    st.caption("TRAINING WORKSPACE · Synthetic traces only · No model calls, prompt execution, classifiers, customer data, live tools, or production controls")
    case_id = st.selectbox("Choose an LLM misuse investigation", list(CASES), format_func=lambda key: CASES[key]["name"], key="mr_case")
    case = CASES[case_id]
    st.markdown(f"### {case['question']}")
    st.write(case["pattern"])
    st.caption(f"Scope: {case['assets']} · Trust boundary: {case['boundary']}")

    with st.expander("LLM risk landscape · OWASP LLM Top 10 and adjacent operational concerns"):
        groups = {}
        for code, name, description, group in TAXONOMY:
            groups.setdefault(group, []).append((code, name, description))
        cols = st.columns(4)
        for col, (group, items) in zip(cols, groups.items()):
            with col:
                st.markdown(f"**{group}**")
                for code, name, description in items:
                    st.caption(f"{code} · {name}")
                    st.write(description)
        st.caption("Taxonomy is a planning aid. Applicability, severity, legal obligations, and control effectiveness require organization-specific review.")
        st.link_button("Open OWASP LLM Top 10", OWASP_LINK)

    cursor_key = f"mr_cursor_{case_id}"
    if cursor_key not in st.session_state or st.session_state[cursor_key] > len(case["events"]):
        st.session_state[cursor_key] = len(case["events"])
    left_control, right_control, slider_control = st.columns([1, 1, 4])
    left_control.button("← Earlier", key="mr_prev", on_click=step_cursor, args=(cursor_key, -1, len(case["events"])), disabled=st.session_state[cursor_key] <= 1, use_container_width=True)
    right_control.button("Next signal →", key="mr_next", on_click=step_cursor, args=(cursor_key, 1, len(case["events"])), disabled=st.session_state[cursor_key] >= len(case["events"]), use_container_width=True)
    with slider_control:
        revealed = st.slider("Trace evidence revealed", 1, len(case["events"]), key=cursor_key)
    events = visible_events(case_id, revealed)
    control_state, control_detail = detection_status(events)
    st.caption(f"Replay through {events[-1][0]} UTC · {revealed} of {len(case['events'])} fictional trace records revealed · conclusions never use later events.")
    metrics = st.columns(4)
    metrics[0].metric("Trace records", len(events))
    metrics[1].metric("Policy decisions", sum(e[5] == "blocked" for e in events))
    metrics[2].metric("Detection signals", sum(e[5] == "signal" for e in events))
    metrics[3].metric("Control state", "Blocked" if "blocked" in [e[5] for e in events] else "Review")

    investigate, controls, governance = st.tabs(["Investigation trace", "Controls & detections", "Governance & assurance"])
    with investigate:
        timeline, panel = st.columns([1.35, 1], gap="large")
        with timeline:
            st.subheader("What the trace demonstrates")
            st.caption("Violet: observed system activity · Amber: detection signal · Teal: a preventive gate · Blue: investigation or improvement. Model plans are not external actions.")
            for event in events:
                label, summary, detail = event_explanation(event)
                state = event[5]
                st.markdown(f'<div class="mr-lane {escape(state)}"><div class="mr-card"><div class="mr-meta">{escape(event[0])} UTC / {escape(label)} / {escape(event[1])}</div><div class="mr-title">{escape(event[2])}</div><div class="mr-copy">{escape(summary)}</div><span class="mr-detail">{escape(detail)}</span></div></div>', unsafe_allow_html=True)
        with panel:
            st.subheader("Investigation decision panel")
            st.markdown(f'<div class="mr-callout"><strong>{escape(case["status"])}</strong><br>{escape(control_detail)}</div>', unsafe_allow_html=True)
            st.markdown("**Relevant threat model**")
            st.write(case["mappings"])
            st.markdown("**Evidence boundary**")
            st.write("This workspace reports only what its synthetic trace supports. It does not attribute a person, prove malicious intent, infer a delivered output, or claim a model was compromised.")
            st.markdown("**Known gap**")
            st.write(case["gaps"])
            st.link_button("Read the mapped public guidance", case["reference"])
            with st.expander("Analyst question"):
                st.write("What additional record would change the conclusion? Consider tool execution/audit logs, delivery state, retrieval provenance, identity scope, approval outcome, policy version, and evaluation result.")

    with controls:
        st.subheader("Detection engineering and response")
        st.caption("These are design patterns, not security guarantees. Combine deterministic policy checks, human review, monitoring and adversarial evaluations.")
        for title, confidence, evidence, method in case["detections"]:
            with st.container(border=True):
                st.markdown(f"**{title}**")
                st.caption(f"Evidence confidence: {confidence}")
                st.write(evidence)
                st.markdown("**Detection data to retain**")
                st.write(method)
        st.markdown("### Suggested response plan")
        for phase, action in case["responses"]:
            st.markdown(f"<div class='mr-card'><div class='mr-meta'>{escape(phase.upper())}</div><div class='mr-copy'>{escape(action)}</div></div>", unsafe_allow_html=True)
        st.markdown("### Defense-in-depth control map")
        st.write("1. Classify and label untrusted input/retrieval.  2. Constrain context and validate structured outputs.  3. Enforce least privilege, explicit tool schemas and tool-level policy checks.  4. Require human approval for consequential actions.  5. Retain minimal, protected traces for detection, audit, incident response and evaluation.")
        st.caption("This mirrors public guidance such as layered guardrails, action-boundary approvals, real-time and asynchronous monitoring, red-team/evaluation feedback loops, access controls, and centralized investigation records. It is not a claim about any vendor's proprietary implementation.")
        links = st.columns(3)
        links[0].link_button("OpenAI: guardrails & approvals", OPENAI_LINK)
        links[1].link_button("Anthropic: layered safeguards", ANTHROPIC_LINK)
        links[2].link_button("MITRE ATLAS", ATLAS_LINK)

    with governance:
        st.subheader("Assurance loop")
        st.write("Use NIST AI RMF functions as a practical review cycle: **Govern** ownership, policy and escalation; **Map** assets, users, data, tools and impact; **Measure** evaluations, telemetry and control effectiveness; **Manage** treatment, monitoring, incident response and change control.")
        st.link_button("NIST AI RMF and Generative AI Profile", NIST_LINK)
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Pre-deployment evidence**")
            st.write("Documented use case and boundaries; data-flow and tool inventory; threat model; adversarial test suite; access model; privacy/retention decision; stop/launch criteria; named accountable owner.")
        with c2:
            st.markdown("**Operational evidence**")
            st.write("Versioned policies and prompts; tool approval/execution audit; retrieval provenance; redacted traces; detection coverage; eval drift/incident trends; exception records; tabletop and red-team findings.")
        notes_key = f"mr_notes_{case_id}"
        notes = st.text_area("Analyst notes / evidence request", placeholder="Record the supported conclusion, unknowns, owner and next evidence to obtain. Do not enter live prompts, secrets, personal data or incident details.", key=notes_key)
        report = {"workspace": "Model Risk Studio", "synthetic": True, "case": case["name"], "replay_through": events[-1][0], "trace": [{"time": e[0], "layer": e[1], "action": e[2], "detail": e[3], "interpretation": e[4], "state": e[5]} for e in events], "control_state": control_state, "control_explanation": control_detail, "detections": case["detections"], "responses": case["responses"], "gap": case["gaps"], "analyst_notes": notes, "references": {"OWASP LLM Top 10": OWASP_LINK, "MITRE ATLAS": ATLAS_LINK, "NIST AI RMF": NIST_LINK, "OpenAI guardrails guidance": OPENAI_LINK, "Anthropic Responsible Scaling Policy": ANTHROPIC_LINK}}
        st.download_button("Export LLM misuse investigation handoff", json.dumps(report, indent=2), f"model-risk-{case_id}-handoff.json", "application/json", key="mr_export")
