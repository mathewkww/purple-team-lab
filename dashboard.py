"""Analyst-facing threat review workspace. All review state is session-local."""

from html import escape
from urllib.parse import urlsplit
import re
import streamlit as st


def card(eyebrow, title, body, tone=""):
    st.markdown(
        f'<div class="desk-card {tone}"><div class="desk-label">{escape(str(eyebrow))}</div>'
        f'<div class="desk-value">{escape(str(title))}</div><div class="desk-copy">{escape(str(body))}</div></div>',
        unsafe_allow_html=True,
    )

def reference_links(notes):
    """Allow only HTTPS references supplied by the advisory feed."""
    links = re.findall(r'https://[^\s<>"\']+', notes or "")
    return list(dict.fromkeys(url.rstrip(".;,)") for url in links if urlsplit(url).hostname))[:6]


def render_dashboard(latest_snapshot, fetch_feed, simulate, scenarios, render_pipeline):
    st.session_state.setdefault("threat_reviews", {})
    st.markdown('<div class="desk-eyebrow">INTELLIGENCE → DECISIONS → READINESS</div>', unsafe_allow_html=True)
    st.title("Your threat readiness desk")
    st.markdown("Find what matters to your environment. Turn each advisory into a preparation plan and a defensive rehearsal.")
    st.caption("PUBLIC INTELLIGENCE · SESSION WORKSPACE · SYNTHETIC REHEARSALS")

    try:
        advisories = latest_snapshot()
        available = bool(advisories)
    except Exception:
        advisories, available = [], False

    if "desk_notice" in st.session_state:
        st.success(st.session_state.pop("desk_notice"))
    reviews = st.session_state.threat_reviews
    in_scope = sum(reviews.get(a["cve"], {}).get("exposure") == "Potentially affected" for a in advisories)
    unreviewed = sum(reviews.get(a["cve"], {}).get("exposure", "Needs assessment") == "Needs assessment" for a in advisories)
    a, b, c, d = st.columns(4)
    with a: card("LATEST KEV ENTRIES", len(advisories) if available else "Unavailable", "Known exploitation · ordered by catalog addition", "violet")
    with b: card("NEEDS ASSESSMENT", unreviewed if available else "—", "Match affected versions to your inventory")
    with c: card("POTENTIALLY AFFECTED", in_scope if available else "—", "Your assessments in this session", "amber")
    with d: card("REHEARSALS COMPLETED", len(st.session_state.runs), f"{len(st.session_state.events)} synthetic events · 3 template behaviors", "teal")

    st.markdown('<div class="desk-guide"><b>Start here</b><span>01 Select a threat</span><span>02 Assess & prepare</span><span>03 Rehearse a response</span></div>', unsafe_allow_html=True)
    toolbar, refresh = st.columns([4, 1])
    with toolbar:
        st.caption("SOURCE: CISA Known Exploited Vulnerabilities · cached up to 1 hour · catalog additions are not necessarily new disclosures or zero-days.")
    with refresh:
        if st.button("Refresh intelligence", use_container_width=True):
            fetch_feed.clear()
            st.rerun()

    if available:
        queue, detail = st.columns([1, 1.7], gap="large")
        with queue:
            st.subheader("Threat queue")
            query = st.text_input("Find a CVE or product", placeholder="Search CVE, vendor, product…")
            only_unreviewed = st.checkbox("Needs assessment only")
            visible = [a for a in advisories if query.casefold() in f'{a["cve"]} {a["product"]} {a["title"]}'.casefold()
                       and (not only_unreviewed or reviews.get(a["cve"], {}).get("exposure", "Needs assessment") == "Needs assessment")]
            st.caption(f"{len(visible)} of {len(advisories)} records · newest additions first")
            if visible:
                visible_ids = {a["cve"] for a in visible}
                if st.session_state.get("desk_selected") not in visible_ids:
                    st.session_state.desk_selected = visible[0]["cve"]
                with st.container(height=620, border=False):
                    for item in visible:
                        selected = item["cve"] == st.session_state.desk_selected
                        if st.button(f'{item["cve"]} · {item["product"]}', key=f'pick-{item["cve"]}', type="primary" if selected else "secondary", use_container_width=True):
                            st.session_state.desk_selected = item["cve"]
                            st.rerun()
                        status = reviews.get(item["cve"], {}).get("exposure", "Needs assessment")
                        st.caption(f'Added {item["added"]} · {status}')
            else:
                st.info("No threats match these filters. Clear the search or assessment filter to see the queue.")

        with detail:
            if visible:
                item = next(a for a in visible if a["cve"] == st.session_state.desk_selected)
                cve = item["cve"]
                st.markdown(f'<div class="desk-eyebrow">ANALYST BRIEF / {escape(cve)}</div>', unsafe_allow_html=True)
                st.subheader(item["title"])
                assessment = reviews.get(cve, {}).get("exposure", "Needs assessment")
                st.markdown(f'<span class="desk-badge">KNOWN EXPLOITATION</span> <span class="desk-badge neutral">{escape(assessment.upper())}</span>', unsafe_allow_html=True)
                st.caption(f'{item["product"]} · Added to KEV {item["added"]}')
                brief, prepare, rehearse = st.tabs(["Understand", "Assess & prepare", "Rehearse"])
                with brief:
                    st.markdown("#### What is happening")
                    st.write(item.get("description") or "A description was not supplied by the catalog. Open the source record for technical scope.")
                    st.markdown("#### Why review this now")
                    st.write("CISA lists this vulnerability as exploited in the wild. Check affected versions and access prerequisites, then prioritize any matching assets by internet exposure and business impact.")
                    card("YOUR ENVIRONMENT", reviews.get(cve, {}).get("exposure", "Needs assessment"), "No asset inventory is connected. Record your assessment in the next tab.")
                    st.markdown("#### Source evidence")
                    st.link_button("Open CISA catalog record ↗", f'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}')
                    for index, url in enumerate(reference_links(item.get("notes", ""))):
                        st.link_button(f'Reference {index + 1} · {urlsplit(url).hostname} ↗', url)
                    st.caption(f'CISA-listed ransomware use: {item.get("ransomware", "Unknown")} · Federal remediation due date: {item.get("due", "Not supplied")}. This is not your organization’s SLA.')
                with prepare:
                    st.markdown("#### Recommended action from CISA")
                    st.write(item["patch"])
                    st.caption("Confirm exact affected versions and fixed releases in the publisher’s references before scheduling a change.")
                    review = reviews.get(cve, {})
                    with st.form(f'assess-{cve}'):
                        options = ["Needs assessment", "Potentially affected", "Not applicable", "Mitigated — pending verification", "Verified resolved"]
                        exposure = st.selectbox("Your assessment", options, index=options.index(review.get("exposure", options[0])))
                        inventory = st.checkbox("Checked affected versions and exposure against inventory", value=review.get("inventory", False))
                        change = st.checkbox("Identified a patch or mitigation and rollback plan", value=review.get("change", False))
                        telemetry = st.checkbox("Identified relevant logs and investigation owner", value=review.get("telemetry", False))
                        evidence = st.text_area("Assessment notes / evidence", value=review.get("evidence", ""), placeholder="Affected version, asset scope, source reference, next step…")
                        if st.form_submit_button("Save assessment", type="primary"):
                            reviews[cve] = dict(exposure=exposure, inventory=inventory, change=change, telemetry=telemetry, evidence=evidence)
                            st.session_state.desk_notice = f"Assessment saved for {cve}. Export the brief to retain it beyond this session."
                            st.rerun()
                    st.caption("Assessments and runs belong to this browser session; export before leaving. No patches are applied from this app.")
                with rehearse:
                    st.markdown("#### Choose a behavior to exercise")
                    st.write("Select a template relevant to your investigation. The rehearsal generates example telemetry and response steps; it does not reproduce this CVE or test your deployed controls.")
                    scenario_name = st.selectbox("Rehearsal template", list(scenarios), key=f'template-{cve}')
                    template = scenarios[scenario_name]
                    st.caption(template["technique"])
                    for _, source, text, _ in template["signals"]:
                        st.markdown(f"**{source}** · {text}")
                    if st.button("Run selected rehearsal", type="primary", key=f'rehearse-{cve}', use_container_width=True):
                        simulate(scenario_name, f'{cve} · {item["title"]}')
                        st.session_state.desk_notice = f"Rehearsal complete: {scenario_name}. Added 3 synthetic events. Review the evidence below."
                        st.rerun()
                review = reviews.get(cve, {})
                report = f'# {cve}: {item["title"]}\n\nProduct: {item["product"]}\nKEV added: {item["added"]}\nAssessment: {review.get("exposure", "Needs assessment")}\n\n## Advisory description\n{item.get("description", "Not supplied")}\n\n## CISA action\n{item["patch"]}\n\n## Analyst evidence\n{review.get("evidence") or "No notes recorded."}\n\n## Preparation checklist\n' + '\n'.join(f'- [{"x" if review.get(key) else " "}] {label}' for key, label in [("inventory", "Inventory and exposure reviewed"), ("change", "Mitigation and rollback planned"), ("telemetry", "Logs and investigation owner identified")]) + f'\n\nSource: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}\n\nRehearsals are synthetic template exercises, not validation of this CVE.\n'
                st.download_button("Export analyst brief ↓", report, file_name=f'{cve}-readiness.md', mime="text/markdown", use_container_width=True)
    else:
        st.warning("The CISA feed is unavailable. Refresh intelligence to retry. Your rehearsal evidence remains available below.")

    st.divider()
    st.markdown('<div class="desk-eyebrow">EVIDENCE & NEXT STEPS</div>', unsafe_allow_html=True)
    st.subheader("What have we exercised?")
    st.caption("Six baseline runs exercise three templates on session startup. Additional runs appear here immediately. Production detection effectiveness is unmeasured.")
    cols = st.columns(3)
    for col, (name, scenario) in zip(cols, scenarios.items()):
        matching = [r for r in st.session_state.runs if r["scenario"] == name]
        with col:
            card(scenario["technique"].split(" — ")[0], name, f'{len(matching)} runs · {sum(r["signals"] for r in matching)} synthetic events', "violet")
            with st.expander("Inspect signals & response"):
                st.markdown("**Evidence to look for**")
                for _, source, text, _ in scenario["signals"]:
                    st.write(f"{source}: {text}")
                st.markdown("**If compromise is confirmed**")
                for action in scenario["response"]:
                    st.markdown(f"- {action}")
    if st.session_state.runs:
        recent = st.session_state.runs[0]
        st.caption(f'LATEST RUN · {recent["id"]} · {recent["time"].strftime("%H:%M:%S UTC")} · {recent["advisory"]}')
    with st.expander("Explore the purple-team workflow"):
        st.caption("Animated workflow illustration; counters reflect this session’s records and synthetic runs.")
        render_pipeline(len(st.session_state.advisories), len(st.session_state.runs), len(st.session_state.events))
    st.markdown('<div class="desk-footer"><b>Bring your own intelligence</b><span>Use Threat Intake for analyst findings. Simulation Lab lets you choose a behavior. Recent Simulations holds the session’s run history.</span></div>', unsafe_allow_html=True)
