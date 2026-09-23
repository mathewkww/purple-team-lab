"""Fictional training fixtures and a small, reproducible SQLite evidence database.

Vendor names describe illustrative source formats, not installed connectors.
Only the fields used by this lesson are represented; these are not full schemas.
"""
import json
import sqlite3

CASES = {
    "cloud": {
        "name": "Cloud identity → storage collection", "actor": "riley@example.test", "session": "cloud-s42",
        "start": "2026-09-23T09:00:00Z", "end": "2026-09-23T09:30:00Z",
        "service": "Finance export service", "boundary": "Federated identity → AWS role → S3 data",
        "question": "Does unusual authentication become a credible data-access incident?",
        "lesson": "Join identity and cloud events by the documented federation session. An alert is a pointer to evidence; a queued response is not containment.",
        "join_note": "The training fixture carries cloud-s42 in the identity session and federation source identity. A real deployment must establish and validate that mapping.",
        "sources": ["Entra ID", "AWS CloudTrail", "Splunk ES", "Splunk SOAR"],
        "references": {"ATT&CK T1078.004 · Cloud Accounts": "https://attack.mitre.org/techniques/T1078/004/", "ATT&CK T1530 · Data from Cloud Storage": "https://attack.mitre.org/techniques/T1530/"},
        "actions": [("Identity owner", "Verify the session with the account owner and revoke suspect sessions if unauthorized."), ("Cloud response", "Scope role permissions and object reads; preserve federation and S3 data events."), ("Data owner", "Review data sensitivity and determine whether access constituted a breach.")],
        "blind_spot": "CloudTrail data events must be enabled for the relevant storage. Object reads do not establish onward exfiltration or the human behind the session.",
    },
    "api": {
        "name": "API access → cross-tenant disclosure", "actor": "customer-17", "session": "api-s17",
        "start": "2026-09-23T10:00:00Z", "end": "2026-09-23T10:30:00Z",
        "service": "Customer invoice API", "boundary": "Customer identity → authorization check → tenant-owned object",
        "question": "Is an API anomaly just volume, or is an authorization boundary failing?",
        "lesson": "Combine application ownership decisions with cloud access outcomes. HTTP 200 alone does not prove a cross-tenant disclosure.",
        "join_note": "API session api-s17 and request ID req-17 link application authorization logs with Cloud Logging. SIEM and SOAR reference the same evidence IDs.",
        "sources": ["API audit", "GCP Cloud Logging", "Microsoft Sentinel", "Logic Apps SOAR"],
        "references": {"OWASP API1:2023 · Object Level Authorization": "https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/", "OWASP A01:2025 · Broken Access Control": "https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/"},
        "actions": [("API owner", "Enforce server-side tenant and object ownership checks; add cross-tenant regression tests."), ("SOC", "Scope successful object access by this session and preserve request IDs."), ("Response lead", "Consider a temporary endpoint restriction; rate limits alone do not repair authorization.")],
        "blind_spot": "Object-owner and authorization-decision logs are required. Gateway status codes cannot establish which tenant owned the returned object.",
    },
    "admin": {
        "name": "Admin change → false-positive investigation", "actor": "avery@example.test", "session": "admin-s8",
        "start": "2026-09-23T11:00:00Z", "end": "2026-09-23T11:30:00Z",
        "service": "Azure diagnostic configuration", "boundary": "Privileged operator → subscription monitoring configuration",
        "question": "Does a monitoring change indicate evasion or authorized maintenance?",
        "lesson": "Use change authorization and subsequent control state to challenge an evasion hypothesis. Avoid attributing every alert to a threat actor.",
        "join_note": "Operator, admin-s8, resource, and CHG-204 agree across identity, Azure Activity, and the SOAR change lookup. An IP-only neighbor is deliberately excluded.",
        "sources": ["Entra ID", "Azure Activity", "Microsoft Sentinel", "Logic Apps SOAR"],
        "references": {"OWASP A09:2025 · Logging & Alerting": "https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/"},
        "actions": [("Change owner", "Confirm the approved actor, resource, and maintenance window against the ticket."), ("Cloud monitoring", "Verify log delivery after the change and document any collection gap."), ("Detection engineer", "Tune narrowly using change context; retain alerts for unapproved changes.")],
        "blind_spot": "A successful configuration update is not proof that all log delivery continued. This fixture includes a later delivery check, but not a complete ingestion history.",
    },
}


def fixture(source, event_id, minute, actor, session, asset, action, outcome, details=None, origin=None, ip="198.51.100.24", hour="09"):
    """Represent an event using one of four deliberately minimal source shapes."""
    timestamp = f"2026-09-23T{hour}:{minute:02}:00Z"
    common = dict(actor=actor, session=session, asset=asset, action=action, outcome=outcome, ip=ip, details=details or {})
    if source in ("Splunk ES", "Microsoft Sentinel"):
        raw = {"TimeGenerated": timestamp, "SystemAlertId": event_id, "Entities": common, "EvidenceEventIds": common["details"].get("evidence_ids", [])}
        kind = "SIEM alert"
    elif source in ("Splunk SOAR", "Logic Apps SOAR"):
        raw = {"created_time": timestamp, "action_run_id": event_id, "status": outcome, "context": common}
        kind = "SOAR response"
    elif source == "AWS CloudTrail":
        raw = {"eventTime": timestamp, "eventID": event_id, "eventName": action, "userIdentity": {"principalId": actor, "sourceIdentity": session}, "sourceIPAddress": ip, "resources": [asset], "responseElements": {"result": outcome}, "trainingContext": details or {}}
        kind = "Cloud audit"
    else:
        raw = {"timestamp": timestamp, "insertId": event_id, "jsonPayload": common}
        kind = "Application audit" if source == "API audit" else "Identity" if source == "Entra ID" else "Cloud audit"
    return dict(source=source, kind=kind, raw=raw, origin=origin or event_id)


def sample_records():
    c = CASES["cloud"]
    def cloud(src, eid, minute, action, outcome, details=None, **kw):
        return fixture(src, eid, minute, c["actor"], c["session"], "finance-exports", action, outcome, details, **kw)
    a = CASES["api"]
    def api(src, eid, minute, action, outcome, details=None, **kw):
        return fixture(src, eid, minute, a["actor"], a["session"], "invoice-api", action, outcome, details, hour="10", **kw)
    d = CASES["admin"]
    def admin(src, eid, minute, action, outcome, details=None, **kw):
        return fixture(src, eid, minute, d["actor"], d["session"], "azure-prod-monitoring", action, outcome, details, hour="11", **kw)
    return [
        cloud("Entra ID", "C01", 0, "SignIn", "success", {"new_device": True, "mfa": "satisfied", "federation_session": "cloud-s42"}),
        cloud("AWS CloudTrail", "C02", 2, "AssumeRole", "success", {"role": "finance-reader"}),
        cloud("AWS CloudTrail", "C03", 4, "ListObjects", "success", {"objects_listed": 42}),
        cloud("AWS CloudTrail", "C04", 6, "GetObject", "success", {"object": "quarterly-demo.csv", "bytes": 8192}),
        cloud("AWS CloudTrail", "C04-copy", 6, "GetObject", "success", {"object": "quarterly-demo.csv", "bytes": 8192}, origin="C04"),
        cloud("Splunk ES", "C05", 7, "UnusualCloudRead", "alert", {"evidence_ids": ["C01", "C04"], "severity": "high"}),
        cloud("Splunk SOAR", "C06", 8, "RevokeSession", "queued", {"evidence_ids": ["C05"]}),
        cloud("AWS CloudTrail", "C07", 9, "GetObject", "success", {"object": "forecast-demo.csv", "bytes": 4096}),
        cloud("Splunk SOAR", "C08", 10, "RevokeSession", "success", {"evidence_ids": ["C05"], "scope": "cloud-s42"}),
        cloud("AWS CloudTrail", "C09", 11, "GetObject", "denied", {"error": "AccessDenied"}),
        fixture("AWS CloudTrail", "N01", 5, "backup@example.test", "backup-s2", "finance-exports", "GetObject", "success", {"scheduled": True}),
        api("GCP Cloud Logging", "A01", 0, "ApiRequest", "success", {"request_id": "req-16", "status": 200, "route": "/invoices/:id"}),
        api("API audit", "A02", 2, "AuthorizationDecision", "allow", {"request_id": "req-17", "subject_tenant": "tenant-a", "object_tenant": "tenant-b", "object_check": "missing"}),
        api("GCP Cloud Logging", "A03", 3, "ApiRequest", "success", {"request_id": "req-17", "status": 200, "returned_object": True, "bytes": 2048}),
        api("Microsoft Sentinel", "A04", 4, "CrossTenantAccess", "alert", {"evidence_ids": ["A02", "A03"], "severity": "high"}),
        api("Logic Apps SOAR", "A05", 5, "RestrictEndpoint", "queued", {"evidence_ids": ["A04"]}),
        api("Logic Apps SOAR", "A06", 7, "RestrictEndpoint", "success", {"evidence_ids": ["A04"]}),
        api("GCP Cloud Logging", "A07", 8, "ApiRequest", "denied", {"request_id": "req-18", "status": 403}),
        fixture("GCP Cloud Logging", "N02", 3, "customer-18", "api-s18", "invoice-api", "ApiRequest", "success", {"status": 200}, hour="10"),
        admin("Entra ID", "D01", 0, "SignIn", "success", {"new_device": False, "mfa": "satisfied"}),
        admin("Azure Activity", "D02", 2, "DiagnosticSettingsWrite", "success", {"change_id": "CHG-204", "destination": "approved-log-workspace"}),
        admin("Microsoft Sentinel", "D03", 3, "MonitoringConfigChanged", "alert", {"evidence_ids": ["D02"], "severity": "medium"}),
        admin("Logic Apps SOAR", "D04", 5, "ChangeTicketLookup", "success", {"change_id": "CHG-204", "approved": True, "actor_match": True, "resource_match": True, "within_window": True}),
        admin("Azure Activity", "D05", 7, "LogDeliveryCheck", "success", {"received_test_event": True}),
        admin("Logic Apps SOAR", "D06", 9, "CaseDisposition", "reviewed", {"disposition": "authorized change", "evidence_ids": ["D04", "D05"]}),
        fixture("Azure Activity", "N03", 3, "other-admin@example.test", "admin-other", "azure-prod-monitoring", "DiagnosticSettingsWrite", "success", {"change_id": "CHG-999"}, hour="11"),
    ]


def normalize(record):
    raw, source = record["raw"], record["source"]
    if record["kind"] == "SIEM alert":
        ts, eid, common = raw["TimeGenerated"], raw["SystemAlertId"], raw["Entities"]
    elif record["kind"] == "SOAR response":
        ts, eid, common = raw["created_time"], raw["action_run_id"], raw["context"]
    elif source == "AWS CloudTrail":
        ts, eid = raw["eventTime"], raw["eventID"]
        common = dict(actor=raw["userIdentity"]["principalId"], session=raw["userIdentity"]["sourceIdentity"], asset=raw["resources"][0], action=raw["eventName"], outcome=raw["responseElements"]["result"], ip=raw["sourceIPAddress"], details=raw["trainingContext"])
    else:
        ts, eid, common = raw["timestamp"], raw["insertId"], raw["jsonPayload"]
    return dict(id=eid, time=ts, source=source, kind=record["kind"], origin=record["origin"], **common, raw=raw)


def database():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE events (id TEXT PRIMARY KEY, time TEXT, source TEXT, kind TEXT, origin TEXT, actor TEXT, session TEXT, asset TEXT, action TEXT, outcome TEXT, ip TEXT, details TEXT, raw TEXT)")
    for record in sample_records():
        row = normalize(record)
        row["details"], row["raw"] = json.dumps(row["details"]), json.dumps(row["raw"])
        conn.execute("INSERT INTO events VALUES (:id,:time,:source,:kind,:origin,:actor,:session,:asset,:action,:outcome,:ip,:details,:raw)", row)
    conn.commit()
    return conn


def correlate(conn, case_id, sources=None):
    """Exact actor+session and bounded event time; never group on IP alone."""
    case = CASES[case_id]
    rows = conn.execute("SELECT * FROM events WHERE actor=? AND session=? AND time BETWEEN ? AND ? ORDER BY time,id", (case["actor"], case["session"], case["start"], case["end"])).fetchall()
    unique, seen, duplicates = [], set(), 0
    for row in rows:
        event = dict(row)
        if sources is not None and event["source"] not in sources:
            continue
        key = (event["source"], event["origin"])
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        event["details"], event["raw"] = json.loads(event["details"]), json.loads(event["raw"])
        unique.append(event)
    return unique, duplicates


def findings(events):
    """Deterministic teaching rules. Evidence IDs are the complete rule support."""
    results = []
    def add(title, confidence, evidence, mapping, explanation, alternative):
        results.append(dict(title=title, confidence=confidence, evidence=[e["id"] for e in evidence], mapping=mapping, explanation=explanation, alternative=alternative))
    signins = [e for e in events if e["action"] == "SignIn" and e["details"].get("new_device") and e["outcome"] == "success"]
    reads = [e for e in events if e["action"] == "GetObject" and e["outcome"] == "success"]
    if signins:
        evidence = [signins[0]] + [e for e in reads if e["time"] > signins[0]["time"]]
        add("Unusual cloud session" if len(evidence) == 1 else "Unusual session followed by storage reads", "Low" if len(evidence) == 1 else "Moderate", evidence, "T1078.004 / T1530" if len(evidence) > 1 else "T1078.004 (candidate)", "New-device authentication is observed." if len(evidence) == 1 else "The same mapped principal and session successfully read storage after the unusual sign-in. This supports a collection hypothesis; compromise and onward exfiltration remain unproven.", "A new approved workstation or legitimate export could explain this sequence. Verify with the account and data owners.")
    auth = [e for e in events if e["action"] == "AuthorizationDecision" and e["details"].get("object_check") == "missing" and e["details"].get("subject_tenant") != e["details"].get("object_tenant")]
    for event in auth:
        matched = [e for e in events if e["action"] == "ApiRequest" and e["details"].get("request_id") == event["details"].get("request_id") and e["time"] >= event["time"] and e["outcome"] == "success" and e["details"].get("returned_object")]
        if matched:
            add("Cross-tenant object access supported", "High", [event, matched[0]], "OWASP API1:2023 / A01:2025", "Ownership mismatch, missing object authorization, and a successful object response share one request ID. The access-control failure is supported; actor intent is still a hypothesis.", "An intentional delegation model would change the interpretation. Check whether any explicit cross-tenant grant exists.")
    changes = [e for e in events if e["action"] == "DiagnosticSettingsWrite"]
    tickets = [e for e in events if e["action"] == "ChangeTicketLookup" and all(e["details"].get(k) for k in ("approved", "actor_match", "resource_match", "within_window"))]
    for change in changes:
        ticket = next((e for e in tickets if e["details"].get("change_id") == change["details"].get("change_id") and e["time"] >= change["time"]), None)
        add("Authorized maintenance supported" if ticket else "Monitoring configuration changed", "High" if ticket else "Low", [change, ticket] if ticket else [change], "OWASP A09:2025 (control review)", "Change authorization matches actor, resource, ticket and window. This weakens the evasion hypothesis." if ticket else "A configuration write is observed. Its effect on logging and its authorization are not yet established.", "Even an approved change can accidentally interrupt telemetry. Verify log delivery separately.")
    return results


def response_status(events):
    actions = [e for e in events if e["kind"] == "SOAR response" and e["action"] in ("RevokeSession", "RestrictEndpoint")]
    completed = [e for e in actions if e["outcome"] == "success"]
    if completed:
        action = completed[-1]
        denied = [e for e in events if e["kind"] in ("Cloud audit", "Application audit") and e["outcome"] == "denied" and e["time"] > action["time"]]
        if denied:
            return "Denial observed", f'{action["id"]} reports success; {denied[0]["id"]} records a later denial for this session. Other sessions and resources are not validated.'
        return "Action reported complete", f'{action["id"]} reports success. A subsequent enforcement check has not been observed.'
    if actions:
        return "Action queued", "The playbook has queued a response. Access may still be possible until enforcement is confirmed."
    return "No containment evidence", "No containment action is present in the visible evidence."
