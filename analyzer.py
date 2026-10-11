import argparse
import hashlib
import ipaddress
import json


from collections import Counter, defaultdict, deque

from datetime import datetime, timedelta

from pathlib import Path

from ai_analyst import analyze_with_ai

from ml_detector import analyze_failed_logins

from report_generator import generate_incident_report
from attack_classifier import classify_incident
from trello_integration import post_incident

from baseline_manager import (    get_password_history,
    get_mfa_history,
    password_baseline_ready,
    mfa_baseline_ready,
    password_baseline_summary,
    mfa_baseline_summary,
)

ROOT = Path(__file__).resolve().parent

LOG_FILE = ROOT / "sample_logs" / "auth.log"

STATE_FILE = ROOT / "data" / "last_report_fingerprint.json"

WINDOW = timedelta(minutes=5)

MFA_SESSION_TIMEOUT = timedelta(minutes=5)

PASSWORD_THRESHOLD = 5

MFA_THRESHOLD = 3

MIN_BASELINE_SAMPLES = 10

PASSWORD_FAILURES = {"FAILED_LOGIN", "PASSWORD_FAILURE"}

PASSWORD_SUCCESSES = {"SUCCESS_LOGIN", "PASSWORD_SUCCESS"}

EVENT_TYPES = PASSWORD_FAILURES | PASSWORD_SUCCESSES | {

    "MFA_FAILURE", "MFA_SUCCESS", "PASSWORD_LOCKOUT", "MFA_LOCKOUT"

}

def parse_events(path: Path):

    # Reject malformed entries before they reach the detection rules.

    events = []

    invalid = 0

    if not path.is_file():

        print(f"[ERROR] Missing log file: {path}")

        return events, invalid

    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):

        parts = raw.split()

        if len(parts) < 5 or parts[2] not in EVENT_TYPES:

            invalid += 1

            continue

        try:

            timestamp = datetime.strptime(" ".join(parts[:2]), "%Y-%m-%d %H:%M:%S")

            fields = dict(part.split("=", 1) for part in parts[3:] if "=" in part)

            username = fields["user"]

            source_ip = str(ipaddress.ip_address(fields["ip"]))

            if not username:

                raise ValueError("empty username")

        except (ValueError, KeyError):

            invalid += 1

            continue

        events.append({

            "timestamp": timestamp,

            "event": parts[2],

            "username": username,

            "source_ip": source_ip,

            "line": line_number,

        })

    events.sort(key=lambda e: (e["timestamp"], e["line"]))

    return events, invalid

def alert(kind, event, failures, severity, risk, **details):

    result = {

        "type": kind,

        "source_ip": event["source_ip"],

        "username": event["username"],

        "failed_attempts": failures,

        "severity": severity,

        "risk_score": risk,

        "timestamp": event["timestamp"].isoformat(),

    }

    result.update(details)

    return result

def detect_password_threats(events):
    # Prefer the final outcome of a password attempt over duplicate alerts.
    sessions = {}
    threats = []

    def finish(key):
        state = sessions.pop(key, None)
        if not state or state["failures"] < PASSWORD_THRESHOLD:
            return
        event = state["last"]
        outcome = state["outcome"]
        if outcome == "PASSWORD_LOCKOUT":
            kind, severity, risk = "Password Authentication Lockout", "HIGH", 80
            extra = {"protection_status": "LOCKOUT ACTIVATED"}
        elif outcome in PASSWORD_SUCCESSES:
            kind, severity, risk = "Password Accepted After Repeated Failures", "HIGH", 85
            extra = {"password_authenticated": True, "account_fully_authenticated": False}
        else:
            kind, severity, risk = "Possible Password Brute Force (5-minute window)", "HIGH", 75
            extra = {"window_minutes": 5}
        threats.append(alert(kind, event, state["failures"], severity, risk, **extra))

    for event in events:
        kind = event["event"]
        if kind not in PASSWORD_FAILURES | PASSWORD_SUCCESSES | {"PASSWORD_LOCKOUT"}:
            continue
        key = (event["username"], event["source_ip"])
        state = sessions.get(key)
        if state and event["timestamp"] - state["started"] > WINDOW:
            finish(key)
            state = None

        if kind in PASSWORD_FAILURES:
            if state is None or state["outcome"] is not None:
                state = {"started": event["timestamp"], "failures": 0,
                         "last": event, "outcome": None}
                sessions[key] = state
            state["failures"] += 1
            state["last"] = event
        elif kind == "PASSWORD_LOCKOUT":
            # Subsequent blocked requests can produce more lockout log lines.
            # Only the first lockout belongs to an actual failure sequence.
            if state and state["outcome"] is None:
                state["last"] = event
                state["outcome"] = kind
                finish(key)
        elif kind in PASSWORD_SUCCESSES:
            if state and state["outcome"] is None:
                state["last"] = event
                state["outcome"] = kind
                finish(key)
    for key in list(sessions):
        finish(key)
    return threats


def detect_mfa_threats(events):
    # MFA lockouts count as protective events even if the current session has
    # fewer than three failures. Repeated lockout messages are not new incidents.
    sessions = {}
    threats = []

    def finish(key, outcome=None):
        state = sessions.pop(key, None)
        if state is None:
            return
        failures = state["failures"]
        if outcome != "MFA_LOCKOUT" and failures < MFA_THRESHOLD:
            return
        event = state["last"]
        if outcome == "MFA_LOCKOUT":
            kind, severity, risk = "MFA Authentication Lockout", "HIGH", 85
            extra = {"protection_status": "MFA LOCKOUT ACTIVATED",
                     "password_authenticated": True, "mfa_authenticated": False}
        elif outcome == "MFA_SUCCESS":
            kind, severity, risk = "MFA Success After Repeated Failures", "CRITICAL", 95
            extra = {"password_authenticated": True, "mfa_authenticated": True,
                     "account_fully_authenticated": True}
        else:
            kind, severity, risk = "Repeated MFA Authentication Failures", "HIGH", 80
            extra = {"password_authenticated": True,
                     "account_fully_authenticated": False}
        threats.append(alert(kind, event, failures, severity, risk, **extra))

    for event in events:
        kind = event["event"]
        key = (event["username"], event["source_ip"])
        current = sessions.get(key)
        if current and event["timestamp"] - current["started"] > MFA_SESSION_TIMEOUT:
            finish(key)
            current = None
        if kind == "PASSWORD_SUCCESS":
            if current:
                finish(key)
            sessions[key] = {"started": event["timestamp"], "failures": 0,
                             "last": event}
        elif kind == "MFA_FAILURE" and current:
            current["failures"] += 1
            current["last"] = event
        elif kind in ("MFA_SUCCESS", "MFA_LOCKOUT") and current:
            current["last"] = event
            finish(key, kind)
    for key in list(sessions):
        finish(key)
    return threats


def recent_failure_counts(events, failure_types):

    # The five-minute snapshot is exploratory until baseline samples use
    # the same time-window definition.

    if not events:

        return Counter()

    cutoff = events[-1]["timestamp"] - WINDOW

    return Counter(

        event["source_ip"] for event in events

        if event["event"] in failure_types and event["timestamp"] >= cutoff

    )

def run_anomalies(counts, feature):

    ready = (password_baseline_ready(MIN_BASELINE_SAMPLES)

             if feature == "PASSWORD" else mfa_baseline_ready(MIN_BASELINE_SAMPLES))

    history = get_password_history() if feature == "PASSWORD" else get_mfa_history()

    print(f"\n=== {feature} ANOMALY DETECTION ===")

    if not ready:

        print("LEARNING MODE: insufficient baseline samples")

        return []

    findings = []

    for ip, failures in counts.items():

        result = analyze_failed_logins(failures, history)

        result.update({"source_ip": ip, "feature_type": feature,

                       "window_minutes": 5})

        print(f"{ip}: {failures} failures, Z={result['z_score']}, "

              f"{result['classification']}")

        if result["classification"] in ("SUSPICIOUS", "HIGHLY ANOMALOUS"):

            findings.append(result)

    return findings

def fingerprint_findings(threats, anomalies):

    # Hash the findings to detect changes to an existing incident.

    payload = json.dumps({"threats": threats, "anomalies": anomalies},

                         sort_keys=True, separators=(",", ":"))

    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_state():
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(STATE_FILE)


def group_incidents(events, threats, anomalies):
    # Group by account/IP and split on inactivity or completed authentication.
    # The first event anchors the incident ID across subsequent updates.
    by_identity = {}
    for event in events:
        key = (event["username"], event["source_ip"])
        by_identity.setdefault(key, []).append(event)

    windows = []
    for (user, ip), entries in by_identity.items():
        current = []
        closed = False
        for event in entries:
            gap = bool(current and event["timestamp"] - current[-1]["timestamp"] > WINDOW)
            fresh_login = bool(current and closed and event["event"] == "PASSWORD_SUCCESS")
            if gap or fresh_login:
                windows.append((user, ip, current))
                current = []
                closed = False
            current.append(event)
            if event["event"] in {"MFA_SUCCESS", "MFA_LOCKOUT", "PASSWORD_LOCKOUT"}:
                closed = True
        if current:
            windows.append((user, ip, current))

    result = []
    for user, ip, entries in windows:
        first, last = entries[0], entries[-1]
        matching = [t for t in threats if t.get("username") == user
                    and t.get("source_ip") == ip
                    and first["timestamp"] <= datetime.fromisoformat(t["timestamp"]) <= last["timestamp"]]
        if not matching:
            continue
        raw_id = f"{user}|{ip}|{first['line']}|{first['timestamp'].isoformat()}"
        incident_id = hashlib.sha256(raw_id.encode()).hexdigest()
        result.append({"key": incident_id, "threats": matching, "anomalies": []})

    for anomaly in anomalies:
        matching = [i for i in result if any(t["source_ip"] == anomaly.get("source_ip")
                    for t in i["threats"])]
        if matching:
            matching[-1]["anomalies"].append(anomaly)
    return result


def main():
    parser = argparse.ArgumentParser(description="Analyze security incidents")
    parser.add_argument("--post-trello", action="store_true", help="Send new incidents to Trello")
    parser.add_argument("--initialize-state", action="store_true", help="Mark current historical incidents as known, without posting")
    args = parser.parse_args()

    print("=" * 60)

    print("       AI-POWERED SECURITY LOG ANALYZER")

    print("=" * 60)

    events, invalid = parse_events(LOG_FILE)

    if not events:

        print("No valid authentication events available.")

        return

    counts = Counter(event["event"] for event in events)

    print(f"\nLoaded {len(events)} valid events; skipped {invalid} malformed lines.")

    print("\n=== AUTHENTICATION SUMMARY ===")

    for name in ("PASSWORD_FAILURE", "FAILED_LOGIN", "PASSWORD_SUCCESS",

                 "SUCCESS_LOGIN", "MFA_FAILURE", "MFA_SUCCESS",

                 "PASSWORD_LOCKOUT", "MFA_LOCKOUT"):

        print(f"{name:<22} {counts[name]}")

    threats = detect_password_threats(events) + detect_mfa_threats(events)

    print("\n=== RULE-BASED SECURITY ALERTS ===")

    if not threats:

        print("No rule-based threats detected.")

    for finding in threats:

        print(f"[{finding['severity']}] {finding['type']} | "

              f"{finding['username']} | {finding['source_ip']} | "

              f"{finding['failed_attempts']} failures")

    print("\n=== BEHAVIORAL BASELINES ===")

    for name, summary in (("PASSWORD", password_baseline_summary()),

                          ("MFA", mfa_baseline_summary())):

        print(f"{name}: {summary['samples']} samples, "

              f"average={summary['average']}")

    password_counts = recent_failure_counts(events, PASSWORD_FAILURES)

    mfa_counts = recent_failure_counts(events, {"MFA_FAILURE"})

    anomalies = (run_anomalies(password_counts, "PASSWORD")

                 + run_anomalies(mfa_counts, "MFA"))

    if not threats and not anomalies:

        print("\nNo security findings require AI analysis or reporting.")

        return


    incidents = group_incidents(events, threats, anomalies)
    state = load_state()
    known = set(state.get("known_ids", []))
    revisions = state.get("incident_revisions", {})
    if not isinstance(revisions, dict):
        revisions = {}

    if args.initialize_state:
        known.update(i["key"] for i in incidents)
        # Treat historical incidents as handled; don't repost them.
        for incident in incidents:
            revisions[incident["key"]] = fingerprint_findings(
                incident["threats"], incident["anomalies"])
        state["known_ids"] = sorted(known)
        state["incident_revisions"] = revisions
        save_state(state)
        print("Historical incidents marked as known. No Trello cards created.")
        return

    processed = 0
    for incident in incidents:
        key = incident["key"]
        incident_threats = incident["threats"]
        incident_anomalies = incident["anomalies"]
        revision = fingerprint_findings(incident_threats, incident_anomalies)
        previous = revisions.get(key)

        # Backward compatibility: a previously handled incident without a
        # stored revision is not automatically re-posted as a new card.
        if previous is None and key in known:
            continue
        if previous == revision:
            continue

        action = "UPDATE" if previous is not None else "CREATE"
        print(f"\\n=== INCIDENT {key[:12]} ({action}) ===")
        print("Findings:", len(incident_threats), "Anomalies:", len(incident_anomalies))
        if not args.post_trello:
            print(f"DRY RUN: would {action.lower()} incident; no API calls or reports.")
            processed += 1
            continue

        ai_report = analyze_with_ai(incident_threats, incident_anomalies)
        report = generate_incident_report(incident_threats, incident_anomalies, ai_report)
        if not report:
            continue
        report["dedupe_key"] = key
        classification = classify_incident(incident_threats, incident_anomalies, ai_report)
        try:
            post_incident(report, classification, incident_threats, incident_anomalies, ai_report)
        except Exception as exc:
            print(f"Trello posting failed (will retry next run): {exc}")
            continue

        known.add(key)
        revisions[key] = revision
        state["known_ids"] = sorted(known)
        state["incident_revisions"] = revisions
        save_state(state)
        processed += 1

    if not processed:
        print("No new or changed incidents.")
    print("\nAnalysis complete.")

if __name__ == "__main__":

    main()
