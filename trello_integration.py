"""Post one sanitized SOC incident card using saved Trello OAuth credentials.

Requires TRELLO_CLIENT_ID for refresh, and data/trello_tokens.json from trello_auth.py.
The authorization token is never printed or included in a card.
"""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOKENS = ROOT / "data" / "trello_tokens.json"
SENT = ROOT / "data" / "trello_posted.json"
BOARD_ID = os.environ.get("TRELLO_BOARD_ID", "sykwHhRk")
API = "https://api.trello.com/1"
TOKEN_ENDPOINT = "https://auth.atlassian.com/oauth/token"


def _request(url, token, method="GET", body=None):
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _load_token():
    if not TOKENS.is_file():
        raise RuntimeError("No Trello token file. Run trello_auth.py first.")
    data = json.loads(TOKENS.read_text(encoding="utf-8"))
    if time.time() < data.get("expires_at", 0) - 120:
        return data["access_token"]
    client_id = os.environ.get("TRELLO_CLIENT_ID")
    if not client_id or not data.get("refresh_token"):
        raise RuntimeError("Token expired. Set TRELLO_CLIENT_ID and reauthorize if necessary.")
    payload = json.dumps({"grant_type": "refresh_token", "client_id": client_id,
                          "refresh_token": data["refresh_token"]}).encode()
    req = urllib.request.Request(TOKEN_ENDPOINT, data=payload, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as response:
        updated = json.loads(response.read().decode())
    data.update(updated)
    data["expires_at"] = int(time.time()) + int(updated.get("expires_in", 3600))
    TOKENS.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.chmod(TOKENS, 0o600)
    return data["access_token"]


def test_connection():
    token = _load_token()
    lists = _request(f"{API}/boards/{BOARD_ID}/lists?fields=name,id", token)
    print("Accessible SOC lists:")
    for item in lists:
        print(" -", item["name"])
    return lists


def post_incident(report, classification, threats, anomalies, ai_analysis):
    """Post one report to Trello; duplicate protection persists across runs."""
    incident_id = report["incident_id"]
    dedupe_key = report.get("dedupe_key", incident_id)
    posted = json.loads(SENT.read_text()) if SENT.exists() else {}
    existing = posted.get(dedupe_key)
    token = _load_token()
    lists = _request(f"{API}/boards/{BOARD_ID}/lists?fields=name,id", token)
    names = {entry["name"].strip().lower(): entry["id"] for entry in lists}
    destination = classification["category"]
    list_id = names.get(destination.lower()) or names.get("needs investigation")
    if not list_id:
        raise RuntimeError("Trello list not found: " + destination)
    severity = report.get("severity", "UNKNOWN")
    # Never upload raw logs, credentials, authenticator codes or private files.
    summary = [f"Incident ID: {incident_id}", f"Severity: {severity}",
               f"Classification: {destination}",
               f"Review: {classification['review_status']}", "", "Detected findings:"]
    for t in threats[:20]:
        summary.append(f"- {t.get('type', 'Unknown')} | {t.get('failed_attempts', '?')} failures")
    for a in anomalies[:20]:
        summary.append(f"- {a.get('feature_type', 'Behavioral')} anomaly: {a.get('classification', '')}")
    summary.extend(["", "Local AI SOC assessment (unverified):", str(ai_analysis)[:4500]])
    payload = {"idList": list_id, "name": f"[{severity}] {destination} — {incident_id}",
               "desc": "\n".join(summary)[:12000]}
    # Reuse the four labels the user already created on the board.
    board_labels = _request(f"{API}/boards/{BOARD_ID}/labels?fields=name,id", token)
    label_ids = {item.get("name", "").strip().lower(): item["id"]
                 for item in board_labels}
    selected = []
    severity_label = label_ids.get(str(severity).lower())
    if severity_label:
        selected.append(severity_label)
    if classification.get("review_required") or destination == "Needs Investigation":
        review_label = label_ids.get("review required")
        if review_label:
            selected.append(review_label)
    if selected:
        payload["idLabels"] = ",".join(selected)
    if existing and existing.get("card_id"):
        # Do not reopen cards that an analyst has manually resolved.
        current_card = _request(
            f"{API}/cards/{existing['card_id']}?fields=idList,closed,url",
            token
        )
        if current_card.get("closed") or current_card.get("idList") == names.get("resolved"):
            print("Incident card already resolved; skipping automatic update")
            return existing
        card = _request(
            f"{API}/cards/{existing['card_id']}",
            token, method="PUT", body=payload
        )
        print("Updated existing Trello incident card")
    else:
        card = _request(f"{API}/cards", token, method="POST", body=payload)
        print("Created Trello incident card")
    posted[dedupe_key] = {"card_id": card["id"], "url": card.get("url", "")}
    SENT.parent.mkdir(parents=True, exist_ok=True)
    SENT.write_text(json.dumps(posted, indent=2), encoding="utf-8")
    os.chmod(SENT, 0o600)
    print("Trello incident card:", card.get("url", "created"))
    return posted[dedupe_key]


if __name__ == "__main__":
    try:
        test_connection()
    except (RuntimeError, urllib.error.URLError, KeyError, ValueError) as exc:
        print("Trello connection test failed:", exc)
