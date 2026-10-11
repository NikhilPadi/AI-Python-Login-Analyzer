import json
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4


REPORT_DIRECTORY = Path(__file__).resolve().parent / "reports"


def determine_severity(threats, anomalies):
    """Determine the highest incident severity."""

    levels = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    highest = "LOW"

    for threat in threats:
        severity = threat.get("severity", "LOW").upper()

        if levels.get(severity, 0) > levels[highest]:
            highest = severity

    for anomaly in anomalies:
        classification = anomaly.get("classification", "")

        if classification == "HIGHLY ANOMALOUS":
            severity = "HIGH"
        elif classification == "SUSPICIOUS":
            severity = "MEDIUM"
        else:
            continue

        if levels[severity] > levels[highest]:
            highest = severity

    return highest


def create_incident_id():
    """Generate a unique incident identifier."""

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d-%H%M%S"
    )

    return f"INC-{timestamp}-{uuid4().hex[:8].upper()}"


def generate_incident_report(threats, anomalies, ai_analysis):
    """Generate JSON and TXT incident reports."""

    if not threats and not anomalies:
        return None

    REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    incident_id = create_incident_id()
    severity = determine_severity(threats, anomalies)

    report = {
        "incident_id": incident_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "threat_count": len(threats),
        "anomaly_count": len(anomalies),
        "threats": threats,
        "anomalies": anomalies,
        "ai_analysis": ai_analysis
    }

    json_path = REPORT_DIRECTORY / f"{incident_id}.json"
    txt_path = REPORT_DIRECTORY / f"{incident_id}.txt"

    # Save machine-readable report.
    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    # Save human-readable report.
    with open(txt_path, "w", encoding="utf-8") as file:

        file.write("=" * 60 + "\n")
        file.write("SECURITY INCIDENT REPORT\n")
        file.write("=" * 60 + "\n\n")

        file.write(f"Incident ID: {incident_id}\n")
        file.write(f"Generated: {report['generated_at']}\n")
        file.write(f"Severity: {severity}\n")
        file.write(f"Threats: {len(threats)}\n")
        file.write(f"Anomalies: {len(anomalies)}\n")

        file.write("\n=== DETECTED THREATS ===\n")

        for number, threat in enumerate(threats, start=1):
            file.write(f"\nThreat #{number}\n")

            for key, value in threat.items():
                file.write(f"{key}: {value}\n")

        file.write("\n=== BEHAVIORAL ANOMALIES ===\n")

        for number, anomaly in enumerate(anomalies, start=1):
            file.write(f"\nAnomaly #{number}\n")

            for key, value in anomaly.items():
                file.write(f"{key}: {value}\n")

        file.write("\n=== LOCAL AI SOC ANALYSIS ===\n\n")
        file.write(ai_analysis or "No AI analysis available.")
        file.write("\n")

    return {
        "incident_id": incident_id,
        "severity": severity,
        "json_report": str(json_path),
        "text_report": str(txt_path)
    }