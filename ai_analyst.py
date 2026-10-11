import json
import os
import re
import urllib.error
import urllib.request


# Use the Windows host's Ollama address by default. Override it with OLLAMA_URL.
OLLAMA_URL = os.getenv(
    "OLLAMA_URL", "http://192.168.254.165:11434/api/generate"
)
MODEL_NAME = os.getenv("OLLAMA_MODEL", "qwen3:8b")
REQUEST_TIMEOUT = 180


# Only structured findings are sent to Ollama, never passwords or TOTP secrets.
def prepare_security_data(threats, anomaly_results):
    return {
        "environment": {
            "type": "Controlled authentication security lab",
            "production_system": False,
            "authentication": "Password followed by Google Authenticator TOTP",
            "localhost": "127.0.0.1 is expected for local website testing",
            "baseline_note": (
                "Statistical baselines use manually verified or simulated "
                "normal observations, not validated production data"
            ),
        },
        "detected_threats": threats,
        "anomaly_analysis": anomaly_results,
    }


def build_prompt(threats, anomaly_results):
    findings = prepare_security_data(threats, anomaly_results)

    return f"""You are a SOC analyst reviewing authentication alerts from a controlled lab.

The Python detection engine has already collected the findings below. Base your
assessment only on these findings. Do not invent timestamps, accounts, network
activity, or evidence of compromise.

Lab context:
- The Flask login site runs locally and uses password authentication followed by
  Google Authenticator TOTP.
- 127.0.0.1 is the loopback address, not an external attacker. Do not infer IP
  spoofing, lateral movement, or remote compromise from localhost alone.
- These are simulated or controlled test events, not verified production attacks.
- The baseline data is not validated on real-world production traffic.

Authentication interpretation:
- PASSWORD_SUCCESS means the password was accepted, not that MFA succeeded.
- MFA_SUCCESS means the second factor was accepted, not that access was malicious.
- PASSWORD_LOCKOUT and MFA_LOCKOUT indicate protective controls activated.
- Repeated failures may reflect guessing, user mistakes, or deliberate lab tests.
- A high Z-score is deviation from the chosen baseline, not a probability of
  compromise. Risk scores are heuristic prioritization values.
- Respect the severity assigned by the detection engine; if it seems overstated,
  explain why instead of silently changing it.
- Never describe account compromise as confirmed without supporting evidence.
- Do not recommend enabling MFA when the website already requires MFA.

Security findings (structured JSON):
{json.dumps(findings, indent=2)}

Write a concise professional assessment using these headings:
1. INCIDENT CLASSIFICATION — suspected category, or Undetermined — Requires Investigation
2. SEVERITY ASSESSMENT — engine severity and justification
3. OBSERVED EVIDENCE — facts from the findings only
4. SECURITY ANALYSIS — likely explanations and reasonable alternatives
5. POTENTIAL IMPACT — hypothetical production impact, separate from lab outcomes
6. RECOMMENDED INVESTIGATION — specific verification steps
7. RECOMMENDED REMEDIATION — proportional to the evidence
8. ESCALATION RECOMMENDATION — No escalation required, Routine analyst review,
   Priority investigation, or Immediate escalation, with explanation
9. CONFIDENCE ASSESSMENT — HIGH, MEDIUM, or LOW, with limitations

Avoid unsupported claims and write only the final SOC assessment."""


# Some Qwen responses contain an optional <think> block; keep only the report.
def clean_ai_response(response_text):
    if not response_text:
        return "AI returned no analysis."

    cleaned = re.sub(
        r"<think>.*?</think>", "", response_text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    cleaned = re.sub(
        r"<think>.*", "", cleaned,
        flags=re.DOTALL | re.IGNORECASE,
    )
    return cleaned.strip() or "AI returned no final assessment."


def analyze_with_ai(threats, anomaly_results):
    if not threats and not anomaly_results:
        return "No security findings require AI analysis."

    payload = {
        "model": MODEL_NAME,
        "prompt": build_prompt(threats, anomaly_results),
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 1400},
    }
    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            result = json.loads(response.read().decode("utf-8"))
        if result.get("error"):
            return f"Local AI analysis failed: {result['error']}"
        return clean_ai_response(result.get("response", ""))
    except urllib.error.HTTPError as error:
        return f"Local AI HTTP error: {error.code} {error.reason}"
    except urllib.error.URLError as error:
        return (
            f"Local AI connection failed: {error.reason}. "
            "Verify that Ollama is running and reachable."
        )
    except TimeoutError:
        return "Local AI analysis timed out. The detections remain available."
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "Local AI returned an invalid response."
    except Exception as error:
        return f"Local AI analysis unavailable: {type(error).__name__}: {error}"


if __name__ == "__main__":
    # This standalone check never generates a Trello card or incident report.
    sample_threats = [{
        "type": "MFA Authentication Lockout",
        "source_ip": "127.0.0.1",
        "username": "testadmin",
        "failed_attempts": 5,
        "severity": "HIGH",
        "risk_score": 85,
        "protection_status": "MFA LOCKOUT ACTIVATED",
        "mfa_authenticated": False,
    }]
    print(analyze_with_ai(sample_threats, []))
