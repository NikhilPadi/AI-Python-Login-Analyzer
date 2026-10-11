"""Conservative classification for a single SOC finding."""
LISTS = ("Password Attacks", "MFA Attacks", "Possible Account Compromise",
         "Security Lockouts", "Behavioral Anomalies", "Needs Investigation")

def classify_incident(threats, anomalies, ai_analysis=""):
    names = [str(t.get("type", "")).lower() for t in threats]
    if not names:
        category = "Behavioral Anomalies" if anomalies else "Needs Investigation"
    elif any("mfa success after" in n for n in names):
        category = "Possible Account Compromise"
    elif any("lockout" in n for n in names):
        category = "Security Lockouts"
    elif any("password accepted after" in n for n in names):
        category = "Possible Account Compromise"
    elif any("mfa" in n for n in names):
        category = "MFA Attacks"
    elif any("password" in n or "brute force" in n for n in names):
        category = "Password Attacks"
    else:
        category = "Needs Investigation"
    # These are rule-supported categories, not calibrated AI probabilities.
    uncertain = category == "Needs Investigation"
    return {
        "category": category,
        "review_required": uncertain,
        "review_status": ("Uncertain: analyst classification needed" if uncertain
                          else "Suspected category based on detection evidence; verify manually"),
        "classification_source": "deterministic rules; local Qwen analysis is advisory",
    }
