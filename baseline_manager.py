import json
import os
from datetime import datetime


BASELINE_FILE = "data/baseline.json"
MAX_HISTORY = 100


def create_empty_baseline():
    """Create the default baseline structure."""

    return {
        "password_failures": [],
        "mfa_failures": [],
        "created_at": datetime.now().isoformat(),
        "updated_at": None
    }


def load_baseline():
    """Load historical authentication behavior."""

    if not os.path.exists(BASELINE_FILE):
        return create_empty_baseline()

    try:
        with open(BASELINE_FILE, "r") as file:
            data = json.load(file)

    except (json.JSONDecodeError, OSError):
        return create_empty_baseline()

    # --------------------------------------------------
    # MIGRATE OLD BASELINE FORMAT
    # --------------------------------------------------

    # Our original project stored password failures as:
    #
    # "failed_logins_per_session"
    #
    # Preserve those observations instead of deleting them.

    if "failed_logins_per_session" in data:

        if "password_failures" not in data:

            data["password_failures"] = data[
                "failed_logins_per_session"
            ]

        del data["failed_logins_per_session"]

    # Make sure both baseline categories exist.

    if "password_failures" not in data:
        data["password_failures"] = []

    if "mfa_failures" not in data:
        data["mfa_failures"] = []

    return data


def save_baseline(data):
    """Save baseline information."""

    os.makedirs(
        os.path.dirname(BASELINE_FILE),
        exist_ok=True
    )

    data["updated_at"] = datetime.now().isoformat()

    with open(BASELINE_FILE, "w") as file:

        json.dump(
            data,
            file,
            indent=4
        )


def get_password_history():
    """Return historical password failure counts."""

    baseline = load_baseline()

    return baseline.get(
        "password_failures",
        []
    )


def get_mfa_history():
    """Return historical MFA failure counts."""

    baseline = load_baseline()

    return baseline.get(
        "mfa_failures",
        []
    )


# Compatibility with our existing analyzer.

def get_failure_history():
    """Return password failure history."""

    return get_password_history()


def add_password_observation(failures):
    """Add a verified-normal password observation."""

    baseline = load_baseline()

    history = baseline.get(
        "password_failures",
        []
    )

    history.append(failures)

    history = history[-MAX_HISTORY:]

    baseline["password_failures"] = history

    save_baseline(baseline)


def add_mfa_observation(failures):
    """Add a verified-normal MFA observation."""

    baseline = load_baseline()

    history = baseline.get(
        "mfa_failures",
        []
    )

    history.append(failures)

    history = history[-MAX_HISTORY:]

    baseline["mfa_failures"] = history

    save_baseline(baseline)


# Compatibility with old baseline trainer.

def add_normal_observation(failures):
    """Add verified-normal password behavior."""

    add_password_observation(failures)


def password_baseline_ready(minimum_samples=10):

    return (
        len(get_password_history())
        >= minimum_samples
    )


def mfa_baseline_ready(minimum_samples=10):

    return (
        len(get_mfa_history())
        >= minimum_samples
    )


# Compatibility with existing analyzer.

def baseline_ready(minimum_samples=10):

    return password_baseline_ready(
        minimum_samples
    )


def calculate_summary(history):
    """Calculate baseline statistics."""

    if not history:

        return {
            "samples": 0,
            "average": 0,
            "minimum": 0,
            "maximum": 0
        }

    return {
        "samples": len(history),

        "average": round(
            sum(history) / len(history),
            2
        ),

        "minimum": min(history),

        "maximum": max(history)
    }


def password_baseline_summary():

    return calculate_summary(
        get_password_history()
    )


def mfa_baseline_summary():

    return calculate_summary(
        get_mfa_history()
    )


# Compatibility with existing analyzer.

def baseline_summary():

    return password_baseline_summary()


def display_summary():

    password = password_baseline_summary()
    mfa = mfa_baseline_summary()

    print("=" * 55)
    print(" SECURITY BEHAVIORAL BASELINES")
    print("=" * 55)

    print("\n=== PASSWORD BASELINE ===")

    print(
        f"Samples:          "
        f"{password['samples']}"
    )

    print(
        f"Average failures: "
        f"{password['average']}"
    )

    print(
        f"Minimum failures: "
        f"{password['minimum']}"
    )

    print(
        f"Maximum failures: "
        f"{password['maximum']}"
    )

    if password_baseline_ready():

        print(
            "Status:           ACTIVE"
        )

    else:

        print(
            "Status:           LEARNING"
        )

    print("\n=== MFA BASELINE ===")

    print(
        f"Samples:          "
        f"{mfa['samples']}"
    )

    print(
        f"Average failures: "
        f"{mfa['average']}"
    )

    print(
        f"Minimum failures: "
        f"{mfa['minimum']}"
    )

    print(
        f"Maximum failures: "
        f"{mfa['maximum']}"
    )

    if mfa_baseline_ready():

        print(
            "Status:           ACTIVE"
        )

    else:

        print(
            "Status:           LEARNING"
        )


if __name__ == "__main__":

    display_summary()