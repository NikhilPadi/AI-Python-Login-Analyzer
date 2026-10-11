import math


def calculate_mean(values):
    """Calculate the average of a list of values."""
    if not values:
        return 0

    return sum(values) / len(values)


def calculate_standard_deviation(values):
    """Calculate population standard deviation."""
    if len(values) < 2:
        return 0

    mean = calculate_mean(values)

    squared_differences = []

    for value in values:
        difference = value - mean
        squared_differences.append(difference ** 2)

    variance = sum(squared_differences) / len(values)

    return math.sqrt(variance)


def calculate_z_score(value, historical_values):
    """Calculate how far a value is from historical behavior."""
    mean = calculate_mean(historical_values)
    standard_deviation = calculate_standard_deviation(
        historical_values
    )

    if standard_deviation == 0:
        return 0

    return (value - mean) / standard_deviation


def detect_anomaly(value, historical_values):
    """Classify activity using its calculated Z-score."""
    z_score = calculate_z_score(
        value,
        historical_values
    )

    if z_score >= 3:
        classification = "HIGHLY ANOMALOUS"
        risk_score = 90

    elif z_score >= 2:
        classification = "SUSPICIOUS"
        risk_score = 65

    else:
        classification = "NORMAL"
        risk_score = 20

    return {
        "value": value,
        "baseline_mean": round(
            calculate_mean(historical_values), 2
        ),
        "z_score": round(z_score, 2),
        "classification": classification,
        "risk_score": risk_score
    }


def analyze_failed_logins(current_failures, historical_failures):
    """Analyze failed-login behavior."""
    result = detect_anomaly(
        current_failures,
        historical_failures
    )

    return {
        "feature": "Failed Login Frequency",
        "current_value": current_failures,
        "normal_average": result["baseline_mean"],
        "z_score": result["z_score"],
        "classification": result["classification"],
        "risk_score": result["risk_score"]
    }


def display_analysis(result):
    """Display the anomaly analysis."""
    print("=" * 55)
    print("       CUSTOM SECURITY ANOMALY DETECTOR")
    print("=" * 55)

    print(f"\nFeature:          {result['feature']}")
    print(f"Current Value:    {result['current_value']}")
    print(f"Normal Average:   {result['normal_average']}")
    print(f"Z-Score:          {result['z_score']}")
    print(f"Classification:   {result['classification']}")
    print(f"Risk Score:       {result['risk_score']}/100")

    if result["classification"] == "HIGHLY ANOMALOUS":
        print("\n[ALERT] Highly abnormal authentication activity detected.")

    elif result["classification"] == "SUSPICIOUS":
        print("\n[WARNING] Suspicious authentication activity detected.")

    else:
        print("\n[OK] Activity is within the expected baseline.")


def main():
    # Simulated historical authentication behavior.
    # Later this will be automatically generated from real log history.
    historical_failures = [
        0,
        1,
        1,
        0,
        2,
        1,
        0,
        1,
        2,
        1
    ]

    # Simulated current activity.
    # Later analyzer.py will provide this automatically.
    current_failures = 10

    result = analyze_failed_logins(
        current_failures,
        historical_failures
    )

    display_analysis(result)


if __name__ == "__main__":
    main()