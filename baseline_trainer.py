from baseline_manager import (
    add_password_observation,
    add_mfa_observation,
    password_baseline_summary,
    mfa_baseline_summary,
    password_baseline_ready,
    mfa_baseline_ready
)


MINIMUM_SAMPLES = 10


def display_baselines():
    """Display password and MFA behavioral baselines."""

    password = password_baseline_summary()
    mfa = mfa_baseline_summary()

    print("\n=== PASSWORD BASELINE ===")
    print(f"Samples:          {password['samples']}")
    print(f"Average failures: {password['average']}")
    print(f"Minimum failures: {password['minimum']}")
    print(f"Maximum failures: {password['maximum']}")

    if password_baseline_ready(MINIMUM_SAMPLES):
        print("Status:           ACTIVE")
    else:
        remaining = MINIMUM_SAMPLES - password["samples"]
        print("Status:           LEARNING")
        print(f"Need {remaining} more observations.")

    print("\n=== MFA BASELINE ===")
    print(f"Samples:          {mfa['samples']}")
    print(f"Average failures: {mfa['average']}")
    print(f"Minimum failures: {mfa['minimum']}")
    print(f"Maximum failures: {mfa['maximum']}")

    if mfa_baseline_ready(MINIMUM_SAMPLES):
        print("Status:           ACTIVE")
    else:
        remaining = MINIMUM_SAMPLES - mfa["samples"]
        print("Status:           LEARNING")
        print(f"Need {remaining} more observations.")


def add_password_sample():
    """Add verified-normal password behavior."""

    value = input(
        "\nFailed password attempts in normal session: "
    ).strip()

    try:
        failures = int(value)

        if failures < 0:
            print("Value cannot be negative.")
            return

    except ValueError:
        print("Enter a whole number.")
        return

    confirm = input(
        f"Confirm {failures} password failures as "
        f"VERIFIED NORMAL? (y/n): "
    ).strip().lower()

    if confirm == "y":
        add_password_observation(failures)
        print("Password observation added.")
    else:
        print("Observation discarded.")


def add_mfa_sample():
    """Add verified-normal MFA behavior."""

    value = input(
        "\nFailed MFA attempts in normal session: "
    ).strip()

    try:
        failures = int(value)

        if failures < 0:
            print("Value cannot be negative.")
            return

    except ValueError:
        print("Enter a whole number.")
        return

    confirm = input(
        f"Confirm {failures} MFA failures as "
        f"VERIFIED NORMAL? (y/n): "
    ).strip().lower()

    if confirm == "y":
        add_mfa_observation(failures)
        print("MFA observation added.")
    else:
        print("Observation discarded.")


def main():

    while True:

        print("\n" + "=" * 55)
        print(" SECURITY BASELINE TRAINER")
        print("=" * 55)

        display_baselines()

        print("\n=== OPTIONS ===")
        print("1. Add normal password observation")
        print("2. Add normal MFA observation")
        print("3. View baselines")
        print("Q. Quit")

        choice = input("\nSelect option: ").strip().lower()

        if choice == "1":
            add_password_sample()

        elif choice == "2":
            add_mfa_sample()

        elif choice == "3":
            display_baselines()

        elif choice == "q":
            print("\nBaseline trainer closed.")
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()