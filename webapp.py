from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import hmac
import json
import os
import re
import secrets
import time

from flask import Flask, redirect, render_template, request, session, url_for
import pyotp
import qrcode


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "sample_logs"
STATIC_DIR = BASE_DIR / "static"

LOG_FILE = LOG_DIR / "auth.log"
TOTP_FILE = DATA_DIR / "totp_secret.txt"
ACCOUNT_FILE = DATA_DIR / "lab_account.json"
SESSION_KEY_FILE = DATA_DIR / "session_secret.txt"

USERNAME = os.getenv("LAB_USERNAME", "testadmin")
MAX_PASSWORD_ATTEMPTS = 5
MAX_MFA_ATTEMPTS = 5
LOCKOUT_SECONDS = 120
SESSION_TIMEOUT_MINUTES = 15
MFA_PENDING_SECONDS = 300
PBKDF2_ITERATIONS = 600_000

for folder in (DATA_DIR, LOG_DIR, STATIC_DIR):
    folder.mkdir(parents=True, exist_ok=True)


def save_private_file(path, content):
    # Keep secrets readable only by the current Ubuntu user.
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)


def load_or_create_secret(path, generator):
    if path.exists():
        os.chmod(path, 0o600)
        return path.read_text(encoding="utf-8").strip()

    value = generator()
    save_private_file(path, value)
    return value


SESSION_SECRET = load_or_create_secret(
    SESSION_KEY_FILE, lambda: secrets.token_hex(32)
)
TOTP_SECRET = load_or_create_secret(TOTP_FILE, pyotp.random_base32)

app = Flask(__name__)
app.secret_key = SESSION_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # This training website runs on local HTTP, not public HTTPS.
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_TIMEOUT_MINUTES),
    MAX_CONTENT_LENGTH=16 * 1024,
)


def hash_password(password, salt, iterations=PBKDF2_ITERATIONS):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    ).hex()


def create_lab_account():
    if ACCOUNT_FILE.exists():
        return

    # Only required for first-time setup. Existing account hashes are preserved.
    initial_password = os.getenv("LAB_INITIAL_PASSWORD")
    if not initial_password:
        raise RuntimeError(
            "First-time setup: set LAB_INITIAL_PASSWORD to a unique test "
            "password before starting webapp.py."
        )

    salt = os.urandom(32)
    account = {
        "username": USERNAME,
        "salt": salt.hex(),
        "password_hash": hash_password(initial_password, salt),
        "iterations": PBKDF2_ITERATIONS,
    }
    save_private_file(ACCOUNT_FILE, json.dumps(account, indent=2))


def load_account():
    return json.loads(ACCOUNT_FILE.read_text(encoding="utf-8"))


def verify_password(username, password):
    account = load_account()
    salt = bytes.fromhex(account["salt"])
    candidate = hash_password(password, salt, account["iterations"])

    username_ok = hmac.compare_digest(username, account["username"])
    password_ok = hmac.compare_digest(candidate, account["password_hash"])
    return username_ok and password_ok


create_lab_account()


def write_log(event, username, ip):
    # Keep the original log format for analyzer.py and live_monitor.py.
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_username = re.sub(r"[^a-zA-Z0-9_.@-]", "_", str(username))[:80]
    entry = f"{timestamp} {event} user={safe_username or 'unknown'} ip={ip}\n"

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(entry)
    print(entry.strip())


# In-memory limits are sufficient for this single-process localhost lab.
# They reset on restart and are not shared across multiple server workers.
password_attempts = defaultdict(int)
password_lockouts = {}
mfa_attempts = defaultdict(int)
mfa_lockouts = {}
used_totp_steps = {}


def is_locked(lockouts, key):
    expiry = lockouts.get(key)
    if expiry is None:
        return False
    if time.monotonic() >= expiry:
        lockouts.pop(key, None)
        return False
    return True


def record_failure(attempts, lockouts, key, limit):
    attempts[key] += 1
    if attempts[key] < limit:
        return False

    lockouts[key] = time.monotonic() + LOCKOUT_SECONDS
    attempts[key] = 0
    return True


def verify_totp_code(code):
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return False

    totp = pyotp.TOTP(TOTP_SECRET)
    current_step = int(time.time()) // 30

    # Accept one step of clock drift but reject previously accepted steps.
    for step in (current_step - 1, current_step, current_step + 1):
        if hmac.compare_digest(code, totp.at(step * 30)):
            if used_totp_steps.get(USERNAME, -1) >= step:
                return False
            used_totp_steps[USERNAME] = step
            return True
    return False


@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr or "127.0.0.1"
        key = (username, ip)

        if is_locked(password_lockouts, key):
            write_log("PASSWORD_LOCKOUT", username, ip)
            error = "Too many login attempts. Please try again later."
        elif verify_password(username, password):
            password_attempts.pop(key, None)
            write_log("PASSWORD_SUCCESS", username, ip)
            session.clear()
            session.permanent = True
            session["pending_user"] = username
            session["pending_since"] = time.time()
            return redirect(url_for("verify_2fa"))
        else:
            write_log("PASSWORD_FAILURE", username or "unknown", ip)
            locked = record_failure(
                password_attempts, password_lockouts, key, MAX_PASSWORD_ATTEMPTS
            )
            if locked:
                write_log("PASSWORD_LOCKOUT", username, ip)
                error = "Too many login attempts. Please try again later."
            else:
                error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/setup")
def setup_2fa():
    if session.get("pending_user") != USERNAME:
        return redirect(url_for("login"))
    if time.time() - session.get("pending_since", 0) > MFA_PENDING_SECONDS:
        session.clear()
        return redirect(url_for("login"))

    totp = pyotp.TOTP(TOTP_SECRET)
    uri = totp.provisioning_uri(
        name=USERNAME, issuer_name="Security Log Analyzer Lab"
    )
    # Existing setup_2fa.html expects this image path.
    # Do not publish the generated QR image or expose this lab publicly.
    qrcode.make(uri).save(STATIC_DIR / "totp_qr.png")
    return render_template("setup_2fa.html")


@app.route("/verify", methods=["GET", "POST"])
def verify_2fa():
    username = session.get("pending_user")
    if not username:
        return redirect(url_for("login"))
    if time.time() - session.get("pending_since", 0) > MFA_PENDING_SECONDS:
        session.clear()
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        ip = request.remote_addr or "127.0.0.1"
        key = (username, ip)

        if is_locked(mfa_lockouts, key):
            write_log("MFA_LOCKOUT", username, ip)
            error = "Too many verification attempts. Please try again later."
        elif verify_totp_code(code):
            write_log("MFA_SUCCESS", username, ip)
            mfa_attempts.pop(key, None)
            session.clear()
            session.permanent = True
            session["authenticated_user"] = username
            return redirect(url_for("success"))
        else:
            write_log("MFA_FAILURE", username, ip)
            locked = record_failure(
                mfa_attempts, mfa_lockouts, key, MAX_MFA_ATTEMPTS
            )
            if locked:
                write_log("MFA_LOCKOUT", username, ip)
                error = "Too many verification attempts. Please try again later."
            else:
                error = "Incorrect verification code."

    return render_template("verify_2fa.html", error=error)


@app.route("/success")
def success():
    username = session.get("authenticated_user")
    if not username:
        return redirect(url_for("login"))
    return render_template("success.html", username=username)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    print("Security Log Analyzer - Local Authentication Lab")
    print("Website: http://127.0.0.1:5000")
    print("Google Authenticator setup: sign in, then visit /setup")
    print(f"Password and MFA lockout: {LOCKOUT_SECONDS} seconds")
    app.run(host="127.0.0.1", port=5000, debug=False)
