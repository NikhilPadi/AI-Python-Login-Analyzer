# AI-Powered Security Log Analyzer

A Python-based cybersecurity project that monitors authentication activity, detects suspicious login attempts, and automates security incident reporting using local AI and Trello.

## Features

- Password and Google Authenticator (TOTP) authentication
- Brute-force, MFA failure, and account lockout detection
- Behavioral anomaly detection using Z-scores
- Local AI security analysis using Qwen3 8B and Ollama
- Real-time authentication log monitoring
- Automated Trello incident reporting and classification
- Incident escalation with duplicate alert prevention
- JSON and TXT security incident reports

## Technologies

Python, Flask, PyOTP, Ollama, Qwen3 8B, Trello API, OAuth 2.0, and Ubuntu Linux.

## How It Works

1. The Flask website records authentication events.
2. Python analyzes logs for suspicious activity.
3. Statistical analysis identifies unusual behavior.
4. Qwen generates an AI-assisted security assessment.
5. Trello receives incidents with severity labels.
6. Existing incidents are updated when new evidence appears.

## Running the Project

Install dependencies:

    pip install flask pyotp qrcode[pil] requests

Set a test password for first-time setup:

    export LAB_INITIAL_PASSWORD="YOUR_TEST_PASSWORD"

Start the authentication website:

    python3 webapp.py

Start live monitoring in another terminal:

    python3 live_monitor.py

Local AI analysis requires Ollama with Qwen3 8B.
Trello integration requires separate API authorization.

## Screenshots

### Security Threat Detection
![Security Detection](screenshots/security_detection.png)

### AI Security Analysis
![AI Analysis](screenshots/ai_analysis.png)

### Automated Trello Incident Escalation
![Trello Escalation](screenshots/trello_escalation.png)

## Project Purpose

Built as a hands-on cybersecurity project to gain experience with authentication security, threat detection, log analysis, AI-assisted incident response, and security automation.

**Note:** This project is intended for a controlled testing environment and is not production-ready.
