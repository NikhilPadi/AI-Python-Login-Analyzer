"""Authorize a local Trello OAuth 2.0 public client using PKCE.

Run: python3 trello_auth.py
Set TRELLO_CLIENT_ID in your terminal first.
Keep data/trello_tokens.json private and out of Git.
"""
import base64
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOKEN_FILE = ROOT / 'data' / 'trello_tokens.json'
REDIRECT_URI = 'http://127.0.0.1:8765/callback'
AUTHORIZE_URL = 'https://auth.atlassian.com/authorize'
TOKEN_URL = 'https://auth.atlassian.com/oauth/token'
SCOPES = 'read:board:trello write:board:trello offline_access'


def save_tokens(payload):
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    previous = {}
    if TOKEN_FILE.exists():
        try:
            previous = json.loads(TOKEN_FILE.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            pass
    previous.update(payload)
    previous['expires_at'] = int(time.time()) + int(payload.get('expires_in', 3600))
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(previous, f, indent=2)
    os.chmod(TOKEN_FILE, 0o600)


def authorize():
    client_id = os.environ.get('TRELLO_CLIENT_ID', '').strip()
    if not client_id:
        raise SystemExit('Set TRELLO_CLIENT_ID in your terminal before running this script.')
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    state = secrets.token_urlsafe(24)
    params = {
        'client_id': client_id, 'scope': SCOPES, 'redirect_uri': REDIRECT_URI,
        'response_type': 'code', 'prompt': 'consent',
        'code_challenge': challenge, 'code_challenge_method': 'S256',
        'state': state,
    }
    url = AUTHORIZE_URL + '?' + urllib.parse.urlencode(params)
    received = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urllib.parse.urlparse(self.path)
            if path.path != '/callback':
                self.send_error(404)
                return
            query = urllib.parse.parse_qs(path.query)
            if query.get('state', [None])[0] != state:
                received['error'] = 'OAuth state mismatch'
            elif 'error' in query:
                received['error'] = query['error'][0]
            else:
                received['code'] = query.get('code', [None])[0]
            body = b'Authorization received. Return to your Ubuntu terminal.'
            self.send_response(200 if received.get('code') else 400)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    with HTTPServer(('127.0.0.1', 8765), Handler) as server:
        server.timeout = 180
        print('Open this URL in Firefox INSIDE your Ubuntu VM if it does not open automatically:')
        print(url)
        webbrowser.open(url)
        deadline = time.monotonic() + 180
        while not received and time.monotonic() < deadline:
            server.handle_request()
    if not received.get('code'):
        raise SystemExit('Authorization was not completed: ' + received.get('error', 'timeout'))

    body = json.dumps({
        'grant_type': 'authorization_code', 'client_id': client_id,
        'redirect_uri': REDIRECT_URI, 'code': received['code'],
        'code_verifier': verifier,
    }).encode('utf-8')
    request = urllib.request.Request(TOKEN_URL, data=body, method='POST', headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            tokens = json.load(response)
    except urllib.error.HTTPError as error:
        raise SystemExit(f'Token exchange failed (HTTP {error.code}): {error.read().decode("utf-8", "replace")[:500]}') from None
    if 'access_token' not in tokens:
        raise SystemExit('No access token returned by Trello.')
    save_tokens(tokens)
    print('Trello authorization succeeded. Tokens saved privately to data/trello_tokens.json')
    print('Do not commit that file to GitHub or share its contents.')


if __name__ == '__main__':
    authorize()
