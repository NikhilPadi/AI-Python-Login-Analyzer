"""Watch the local authentication log and run analyzer.py after new events.

Standard-library only. Start webapp.py separately, then run this monitor.
Ctrl+C stops it. The analyzer handles Trello and incident deduplication.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOG_FILE = ROOT / 'sample_logs' / 'auth.log'
ANALYZER = ROOT / 'analyzer.py'
POLL_SECONDS = 2
QUIET_SECONDS = 4
MIN_RUN_GAP_SECONDS = 15


def signature():
    """Return file identity, size, and modification time, including rotation."""
    try:
        stat = LOG_FILE.stat()
        return stat.st_ino, stat.st_size, stat.st_mtime_ns
    except FileNotFoundError:
        return None


def main():
    if not ANALYZER.is_file():
        print(f'[ERROR] Missing {ANALYZER}', flush=True)
        return 1

    last_seen = signature()
    pending = False
    last_change = time.monotonic()
    last_run = float('-inf')
    print('=== LIVE SECURITY MONITOR ===', flush=True)
    print(f'Watching: {LOG_FILE}', flush=True)
    print('Only changes after startup trigger a scan. Trello posting enabled. Press Ctrl+C to stop.', flush=True)

    try:
        while True:
            time.sleep(POLL_SECONDS)
            current = signature()
            if current != last_seen:
                last_seen = current
                if current is None:
                    pending = False
                    print('Log missing; waiting for it to return.', flush=True)
                else:
                    pending = True
                    last_change = time.monotonic()
                    print('New log activity detected; waiting for a quiet period...', flush=True)

            now = time.monotonic()
            if (pending and current is not None
                    and now - last_change >= QUIET_SECONDS
                    and now - last_run >= MIN_RUN_GAP_SECONDS):
                pending = False
                last_run = now
                print('\n=== RUNNING SECURITY ANALYZER ===', flush=True)
                try:
                    result = subprocess.run(
                        [sys.executable, '-u', str(ANALYZER), '--post-trello'],
                        cwd=ROOT,
                        check=False,
                        timeout=240,
                    )
                    if result.returncode:
                        print(f'[WARNING] Analyzer exited with code {result.returncode}', flush=True)
                except subprocess.TimeoutExpired:
                    print('[WARNING] Analyzer exceeded 240 seconds.', flush=True)
                except OSError as exc:
                    print(f'[ERROR] Could not launch analyzer: {exc}', flush=True)
                # Changes while the analyzer was running should be processed.
                after = signature()
                if after != last_seen:
                    last_seen = after
                    pending = after is not None
                    last_change = time.monotonic()
                print('\nMonitoring for new activity...', flush=True)
    except KeyboardInterrupt:
        print('\nMonitor stopped.', flush=True)
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
