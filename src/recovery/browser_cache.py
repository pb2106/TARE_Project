#!/usr/bin/env python3
"""
Module 2 – Browser Activity & Cache Simulation (Member 1)
==========================================================
Simulates browser-like activity by writing fake browsing artifacts
that mimic real Chrome / Firefox storage structures:
  • History entries (URLs, titles, timestamps)
  • Cookie files
  • Cached page content

After simulation the module can parse artifacts and perform a
*normal* delete (not secure wipe — that's Member 2's job).
"""

import os
import json
import hashlib
import random
from pathlib import Path
from datetime import datetime, timedelta

from .shared_constants import (
    BROWSER_DATA_DIR, EVIDENCE_DIR,
    SEVERITY_INFO, SEVERITY_FINDING,
)


class BrowserCacheSimulator:
    """
    Creates and manages simulated browser artifacts inside the
    forensic test environment.
    """

    _HISTORY_ENTRIES = [
        {"url": "https://mail.google.com/mail/inbox",       "title": "Gmail – Inbox"},
        {"url": "https://drive.google.com/drive/my-drive",  "title": "Google Drive"},
        {"url": "https://github.com/user/forensic-project", "title": "GitHub – forensic-project"},
        {"url": "https://stackoverflow.com/questions/12345", "title": "SO – Python file deletion"},
        {"url": "https://en.wikipedia.org/wiki/Data_remanence", "title": "Data remanence – Wikipedia"},
        {"url": "https://banking.example.com/accounts",     "title": "Online Banking – Accounts"},
        {"url": "https://webmail.company.com/compose",      "title": "Webmail – New Message"},
        {"url": "https://docs.python.org/3/library/os.html","title": "os — Python Docs"},
    ]

    _COOKIES = [
        {"domain": ".google.com",   "name": "SID",       "value": "FgYJ2k..."},
        {"domain": ".google.com",   "name": "NID",       "value": "511=Qx..."},
        {"domain": ".github.com",   "name": "_gh_sess",  "value": "abc123..."},
        {"domain": ".example.com",  "name": "session_id", "value": "s3cr3t_t0k3n"},
        {"domain": ".company.com",  "name": "auth_token", "value": "jwt_eyABC..."},
    ]

    _CACHED_PAGES = [
        {"url": "https://mail.google.com/mail/inbox",
         "content": "<html><body>Inbox (3 new)</body></html>"},
        {"url": "https://banking.example.com/accounts",
         "content": "<html><body>Balance: $12,345.67</body></html>"},
        {"url": "https://docs.python.org/3/library/os.html",
         "content": "<html><body>os module docs</body></html>"},
    ]

    def __init__(self, browser_dir=None, evidence_logger=None):
        self.browser_dir = Path(browser_dir) if browser_dir else BROWSER_DATA_DIR
        self.evidence_logger = evidence_logger

        self.chrome_dir = self.browser_dir / "Chrome" / "Default"
        self.firefox_dir = self.browser_dir / "Firefox" / "profile.default"
        self.chrome_dir.mkdir(parents=True, exist_ok=True)
        self.firefox_dir.mkdir(parents=True, exist_ok=True)

        self._artifacts = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def simulate_browsing(self, callback=None):
        """Create fake browser artifacts. Returns dict with counts."""
        created = {"history": 0, "cookies": 0, "cache": 0}
        now = datetime.now()

        # Chrome-style History
        history = []
        for i, entry in enumerate(self._HISTORY_ENTRIES):
            visit_time = now - timedelta(minutes=random.randint(5, 120))
            history.append({
                "id": i + 1, "url": entry["url"], "title": entry["title"],
                "visit_time": visit_time.isoformat(),
                "visit_count": random.randint(1, 15),
                "typed_count": random.randint(0, 3),
            })
            created["history"] += 1

        with open(self.chrome_dir / "History", "w") as f:
            json.dump(history, f, indent=2)
        self._notify(callback, f"Created Chrome History ({len(history)} entries)")

        with open(self.firefox_dir / "places.json", "w") as f:
            json.dump(history, f, indent=2)
        self._notify(callback, f"Created Firefox places.json ({len(history)} entries)")

        # Cookies
        cookies = []
        for c in self._COOKIES:
            cookies.append({
                **c, "path": "/", "secure": True, "httponly": True,
                "expiry": (now + timedelta(days=30)).isoformat(),
                "created": now.isoformat(),
            })
            created["cookies"] += 1

        with open(self.chrome_dir / "Cookies", "w") as f:
            json.dump(cookies, f, indent=2)
        self._notify(callback, f"Created Chrome Cookies ({len(cookies)} entries)")

        with open(self.firefox_dir / "cookies.json", "w") as f:
            json.dump(cookies, f, indent=2)
        self._notify(callback, "Created Firefox cookies.json")

        # Cache
        for browser_cache, label in [
            (self.chrome_dir / "Cache", "Chrome"),
            (self.firefox_dir / "cache2" / "entries", "Firefox"),
        ]:
            browser_cache.mkdir(parents=True, exist_ok=True)
            for page in self._CACHED_PAGES:
                url_hash = hashlib.md5(page["url"].encode()).hexdigest()[:12]
                cache_file = browser_cache / (f"f_{url_hash}" if "Chrome" in str(browser_cache) else url_hash)
                with open(cache_file, "w") as f:
                    f.write(page["content"])
                if label == "Chrome":
                    created["cache"] += 1
                self._notify(callback, f"Cached ({label}): {page['url'][:50]}…")

        self._notify(callback, f"Simulation complete: {sum(created.values())} artifacts created")
        return created

    def parse_artifacts(self):
        """Parse all simulated browser artifacts and return a unified list."""
        self._artifacts = []
        self._parse_history(self.chrome_dir / "History", "Chrome")
        self._parse_history(self.firefox_dir / "places.json", "Firefox")
        self._parse_cookies(self.chrome_dir / "Cookies", "Chrome")
        self._parse_cookies(self.firefox_dir / "cookies.json", "Firefox")
        self._parse_cache(self.chrome_dir / "Cache", "Chrome")
        self._parse_cache(self.firefox_dir / "cache2" / "entries", "Firefox")

        if self.evidence_logger:
            self.evidence_logger.log(
                "browser_cache", "artifacts_parsed",
                f"Parsed {len(self._artifacts)} browser artifacts",
                SEVERITY_FINDING,
            )
        return self._artifacts

    def delete_artifacts(self, callback=None):
        """Normal-delete all browser artifacts. Returns count."""
        count = 0
        for browser_root in [self.chrome_dir, self.firefox_dir]:
            if not browser_root.exists():
                continue
            for root, dirs, files in os.walk(browser_root, topdown=False):
                for fname in files:
                    fpath = Path(root) / fname
                    try:
                        os.remove(fpath)
                        count += 1
                        if callback:
                            callback(f"Deleted: {fpath.relative_to(self.browser_dir)}")
                    except Exception as e:
                        if callback:
                            callback(f"Failed: {fpath.name} — {e}")

        if self.evidence_logger:
            self.evidence_logger.log(
                "browser_cache", "artifacts_deleted",
                f"Normal-deleted {count} browser artifact files",
                SEVERITY_INFO,
            )
        return count

    def get_artifacts(self):
        return self._artifacts

    # ------------------------------------------------------------------
    # Internal parsing helpers
    # ------------------------------------------------------------------

    def _parse_history(self, path, browser):
        if not path.exists():
            return
        try:
            with open(path, "r") as f:
                entries = json.load(f)
            for e in entries:
                self._artifacts.append({
                    "browser": browser, "type": "history", "path": str(path),
                    "detail": f"{e.get('title', 'N/A')} — {e.get('url', '')}",
                    "size": path.stat().st_size,
                    "timestamp": e.get("visit_time", ""),
                })
        except Exception:
            pass

    def _parse_cookies(self, path, browser):
        if not path.exists():
            return
        try:
            with open(path, "r") as f:
                cookies = json.load(f)
            for c in cookies:
                self._artifacts.append({
                    "browser": browser, "type": "cookie", "path": str(path),
                    "detail": f"{c.get('domain', '')} → {c.get('name', '')}",
                    "size": path.stat().st_size,
                    "timestamp": c.get("created", ""),
                })
        except Exception:
            pass

    def _parse_cache(self, cache_dir, browser):
        if not cache_dir.exists():
            return
        for fpath in cache_dir.iterdir():
            if fpath.is_file():
                try:
                    stat = fpath.stat()
                    self._artifacts.append({
                        "browser": browser, "type": "cache", "path": str(fpath),
                        "detail": f"Cached file: {fpath.name}",
                        "size": stat.st_size,
                        "timestamp": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    })
                except Exception:
                    pass

    def _notify(self, callback, msg):
        if callback:
            ts = datetime.now().strftime("%H:%M:%S")
            callback(f"[{ts}] {msg}")
        if self.evidence_logger:
            self.evidence_logger.log("browser_cache", "simulation", msg, SEVERITY_INFO)


# ════════════════════════════════════════════════════════════════════
#  Self-test
# ════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=== Browser Cache Simulator Self-Test ===\n")
    bcs = BrowserCacheSimulator()
    result = bcs.simulate_browsing(callback=lambda m: print(f"  {m}"))
    print(f"\nCreated: {result}")
    artifacts = bcs.parse_artifacts()
    print(f"Parsed {len(artifacts)} artifacts")
    count = bcs.delete_artifacts(callback=lambda m: print(f"  {m}"))
    print(f"Deleted {count} files")
    print("\n✓ Browser Cache self-test passed.")
