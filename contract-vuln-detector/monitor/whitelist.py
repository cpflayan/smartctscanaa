"""
Whitelist manager for monitored contracts.
Contracts that pass deep scanning with no issues are auto-added to the whitelist.
Whitelisted contracts are skipped in future scans.
"""

import json
import logging
import os
import threading
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class Whitelist:
    """
    Thread-safe whitelist manager with JSON file persistence.

    Whitelist entries are keyed by "chain:address" (address lowercased).
    Each entry stores: address, chain, added_at, reason, scan_summary.
    """

    def __init__(self, filepath: str = "./reports/whitelist.json"):
        self.filepath = filepath
        self._lock = threading.Lock()
        self._entries: dict[str, dict] = {}
        self._load()

    def _load(self):
        """Load whitelist from JSON file."""
        if not os.path.exists(self.filepath):
            return
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._entries = data
            logger.info(f"Loaded {len(self._entries)} whitelist entries")
        except Exception as e:
            logger.warning(f"Failed to load whitelist: {e}")

    def _save(self):
        """Persist whitelist to JSON file."""
        try:
            os.makedirs(os.path.dirname(self.filepath) or ".", exist_ok=True)
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self._entries, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"Failed to save whitelist: {e}")

    @staticmethod
    def _key(address: str, chain: str) -> str:
        return f"{chain}:{address.lower()}"

    def is_whitelisted(self, address: str, chain: str) -> bool:
        """Check if a contract is whitelisted."""
        key = self._key(address, chain)
        with self._lock:
            return key in self._entries

    def add(
        self,
        address: str,
        chain: str,
        reason: str = "clean_scan",
        scan_summary: dict = None,
        contract_name: str = None,
    ) -> bool:
        """
        Add a contract to the whitelist.

        Returns True if newly added, False if already present.
        """
        key = self._key(address, chain)
        with self._lock:
            if key in self._entries:
                return False
            self._entries[key] = {
                "address": address.lower(),
                "chain": chain,
                "contract_name": contract_name or "unknown",
                "added_at": datetime.now().isoformat(),
                "reason": reason,
                "scan_summary": scan_summary or {},
            }
            self._save()
        return True

    def remove(self, address: str, chain: str) -> bool:
        """Remove a contract from the whitelist. Returns True if removed."""
        key = self._key(address, chain)
        with self._lock:
            if key not in self._entries:
                return False
            del self._entries[key]
            self._save()
        return True

    def list_all(self, chain: str = None) -> list[dict]:
        """List all whitelist entries, optionally filtered by chain."""
        with self._lock:
            entries = list(self._entries.values())
        if chain:
            entries = [e for e in entries if e["chain"] == chain]
        return entries

    def clear(self, chain: str = None):
        """Clear whitelist. If chain given, only clear that chain."""
        with self._lock:
            if chain:
                self._entries = {
                    k: v for k, v in self._entries.items()
                    if v.get("chain") != chain
                }
            else:
                self._entries.clear()
            self._save()

    def count(self) -> int:
        with self._lock:
            return len(self._entries)
