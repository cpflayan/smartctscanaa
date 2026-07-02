"""
Local file system monitoring for Solidity contracts.
Uses watchdog to detect file changes and trigger re-scans.
"""

import logging
import os
import time
from pathlib import Path

import click
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
from watchdog.observers import Observer

from monitor.notifier import Notifier
from scanners.base_scanner import Finding

logger = logging.getLogger(__name__)


class SolidityFileHandler(FileSystemEventHandler):
    """Handles .sol file creation and modification events."""

    def __init__(self, notifier: Notifier, scan_fn, config: dict, debounce_seconds: float = 2.0):
        super().__init__()
        self.notifier = notifier
        self.scan_fn = scan_fn
        self.config = config
        self.debounce_seconds = debounce_seconds
        self._last_scan: dict[str, float] = {}

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle(event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle(event.src_path)

    def _handle(self, file_path: str):
        if not file_path.endswith(".sol"):
            return

        now = time.time()
        last = self._last_scan.get(file_path, 0)
        if now - last < self.debounce_seconds:
            return
        self._last_scan[file_path] = now

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source_code = f.read()
        except Exception as e:
            logger.warning(f"Cannot read {file_path}: {e}")
            return

        contract_name = Path(file_path).stem
        contract_info = {
            "source": "local_file",
            "file_path": os.path.abspath(file_path),
            "contract_name": contract_name,
        }

        self.notifier.notify(
            "file_changed",
            f"File changed: {file_path}",
            contract_info=contract_info,
            severity="info",
        )

        try:
            findings = self.scan_fn(source_code, file_path, self.config)
            if findings:
                max_sev = max((f.severity for f in findings), key=lambda s: s.value)
                self.notifier.notify(
                    "scan_complete",
                    f"Scan: {file_path} - {len(findings)} finding(s)",
                    findings=findings,
                    contract_info=contract_info,
                    severity=max_sev.value,
                )
            else:
                self.notifier.notify(
                    "scan_complete",
                    f"Scan: {file_path} - no issues found",
                    contract_info=contract_info,
                    severity="info",
                )
        except Exception as e:
            logger.warning(f"Scan failed for {file_path}: {e}")


class FileMonitor:
    """
    Monitors directories for .sol file changes and triggers re-scans.

    Usage:
        monitor = FileMonitor(config, notifier, scan_fn)
        monitor.watch_directory("./contracts")
        monitor.start()
        # ... later ...
        monitor.stop()
    """

    def __init__(self, config: dict, notifier: Notifier, scan_fn=None):
        self.config = config
        self.notifier = notifier
        self.scan_fn = scan_fn or self._default_scan

        monitor_cfg = config.get("monitor", {})
        self.debounce = monitor_cfg.get("file_debounce", 2.0)

        self._observer = Observer()
        self._dirs: list[str] = []

    def watch_directory(self, path: str, recursive: bool = True):
        """
        Register a directory to monitor for .sol file changes.

        Args:
            path: Directory path to watch.
            recursive: Watch subdirectories too.
        """
        abs_path = os.path.abspath(path)
        if not os.path.isdir(abs_path):
            logger.warning(f"Directory not found: {abs_path}")
            return

        handler = SolidityFileHandler(
            notifier=self.notifier,
            scan_fn=self.scan_fn,
            config=self.config,
            debounce_seconds=self.debounce,
        )

        self._observer.schedule(handler, abs_path, recursive=recursive)
        self._dirs.append(abs_path)

    def start(self):
        """Start the file observer."""
        if not self._dirs:
            click.echo("FileMonitor: no directories to watch")
            return

        self._observer.start()
        click.echo(click.style(
            f"FileMonitor started: watching {len(self._dirs)} director(ies)",
            fg="green", bold=True,
        ))
        for d in self._dirs:
            click.echo(f"  {d}")

    def stop(self):
        """Stop the file observer."""
        self._observer.stop()
        self._observer.join(timeout=5)
        click.echo("FileMonitor stopped.")

    @staticmethod
    def _default_scan(source_code: str, file_path: str, config: dict) -> list[Finding]:
        """Default scan function using pattern scanner only."""
        from scanners.pattern_scanner import PatternScanner
        scanner = PatternScanner(config.get("scanners", {}).get("pattern", {}))
        return scanner.scan(source_code, file_path)
