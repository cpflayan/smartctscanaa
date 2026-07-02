"""
Unified notification system for the monitoring module.
Supports terminal output, log file, and auto-generated reports.
"""

import logging
import os
from datetime import datetime
from typing import Optional

import click

from scanners.base_scanner import Finding
from reports.report_generator import ReportGenerator
from analyzer.severity import SeverityScorer

logger = logging.getLogger(__name__)

EVENT_LABELS = {
    "source_changed": "合約原始碼變更",
    "new_event": "鏈上事件",
    "suspicious_tx": "可疑交易",
    "new_contract": "新合約部署",
    "file_changed": "本地檔案變更",
    "scan_complete": "掃描完成",
    "whitelist_added": "已加入白名單",
    "whitelist_skipped": "白名單跳過",
    "tx_deep_scan": "交易觸發深度掃描",
}

SEVERITY_COLORS = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "blue",
}


class Notifier:
    """
    Unified notification dispatcher.
    Sends alerts to terminal, log file, and/or report generator.
    """

    def __init__(self, config: dict = None, output_dir: str = "./reports", log_file: str = None):
        self.config = config or {}
        self.output_dir = output_dir
        self._setup_file_logger(log_file)

    def _setup_file_logger(self, log_file: str = None):
        """Set up a dedicated file logger for monitor events."""
        self._file_logger = logging.getLogger("monitor.events")
        self._file_logger.setLevel(logging.INFO)
        self._file_logger.propagate = False

        if log_file:
            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
            handler = logging.FileHandler(log_file, encoding="utf-8")
            handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
            self._file_logger.addHandler(handler)

    def notify(
        self,
        event_type: str,
        message: str,
        findings: list[Finding] = None,
        contract_info: dict = None,
        severity: str = "info",
    ):
        """
        Dispatch a notification to all configured outputs.

        Args:
            event_type: One of source_changed, new_event, suspicious_tx,
                        new_contract, file_changed, scan_complete.
            message: Human-readable description.
            findings: Optional list of Finding objects from a scan.
            contract_info: Optional contract metadata dict.
            severity: critical/high/medium/low/info.
        """
        label = EVENT_LABELS.get(event_type, event_type)
        timestamp = datetime.now().strftime("%H:%M:%S")

        self._notify_terminal(label, message, findings, severity, timestamp)
        self._notify_log(label, message, findings, severity)

        if findings:
            self._notify_report(findings, contract_info, event_type)

    def _notify_terminal(
        self, label: str, message: str, findings: list[Finding],
        severity: str, timestamp: str,
    ):
        """Print alert to terminal with color."""
        color = SEVERITY_COLORS.get(severity, "white")
        icon = {"critical": "!!", "high": "!", "medium": "~", "low": "-", "info": "i"}.get(severity, " ")

        click.echo("")
        click.echo(click.style(
            f"[{timestamp}] [{icon}] {label}: {message}",
            fg=color, bold=True,
        ))

        if findings:
            by_sev = {}
            for f in findings:
                sev = f.severity.value
                by_sev[sev] = by_sev.get(sev, 0) + 1
            parts = [f"{s.upper()}:{c}" for s, c in sorted(by_sev.items())]
            click.echo(f"  Findings: {len(findings)} ({', '.join(parts)})")

            for f in findings[:5]:
                sev_color = SEVERITY_COLORS.get(f.severity.value, "white")
                click.echo(click.style(
                    f"    [{f.severity.value.upper()}] {f.vuln_type} @ line {f.line}",
                    fg=sev_color,
                ))
            if len(findings) > 5:
                click.echo(f"    ... and {len(findings) - 5} more")

    def _notify_log(self, label: str, message: str, findings: list[Finding], severity: str):
        """Write alert to log file."""
        log_level = {
            "critical": logging.CRITICAL,
            "high": logging.ERROR,
            "medium": logging.WARNING,
            "low": logging.INFO,
            "info": logging.INFO,
        }.get(severity, logging.INFO)

        self._file_logger.log(log_level, f"[{severity.upper()}] {label}: {message}")
        if findings:
            for f in findings:
                self._file_logger.log(
                    log_level,
                    f"  [{f.severity.value.upper()}] {f.vuln_type} @ line {f.line} - {f.description[:80]}",
                )

    def _notify_report(self, findings: list[Finding], contract_info: dict, event_type: str):
        """Generate a scan report."""
        if not contract_info:
            contract_info = {"source": "monitor"}

        try:
            scorer = SeverityScorer()
            scored = scorer.rank_findings(findings)
            stats = scorer.summary_stats(scored)

            report_config = self.config.get("reports", {})
            report_config["output_dir"] = self.output_dir
            generator = ReportGenerator(report_config)

            contract_name = contract_info.get("contract_name", "unknown")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_name = f"monitor_{contract_name}_{event_type}_{ts}"

            batch_summary = {
                "overall_risk": "unknown",
                "summary": f"Monitor-triggered scan ({event_type})",
                "critical_issues": [],
                "recommendations_priority": [],
                "contract_hardening_suggestions": [],
            }

            generated = generator.generate(
                findings=findings,
                batch_summary=batch_summary,
                scored_results=scored,
                contract_info=contract_info,
                output_name=output_name,
            )

            paths = ", ".join(generated.values())
            self._file_logger.info(f"Report generated: {paths}")
            click.echo(click.style(f"  Report: {paths}", fg="cyan"))

        except Exception as e:
            logger.warning(f"Failed to generate monitor report: {e}")
