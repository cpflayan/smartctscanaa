"""
Mythril integration scanner.
Wraps Mythril's CLI for symbolic execution-based vulnerability detection.
"""

import json
import logging
import os
import subprocess
import tempfile
from typing import Optional

from .base_scanner import BaseScanner, Finding, Severity, ScannerType

logger = logging.getLogger(__name__)

# Mythril SWC-ID to vuln_type mapping
_SWC_MAP = {
    "SWC-101": "integer-overflow",
    "SWC-102": "tx-origin-auth",
    "SWC-103": "tx-origin-auth",
    "SWC-104": "unchecked-call",
    "SWC-105": "unprotected-ether-withdrawal",
    "SWC-106": "unprotected-selfdestruct",
    "SWC-107": "reentrancy",
    "SWC-108": "state-variable-default-visibility",
    "SWC-109": "uninitialized-storage",
    "SWC-110": "assert-violation",
    "SWC-111": "use-of-deprecated-functions",
    "SWC-112": "delegatecall-to-untrusted-contract",
    "SWC-113": "dos-gas-limit",
    "SWC-114": "transaction-ordering-dependence",
    "SWC-115": "authorization-through-tx-origin",
    "SWC-116": "block-values-as-time-proxy",
    "SWC-117": "signature-malleability",
    "SWC-118": "incorrect-inheritance-order",
    "SWC-119": "shadowing-state-variables",
    "SWC-120": "weak-randomness",
    "SWC-121": "missing-protection-against-signature-replay",
    "SWC-122": "lack-of-proper-signature-verification",
    "SWC-124": "write-to-arbitrary-storage-location",
    "SWC-125": "incorrect-inheritance-order",
    "SWC-127": "arbitrary-jump-with-function-type-variable",
    "SWC-128": "dos-with-block-gas-limit",
    "SWC-129": "typographical-error",
    "SWC-130": "right-to-left-override-character",
    "SWC-132": "unexpected-ether-balance",
    "SWC-133": "hash-collision",
    "SWC-134": "message-call-with-1023-gas",
    "SWC-135": "code-with-no-effects",
    "SWC-136": "unencrypted-private-data",
}

# Mythril severity titles to our Severity
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}


class MythrilScanner(BaseScanner):
    """
    Scanner that wraps Mythril CLI for symbolic execution analysis.
    Requires mythril to be installed: pip install mythril
    """

    @property
    def scanner_type(self) -> ScannerType:
        return ScannerType.MYTHRIL

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.strategy = self.config.get("strategy", "bfs")
        self.max_depth = self.config.get("max_depth", 100)
        self.execution_timeout = self.config.get("execution_timeout", 300)

    def scan(self, source_code: str, file_path: str = "<unknown>") -> list[Finding]:
        if not self.enabled:
            return []

        tmp_dir = tempfile.mkdtemp(prefix="mythril_scan_")
        sol_file = os.path.join(tmp_dir, "contract.sol")

        try:
            with open(sol_file, "w", encoding="utf-8") as f:
                f.write(source_code)

            json_out = os.path.join(tmp_dir, "output.json")

            cmd = [
                "myth", "analyze", sol_file,
                "--execution-timeout", str(self.execution_timeout),
                "--strategy", self.strategy,
                "--max-depth", str(self.max_depth),
                "-o", "json",
                "-j", json_out,
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # Mythril writes JSON to stdout or file depending on version
            mythril_output = None
            if os.path.exists(json_out):
                with open(json_out, "r", encoding="utf-8") as f:
                    mythril_output = json.load(f)
            else:
                # Try parsing stdout
                try:
                    mythril_output = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    # Sometimes mythril prints non-JSON to stdout
                    if proc.returncode != 0:
                        logger.warning(f"Mythril failed (exit {proc.returncode}): {proc.stderr[:200]}")
                    return self._parse_text_output(proc.stdout, file_path, source_code)

            return self._parse_json_output(mythril_output, file_path, source_code)

        except FileNotFoundError:
            logger.error(
                "myth 命令未找到。请安装: pip install mythril\n"
                "或使用 --scanner pattern 跳过 Mythril。"
            )
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"Mythril 超时 (>{self.timeout}s)，这是常见现象，建议使用 Slither + Pattern 替代。")
            return []
        except Exception as e:
            logger.warning(f"Mythril analysis failed: {e}")
            return []
        finally:
            try:
                for fn in os.listdir(tmp_dir):
                    os.remove(os.path.join(tmp_dir, fn))
                os.rmdir(tmp_dir)
            except OSError:
                pass

    def _parse_json_output(self, output: dict, file_path: str, source_code: str) -> list[Finding]:
        """Parse Mythril JSON output into Findings."""
        findings = []
        issues = output.get("issues", [])

        for issue in issues:
            finding = self._parse_issue(issue, file_path, source_code)
            if finding:
                findings.append(finding)

        return findings

    def _parse_issue(self, issue: dict, file_path: str, source_code: str) -> Optional[Finding]:
        """Convert a single Mythril issue to a Finding."""
        try:
            title = issue.get("title", "Unknown Issue")
            description = issue.get("description", "")
            swc_id = issue.get("swc-id", "")
            severity_str = issue.get("severity", "medium").lower()

            severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
            vuln_type = _SWC_MAP.get(swc_id, swc_id.lower().replace("-", "-") or title.lower().replace(" ", "-"))

            # Extract location
            line_num = issue.get("lineno", 1)
            if isinstance(line_num, str):
                try:
                    line_num = int(line_num)
                except ValueError:
                    line_num = 1

            # Sometimes address/offset are provided instead of line numbers
            code_hash = issue.get("code_hash", "")
            contract_name = issue.get("contract", None)
            function_name = issue.get("function", None)

            snippet = self._extract_snippet(source_code, line_num)

            return Finding(
                vuln_type=vuln_type,
                severity=severity,
                file=file_path,
                line=line_num,
                description=f"[{title}] {description}".strip(),
                code_snippet=snippet,
                scanner=self.scanner_type,
                confidence=0.75,
                contract_name=contract_name,
                function_name=function_name,
                raw_output=json.dumps(issue, ensure_ascii=False),
            )
        except Exception as e:
            logger.debug(f"Failed to parse Mythril issue: {e}")
            return None

    def _parse_text_output(self, stdout: str, file_path: str, source_code: str) -> list[Finding]:
        """
        Fallback parser for Mythril text output when JSON is not available.
        Extracts issues from the human-readable text format.
        """
        findings = []
        import re

        # Mythril text output pattern:
        # ==== <Type> ====
        # SWC ID: <id>
        # Severity: <sev>
        # Contract: <name>
        # Function name: <name>
        # <description>
        issue_pattern = re.compile(
            r"====\s+(.+?)\s+====\s*\n"
            r"(?:SWC ID:\s*(\S+)\s*\n)?"
            r"(?:Severity:\s*(\w+)\s*\n)?"
            r"(?:Contract:\s*(\w+)\s*\n)?"
            r"(?:Function name:\s*(\w+)\s*\n)?"
            r"(.+?)(?=\n====|$)",
            re.DOTALL
        )

        for match in issue_pattern.finditer(stdout):
            title = match.group(1).strip()
            swc_id = match.group(2) or ""
            severity_str = (match.group(3) or "medium").lower()
            contract_name = match.group(4)
            function_name = match.group(5)
            description = match.group(6).strip()

            severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
            vuln_type = _SWC_MAP.get(swc_id, title.lower().replace(" ", "-"))

            findings.append(Finding(
                vuln_type=vuln_type,
                severity=severity,
                file=file_path,
                line=1,
                description=f"[{title}] {description}",
                code_snippet=self._extract_snippet(source_code, 1),
                scanner=self.scanner_type,
                confidence=0.65,
                contract_name=contract_name,
                function_name=function_name,
                raw_output=match.group(0),
            ))

        return findings
