"""
Slither integration scanner.
Wraps Slither's Python API for static analysis of Solidity contracts.
"""

import os
import re
import subprocess
import tempfile
import logging
from typing import Optional

from .base_scanner import BaseScanner, Finding, Severity, ScannerType

logger = logging.getLogger(__name__)

# Slither severity mapping
_SLITHER_SEVERITY_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}

# Detector name to vuln_type mapping
_DETECTOR_TYPE_MAP = {
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy-no-eth",
    "reentrancy-unlimited-gas": "reentrancy-unlimited-gas",
    "reentrancy-events": "reentrancy-events",
    "unchecked-lowlevel": "unchecked-lowlevel",
    "unchecked-send": "unchecked-send",
    "suicidal": "suicidal",
    "arbitrary-send-eth": "arbitrary-send-eth",
    "arbitrary-send-erc20": "arbitrary-send-erc20",
    "controlled-delegatecall": "controlled-delegatecall",
    "tx-origin": "tx-origin",
    "shadowing-state": "shadowing-state",
    "shadowing-local": "shadowing-local",
    "locked-ether": "locked-ether",
    "missing-zero-check": "missing-zero-check",
    "solc-version": "old-solc-version",
    "pragma": "pragma-issue",
    "naming-convention": "naming-convention",
    "dead-code": "dead-code",
    "unused-return": "unused-return",
    "incorrect-equality": "incorrect-equality",
    "calls-loop": "calls-in-loop",
    "timestamp": "timestamp-dependence",
    "assembly": "inline-assembly",
    "low-level-calls": "low-level-calls",
    "write-after-write": "write-after-write",
    "boolean-cst": "boolean-constant-misuse",
    "costly-loop": "costly-loop",
    "divide-before-multiply": "divide-before-multiply",
    "erc20-interface": "erc20-interface-issue",
    "erc721-interface": "erc721-interface-issue",
    "tautology": "tautology",
    "uninitialized-local": "uninitialized-local",
    "uninitialized-state": "uninitialized-state",
    "uninitialized-storage": "uninitialized-storage",
}


class SlitherScanner(BaseScanner):
    """
    Scanner that wraps Slither for deep static analysis.
    Requires slither-analyzer to be installed: pip install slither-analyzer
    """

    @property
    def scanner_type(self) -> ScannerType:
        return ScannerType.SLITHER

    def __init__(self, config: dict = None):
        super().__init__(config)
        self._detectors = self.config.get("detectors", None)
        self._solc_path = self.config.get("solc_path", None)

    def scan(self, source_code: str, file_path: str = "<unknown>") -> list[Finding]:
        if not self.enabled:
            return []

        try:
            from slither import Slither
            from slither.exceptions import SlitherException
        except ImportError:
            logger.error(
                "Slither 未安装。请运行: pip install slither-analyzer\n"
                "或启用 --scanner pattern 模式跳过 Slither。"
            )
            return self._fallback_scan(source_code, file_path)

        solc_path = self._ensure_solc_version(source_code)

        # Write source to a temp file for Slither to process
        tmp_dir = tempfile.mkdtemp(prefix="slither_scan_")
        sol_file = os.path.join(tmp_dir, os.path.basename(file_path) if file_path != "<unknown>" else "contract.sol")
        if not sol_file.endswith(".sol"):
            sol_file += ".sol"

        try:
            with open(sol_file, "w", encoding="utf-8") as f:
                f.write(source_code)

            # Initialize Slither
            slither_kwargs = {}
            effective_solc = solc_path or self._solc_path
            if effective_solc:
                slither_kwargs["solc"] = effective_solc

            sl = Slither(sol_file, **slither_kwargs)
            findings = []

            # Register detectors (slither 0.11.5+ requires explicit registration)
            from slither.detectors import all_detectors as _all_detectors

            detector_classes = [
                getattr(_all_detectors, name)
                for name in dir(_all_detectors)
                if not name.startswith("_")
                and isinstance(getattr(_all_detectors, name), type)
            ]

            # Map ARGUMENT -> class for filtering
            arg_to_class = {cls.ARGUMENT: cls for cls in detector_classes if hasattr(cls, "ARGUMENT")}

            if self._detectors:
                selected = [arg_to_class[d] for d in self._detectors if d in arg_to_class]
            else:
                selected = detector_classes

            for cls in selected:
                try:
                    sl.register_detector(cls)
                except Exception as e:
                    logger.debug(f"Failed to register detector {cls}: {e}")

            # run_detectors returns list[list[dict]]
            all_results = sl.run_detectors()

            for result_list in all_results:
                if not isinstance(result_list, list):
                    continue
                for result in result_list:
                    finding = self._parse_slither_result(result, file_path, source_code)
                    if finding:
                        findings.append(finding)

            return findings

        except Exception as e:
            logger.warning(f"Slither analysis failed: {e}")
            return self._fallback_scan(source_code, file_path)

        finally:
            # Cleanup temp file
            try:
                if os.path.exists(sol_file):
                    os.remove(sol_file)
                os.rmdir(tmp_dir)
            except OSError:
                pass

    def _ensure_solc_version(self, source_code: str) -> Optional[str]:
        """Extract pragma version from source and ensure correct solc is available via solc-select."""
        match = re.search(r'pragma\s+solidity\s+[\^>=<]*\s*(\d+\.\d+\.\d+)', source_code)
        if not match:
            return None

        required_version = match.group(1)

        try:
            result = subprocess.run(
                ["solc-select", "install", required_version],
                capture_output=True, text=True, timeout=30,
            )
            subprocess.run(
                ["solc-select", "use", required_version],
                capture_output=True, text=True, timeout=10,
            )
            solc_path = os.path.expanduser(f"~/.solc-select/artifacts/solc-{required_version}/solc-{required_version}")
            if os.path.exists(solc_path):
                logger.info(f"Switched solc to {required_version} for compilation")
                return solc_path
        except Exception as e:
            logger.debug(f"solc-select switch to {required_version} failed: {e}")

        return None

    def _parse_slither_result(self, result, file_path: str, source_code: str) -> Optional[Finding]:
        """Convert a Slither result dict to a Finding."""
        try:
            # result is a dict with keys: description, elements, impact, confidence, check, id
            description = result.get("description", "")
            impact = result.get("impact", "Informational")
            confidence_str = result.get("confidence", "Medium")
            check_id = result.get("check", "unknown")

            severity = _SLITHER_SEVERITY_MAP.get(impact, Severity.INFO)
            confidence_map = {"High": 0.9, "Medium": 0.7, "Low": 0.5}
            confidence = confidence_map.get(confidence_str, 0.5)
            vuln_type = _DETECTOR_TYPE_MAP.get(check_id, check_id)

            # Extract line info from elements
            line_num = 1
            contract_name = None
            function_name = None
            actual_file = file_path

            elements = result.get("elements", [])
            for elem in elements:
                source_mapping = elem.get("source_mapping", {})
                if source_mapping:
                    lines = source_mapping.get("lines", [])
                    if lines:
                        line_num = lines[0]
                    filename = source_mapping.get("filename_short", "")
                    if filename:
                        actual_file = filename

                elem_type = elem.get("type", "")
                if elem_type == "contract":
                    contract_name = elem.get("name", None)
                elif elem_type == "function":
                    function_name = elem.get("name", None)

                if line_num > 1:
                    break  # Use first meaningful location

            snippet = self._extract_snippet(source_code, line_num)

            return Finding(
                vuln_type=vuln_type,
                severity=severity,
                file=actual_file,
                line=line_num,
                description=description.strip(),
                code_snippet=snippet,
                scanner=self.scanner_type,
                confidence=confidence,
                contract_name=contract_name,
                function_name=function_name,
                raw_output=str(result),
            )
        except Exception as e:
            logger.debug(f"Failed to parse Slither result: {e}")
            return None

    def _fallback_scan(self, source_code: str, file_path: str) -> list[Finding]:
        """
        Fallback: invoke slither via CLI subprocess if Python API fails.
        Useful when Slither is installed as a CLI tool but not as a library.
        """
        import subprocess
        import json

        tmp_dir = tempfile.mkdtemp(prefix="slither_fb_")
        sol_file = os.path.join(tmp_dir, "contract.sol")

        try:
            with open(sol_file, "w", encoding="utf-8") as f:
                f.write(source_code)

            cmd = ["slither", sol_file, "--json", "-"]
            if self._detectors:
                cmd.extend(["--detect", ",".join(self._detectors)])

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            try:
                output = json.loads(proc.stdout)
            except json.JSONDecodeError:
                logger.warning("Slither CLI output is not valid JSON")
                return []

            results = output.get("results", {}).get("detectors", [])
            findings = []
            for r in results:
                finding = self._parse_cli_result(r, file_path, source_code)
                if finding:
                    findings.append(finding)
            return findings

        except FileNotFoundError:
            logger.error("slither 命令未找到，请安装: pip install slither-analyzer")
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"Slither 超时 (>{self.timeout}s)")
            return []
        except Exception as e:
            logger.warning(f"Slither CLI fallback failed: {e}")
            return []
        finally:
            try:
                if os.path.exists(sol_file):
                    os.remove(sol_file)
                os.rmdir(tmp_dir)
            except OSError:
                pass

    def _parse_cli_result(self, result: dict, file_path: str, source_code: str) -> Optional[Finding]:
        """Parse a Slither CLI JSON detector result."""
        try:
            description = result.get("description", "")
            impact = result.get("impact", "Informational")
            confidence_str = result.get("confidence", "Medium")
            check = result.get("check", "unknown")

            severity = _SLITHER_SEVERITY_MAP.get(impact, Severity.INFO)
            confidence_map = {"High": 0.9, "Medium": 0.7, "Low": 0.5}
            confidence = confidence_map.get(confidence_str, 0.5)
            vuln_type = _DETECTOR_TYPE_MAP.get(check, check)

            elements = result.get("elements", [])
            line_num = 1
            contract_name = None
            function_name = None

            for elem in elements:
                sm = elem.get("source_mapping", {})
                lines = sm.get("lines", [])
                if lines:
                    line_num = lines[0]
                if elem.get("type") == "contract":
                    contract_name = elem.get("name")
                elif elem.get("type") == "function":
                    function_name = elem.get("name")
                if line_num > 1:
                    break

            snippet = self._extract_snippet(source_code, line_num)
            return Finding(
                vuln_type=vuln_type,
                severity=severity,
                file=file_path,
                line=line_num,
                description=description.strip(),
                code_snippet=snippet,
                scanner=self.scanner_type,
                confidence=confidence,
                contract_name=contract_name,
                function_name=function_name,
                raw_output=str(result),
            )
        except Exception as e:
            logger.debug(f"Failed to parse CLI result: {e}")
            return None
