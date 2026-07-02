"""
Base scanner interface and Finding data class.
All scanners must inherit from BaseScanner and implement the scan() method.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        s = s.strip().lower()
        mapping = {
            "critical": cls.CRITICAL, "crit": cls.CRITICAL,
            "high": cls.HIGH, "h": cls.HIGH,
            "medium": cls.MEDIUM, "med": cls.MEDIUM, "m": cls.MEDIUM,
            "low": cls.LOW, "l": cls.LOW,
            "info": cls.INFO, "informational": cls.INFO, "i": cls.INFO,
        }
        return mapping.get(s, cls.INFO)

    def __lt__(self, other):
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        return order.index(self) < order.index(other)


class ScannerType(str, Enum):
    SLITHER = "slither"
    MYTHRIL = "mythril"
    PATTERN = "pattern"


@dataclass
class Finding:
    """
    Unified vulnerability finding structure.
    All scanners output findings in this format.
    """
    vuln_type: str                         # e.g. "reentrancy", "tx-origin"
    severity: Severity                     # Severity level
    file: str                              # Source file path
    line: int                              # Line number (1-based)
    description: str                       # Short description
    code_snippet: str                      # The suspicious code
    scanner: ScannerType                   # Which scanner found this
    confidence: float = 0.5               # Scanner confidence 0.0-1.0
    contract_name: Optional[str] = None   # Contract name if known
    function_name: Optional[str] = None   # Function name if known
    raw_output: Optional[str] = None      # Raw scanner output for debugging
    ai_analysis: Optional[dict] = None    # AI deep analysis result (populated later)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "code_snippet": self.code_snippet,
            "scanner": self.scanner.value,
            "confidence": self.confidence,
            "contract_name": self.contract_name,
            "function_name": self.function_name,
            "ai_analysis": self.ai_analysis,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        data = data.copy()
        data["severity"] = Severity.from_str(data.get("severity", "info"))
        data["scanner"] = ScannerType(data.get("scanner", "pattern"))
        data.pop("ai_analysis", None)
        data.pop("timestamp", None)
        return cls(**{k: v for k, v in data.items()
                      if k in cls.__dataclass_fields__})


class BaseScanner(ABC):
    """
    Abstract base class for all vulnerability scanners.

    Subclasses must implement:
        - scan(source_code: str, file_path: str) -> list[Finding]
        - scanner_type property -> ScannerType
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.timeout = self.config.get("timeout", 300)

    @property
    @abstractmethod
    def scanner_type(self) -> ScannerType:
        """Return the type of this scanner."""
        ...

    @abstractmethod
    def scan(self, source_code: str, file_path: str = "<unknown>") -> list[Finding]:
        """
        Scan Solidity source code and return a list of findings.

        Args:
            source_code: The Solidity source code to analyze.
            file_path: Optional file path for reference.

        Returns:
            A list of Finding objects.
        """
        ...

    def _extract_snippet(self, source_code: str, line: int, context: int = 3) -> str:
        """Extract a code snippet around a given line number."""
        lines = source_code.split("\n")
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        snippet_lines = []
        for i in range(start, end):
            prefix = ">> " if i == line - 1 else "   "
            snippet_lines.append(f"{prefix}{i + 1:4d} | {lines[i]}")
        return "\n".join(snippet_lines)

    def __repr__(self):
        return f"<{self.__class__.__name__} enabled={self.enabled}>"
