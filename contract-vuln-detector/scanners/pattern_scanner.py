"""
Pattern-based vulnerability scanner.
Uses regex and heuristic rules to quickly identify suspicious code patterns.
Lightweight — runs first to catch what static analyzers may miss.
"""

import re
from typing import Optional

from .base_scanner import BaseScanner, Finding, Severity, ScannerType


# ─── Rule Definitions ────────────────────────────────────────────────────────────
# Each rule: (pattern_regex, vuln_type, severity, description, confidence)
# Patterns are applied line-by-line; first capturing group (if any) is highlighted.

VULN_RULES = [
    # ── Critical / High ──────────────────────────────────────────────────────────
    (
        r"tx\.origin",
        "tx-origin-auth",
        Severity.HIGH,
        "使用 tx.origin 进行身份验证，存在钓鱼攻击风险。应改用 msg.sender。",
        0.85,
    ),
    (
        r"selfdestruct\s*\(",
        "selfdestruct",
        Severity.HIGH,
        "使用了 selfdestruct，可能导致合约资金被强制销毁且无法恢复。",
        0.90,
    ),
    (
        r"delegatecall\s*\(",
        "controlled-delegatecall",
        Severity.HIGH,
        "使用了 delegatecall，如果目标地址可控则存在代码注入风险。",
        0.80,
    ),
    (
        r"suicide\s*\(",
        "selfdestruct-alias",
        Severity.HIGH,
        "使用了 suicide（selfdestruct 的旧别名），合约可被销毁。",
        0.90,
    ),

    # ── Reentrancy Indicators ─────────────────────────────────────────────────────
    (
        r"\.call\{value:\s*[^}]+\}\s*\(",
        "reentrancy-risk",
        Severity.MEDIUM,
        "外部 .call{value: ...} 调用，如状态更新在调用之后则存在重入风险。",
        0.60,
    ),
    (
        r"\.call\.value\s*\(",
        "reentrancy-risk-old",
        Severity.MEDIUM,
        "旧语法 .call.value() 调用，在 Solidity 0.6+ 已弃用，且存在重入风险。",
        0.65,
    ),
    (
        r"\.send\s*\(",
        "unchecked-send",
        Severity.MEDIUM,
        ".send() 调用未检查返回值，失败时不会 revert。应检查返回值或使用 .transfer()。",
        0.75,
    ),
    (
        r"\.transfer\s*\(",
        "transfer-risk",
        Severity.LOW,
        ".transfer() 有 2300 gas 限制，在接收方为合约时可能失败。",
        0.45,
    ),

    # ── Timestamp / Block Dependence ──────────────────────────────────────────────
    (
        r"block\.timestamp",
        "timestamp-dependence",
        Severity.LOW,
        "依赖 block.timestamp，矿工可在一定范围内操纵时间戳。",
        0.50,
    ),
    (
        r"block\.number",
        "block-number-dependence",
        Severity.LOW,
        "依赖 block.number，可能在分叉或重组时产生意外行为。",
        0.40,
    ),
    (
        r"blockhash\s*\(",
        "blockhash-usage",
        Severity.LOW,
        "使用 blockhash()，只能获取最近 256 个区块的哈希，超出范围返回 0。",
        0.45,
    ),

    # ── Access Control ────────────────────────────────────────────────────────────
    (
        r"function\s+\w+\s*\([^)]*\)\s+(?:external|public)\s+(?!.*(?:onlyOwner|onlyAdmin|onlyRole|whenNotPaused|nonReentrant|onlyGovernance|auth|restricted))",
        "missing-access-control",
        Severity.MEDIUM,
        "external/public 函数缺少常见访问控制修饰符，需人工确认权限管理是否完善。",
        0.55,
    ),

    # ── Unchecked Returns ─────────────────────────────────────────────────────────
    (
        r"(?<!require\()(?<!assert\()\.call\s*\(",
        "unchecked-call",
        Severity.MEDIUM,
        "低级别 .call() 返回值未被 require/assert 检查。",
        0.60,
    ),

    # ── Hardcoded Addresses ───────────────────────────────────────────────────────
    (
        r"0x[0-9a-fA-F]{40}",
        "hardcoded-address",
        Severity.INFO,
        "发现硬编码地址，建议使用常量或构造函数参数，便于部署到不同网络。",
        0.70,
    ),

    # ── Deprecated / Dangerous Functions ───────────────────────────────────────────
    (
        r"\bsha3\s*\(",
        "deprecated-sha3",
        Severity.LOW,
        "sha3() 已弃用，应改用 keccak256()。",
        0.90,
    ),
    (
        r"\bthrow\b",
        "deprecated-throw",
        Severity.LOW,
        "throw 已弃用，应改用 revert()。",
        0.90,
    ),
    (
        r"\bsuicide\b",
        "deprecated-suicide",
        Severity.LOW,
        "suicide 关键字已弃用，应使用 selfdestruct。",
        0.85,
    ),

    # ── Visibility Issues ─────────────────────────────────────────────────────────
    (
        r"function\s+\w+\s*\([^)]*\)\s*\{",
        "default-visibility",
        Severity.MEDIUM,
        "函数未声明可见性修饰符（默认 public），可能导致意外暴露。",
        0.65,
    ),

    # ── Assembly Usage ────────────────────────────────────────────────────────────
    (
        r"\bassembly\s*\{",
        "inline-assembly",
        Severity.INFO,
        "使用了内联汇编，增加了代码复杂度和潜在风险，需仔细审计。",
        0.50,
    ),

    # ── Randomness ────────────────────────────────────────────────────────────────
    (
        r"block\.difficulty",
        "weak-randomness",
        Severity.MEDIUM,
        "使用 block.difficulty 作为随机源，可被矿工预测/操纵。",
        0.70,
    ),
    (
        r"uint256\s+\w+\s*=\s*.*block\.(timestamp|number|difficulty)",
        "predictable-random",
        Severity.MEDIUM,
        "使用区块属性生成随机数，可被预测，不适合用于抽奖/赌博等场景。",
        0.75,
    ),

    # ── Integer Overflow (pre-0.8.0) ──────────────────────────────────────────────
    (
        r"pragma\s+solidity\s*[<^]?\s*0\.[0-7]\.",
        "old-solidity-version",
        Severity.LOW,
        "使用 Solidity 0.8.0 之前版本，整数运算未内置溢出检查。",
        0.60,
    ),

    # ── Flash Loan Attack Vectors ─────────────────────────────────────────────────
    (
        r"(?i)flash.?loan|flashLoan|flashloan",
        "flash-loan-related",
        Severity.INFO,
        "代码涉及闪电贷，需确保价格预言机和回调逻辑安全。",
        0.50,
    ),

    # ── Price Oracle Issues ───────────────────────────────────────────────────────
    (
        r"getReserves\s*\(\s*\)",
        "uniswap-reserve-oracle",
        Severity.MEDIUM,
        "直接使用 Uniswap getReserves() 作为价格源，存在闪电贷操纵风险。应使用 TWAP 或 Chainlink。",
        0.65,
    ),
]

# ── Rules that need multi-line context ────────────────────────────────────────────
MULTILINE_RULES = [
    (
        # State variable shadowing: local var with same name as state var
        r"contract\s+(\w+)\s*[^{]*\{([^}]*?(?:uint|int|address|bool|string|bytes)\s+(?:public|private|internal)?\s*(\w+)\s*[^;]*;[^}]*)\}",
        "state-shadowing",
        Severity.MEDIUM,
        "可能存在状态变量影子问题，局部变量与状态变量同名可能导致逻辑错误。",
        0.50,
    ),
]


class PatternScanner(BaseScanner):
    """
    Lightweight regex-based scanner for quick vulnerability pattern matching.
    Designed to complement (not replace) Slither and Mythril.
    """

    @property
    def scanner_type(self) -> ScannerType:
        return ScannerType.PATTERN

    def scan(self, source_code: str, file_path: str = "<unknown>") -> list[Finding]:
        if not self.enabled:
            return []

        findings: list[Finding] = []
        lines = source_code.split("\n")

        # Track context for smarter findings
        contract_name = self._extract_contract_name(source_code)
        pragma_version = self._extract_pragma(source_code)

        for line_num, line in enumerate(lines, start=1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            for pattern, vuln_type, severity, description, confidence in VULN_RULES:
                try:
                    match = re.search(pattern, line)
                except re.error:
                    continue

                if match:
                    # Special filtering: skip old-solidity-version if we already found pragma >= 0.8
                    if vuln_type == "old-solidity-version" and pragma_version:
                        major, minor = pragma_version
                        if major >= 0 and minor >= 8:
                            continue

                    # Skip hardcoded-address for zero address
                    if vuln_type == "hardcoded-address":
                        addr = match.group(0).lower()
                        if addr == "0x" + "0" * 40:
                            continue

                    # Skip default-visibility if there's a modifier on same line
                    if vuln_type == "default-visibility":
                        if any(kw in line for kw in ["public", "external", "internal", "private"]):
                            continue

                    snippet = self._extract_snippet(source_code, line_num)
                    func_name = self._find_enclosing_function(lines, line_num)

                    findings.append(Finding(
                        vuln_type=vuln_type,
                        severity=severity,
                        file=file_path,
                        line=line_num,
                        description=description,
                        code_snippet=snippet,
                        scanner=self.scanner_type,
                        confidence=confidence,
                        contract_name=contract_name,
                        function_name=func_name,
                        raw_output=f"Pattern match: '{match.group(0)}' on line {line_num}",
                    ))

        # Apply multiline rules
        for pattern, vuln_type, severity, description, confidence in MULTILINE_RULES:
            try:
                for match in re.finditer(pattern, source_code, re.DOTALL):
                    line_num = source_code[:match.start()].count("\n") + 1
                    snippet = self._extract_snippet(source_code, line_num, context=5)
                    findings.append(Finding(
                        vuln_type=vuln_type,
                        severity=severity,
                        file=file_path,
                        line=line_num,
                        description=description,
                        code_snippet=snippet,
                        scanner=self.scanner_type,
                        confidence=confidence,
                        contract_name=contract_name,
                        raw_output=f"Multiline pattern match at offset {match.start()}",
                    ))
            except re.error:
                pass

        return self._deduplicate(findings)

    # ── Helpers ────────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_contract_name(source_code: str) -> Optional[str]:
        """Extract the primary contract name from source."""
        m = re.search(r"contract\s+(\w+)", source_code)
        return m.group(1) if m else None

    @staticmethod
    def _extract_pragma(source_code: str) -> Optional[tuple]:
        """Extract Solidity version from pragma as (major, minor) tuple."""
        m = re.search(r"pragma\s+solidity\s*[><^~]*\s*(\d+)\.(\d+)", source_code)
        if m:
            return (int(m.group(1)), int(m.group(2)))
        return None

    @staticmethod
    def _find_enclosing_function(lines: list[str], target_line: int) -> Optional[str]:
        """Find the function name that encloses the given line number."""
        func_pattern = re.compile(r"function\s+(\w+)\s*\(")
        # Scan backwards from target_line
        for i in range(min(target_line - 1, len(lines) - 1), -1, -1):
            m = func_pattern.search(lines[i])
            if m:
                return m.group(1)
        return None

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings on the same line with the same vuln_type."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.vuln_type, f.line)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
