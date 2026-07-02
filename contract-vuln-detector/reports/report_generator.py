"""
Report generator module.
Produces structured vulnerability reports in JSON and Markdown formats.
"""

import json
import logging
import os
from datetime import datetime
from typing import Optional

from scanners.base_scanner import Finding, Severity

logger = logging.getLogger(__name__)

# Severity display order and symbols
SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "🔵",
}


class ReportGenerator:
    """
    Generates vulnerability reports from analyzed findings.

    Output formats:
    - JSON: Machine-readable, for CI/CD pipelines
    - Markdown: Human-readable, for audit reports
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.output_dir = self.config.get("output_dir", "./reports")
        self.formats = self.config.get("formats", ["json", "markdown"])
        self.include_snippets = self.config.get("include_code_snippets", True)
        self.max_snippet_lines = self.config.get("max_snippet_lines", 20)

    def generate(
        self,
        findings: list[Finding],
        batch_summary: dict,
        scored_results: list,
        contract_info: dict,
        output_name: str = None,
    ) -> dict:
        """
        Generate reports in all configured formats.

        Args:
            findings: List of Finding objects with AI analysis attached.
            batch_summary: AI-generated batch summary dict.
            scored_results: List of (Finding, score_dict) from SeverityScorer.
            contract_info: Metadata about the contract (address, chain, name, etc.).
            output_name: Base filename for reports (without extension).

        Returns:
            dict with paths of generated report files.
        """
        os.makedirs(self.output_dir, exist_ok=True)

        # Default output name based on contract
        if not output_name:
            contract_name = contract_info.get("contract_name", "unknown")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_name = f"{contract_name}_{timestamp}"

        generated_files = {}

        if "json" in self.formats:
            json_path = self._generate_json(
                findings, batch_summary, scored_results,
                contract_info, output_name
            )
            generated_files["json"] = json_path

        if "markdown" in self.formats:
            md_path = self._generate_markdown(
                findings, batch_summary, scored_results,
                contract_info, output_name
            )
            generated_files["markdown"] = md_path

        return generated_files

    def _generate_json(
        self,
        findings: list[Finding],
        batch_summary: dict,
        scored_results: list,
        contract_info: dict,
        output_name: str,
    ) -> str:
        """Generate JSON report."""
        report = {
            "report_version": "1.0",
            "generated_at": datetime.now().isoformat(),
            "generator": "contract-vuln-detector",
            "contract": contract_info,
            "summary": {
                "total_findings": len(findings),
                "batch_summary": batch_summary,
                "severity_distribution": self._count_by_severity(scored_results),
            },
            "findings": [],
        }

        for finding, score_result in scored_results:
            finding_entry = finding.to_dict()
            finding_entry["final_severity"] = score_result["severity"].value
            finding_entry["final_score"] = score_result["score"]
            finding_entry["is_confirmed"] = score_result["is_confirmed"]
            finding_entry["score_breakdown"] = score_result["breakdown"]
            report["findings"].append(finding_entry)

        path = os.path.join(self.output_dir, f"{output_name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        logger.info(f"JSON report generated: {path}")
        return path

    def _generate_markdown(
        self,
        findings: list[Finding],
        batch_summary: dict,
        scored_results: list,
        contract_info: dict,
        output_name: str,
    ) -> str:
        """Generate Markdown report."""
        lines = []

        # Header
        lines.append("# 智能合约安全审计报告")
        lines.append("")
        lines.append(f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"> 生成工具: contract-vuln-detector")
        lines.append("")

        # Contract Info
        lines.append("## 合约信息")
        lines.append("")
        lines.append(f"| 项目 | 值 |")
        lines.append(f"|------|-----|")
        for key, value in contract_info.items():
            if key in ("abi",):
                continue  # Skip large fields
            lines.append(f"| {key} | `{value}` |")
        lines.append("")

        # Summary
        lines.append("## 安全摘要")
        lines.append("")

        overall_risk = batch_summary.get("overall_risk", "unknown").upper()
        lines.append(f"**整体风险等级**: {overall_risk}")
        lines.append("")

        summary_text = batch_summary.get("summary", "无摘要")
        lines.append(f"> {summary_text}")
        lines.append("")

        # Severity distribution table
        sev_counts = self._count_by_severity(scored_results)
        lines.append("### 漏洞分布")
        lines.append("")
        lines.append("| 严重程度 | 数量 |")
        lines.append("|----------|------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            icon = SEVERITY_ICONS.get(sev, "")
            count = sev_counts.get(sev, 0)
            lines.append(f"| {icon} {sev.upper()} | {count} |")
        lines.append("")

        # Confirmed vulnerabilities
        confirmed = [
            (f, s) for f, s in scored_results if s["is_confirmed"]
        ]
        if confirmed:
            lines.append(f"### 确认漏洞: {len(confirmed)} 个")
            lines.append("")

        # Detailed Findings
        lines.append("## 详细分析")
        lines.append("")

        for i, (finding, score_result) in enumerate(scored_results, 1):
            severity = score_result["severity"].value
            icon = SEVERITY_ICONS.get(severity, "")
            is_confirmed = score_result["is_confirmed"]
            status = "✅ 确认" if is_confirmed else "❓ 待确认"

            lines.append(f"### {i}. {icon} [{severity.upper()}] {finding.vuln_type}")
            lines.append("")
            lines.append(f"- **状态**: {status}")
            lines.append(f"- **位置**: `{finding.file}` 第 {finding.line} 行")
            if finding.function_name:
                lines.append(f"- **函数**: `{finding.function_name}()`")
            if finding.contract_name:
                lines.append(f"- **合约**: `{finding.contract_name}`")
            lines.append(f"- **扫描工具**: {finding.scanner.value}")
            lines.append(f"- **综合评分**: {score_result['score']:.3f}")
            lines.append("")

            # Scanner description
            lines.append(f"**工具描述**: {finding.description}")
            lines.append("")

            # Code snippet
            if self.include_snippets and finding.code_snippet:
                lines.append("**代码片段**:")
                lines.append("```solidity")
                snippet_lines = finding.code_snippet.split("\n")[:self.max_snippet_lines]
                lines.extend(snippet_lines)
                lines.append("```")
                lines.append("")

            # AI Analysis
            ai = finding.ai_analysis
            if ai:
                if ai.get("analysis"):
                    lines.append(f"**AI 分析**: {ai['analysis']}")
                    lines.append("")

                if ai.get("attack_path"):
                    lines.append(f"**攻击路径**: {ai['attack_path']}")
                    lines.append("")

                if ai.get("impact"):
                    lines.append(f"**潜在影响**: {ai['impact']}")
                    lines.append("")

                if ai.get("fix_recommendation"):
                    lines.append(f"**修复建议**: {ai['fix_recommendation']}")
                    lines.append("")

                if ai.get("fix_code"):
                    lines.append("**修复代码**:")
                    lines.append("```solidity")
                    lines.append(ai["fix_code"])
                    lines.append("```")
                    lines.append("")

                if ai.get("references"):
                    refs = ai["references"]
                    if isinstance(refs, list) and refs:
                        lines.append("**参考资料**:")
                        for ref in refs:
                            lines.append(f"- {ref}")
                        lines.append("")

            lines.append("---")
            lines.append("")

        # Recommendations
        recs = batch_summary.get("recommendations_priority", [])
        if recs:
            lines.append("## 修复优先级建议")
            lines.append("")
            for j, rec in enumerate(recs, 1):
                lines.append(f"{j}. {rec}")
            lines.append("")

        hardening = batch_summary.get("contract_hardening_suggestions", [])
        if hardening:
            lines.append("## 合约加固建议")
            lines.append("")
            for suggestion in hardening:
                lines.append(f"- {suggestion}")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*报告由 contract-vuln-detector AI 自动生成，仅供参考。建议进行专业人工审计。*")

        path = os.path.join(self.output_dir, f"{output_name}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info(f"Markdown report generated: {path}")
        return path

    @staticmethod
    def _count_by_severity(scored_results: list) -> dict:
        """Count findings by severity level."""
        counts = {sev.value: 0 for sev in Severity}
        for _, result in scored_results:
            sev_value = result["severity"].value
            counts[sev_value] = counts.get(sev_value, 0) + 1
        return counts
