"""
AI Deep Analysis Engine.
Core module that takes scanner findings + source code, sends them to LLM,
and produces structured vulnerability analysis with fix recommendations.
"""

import json
import logging
import os
import re
import time
from typing import Optional

from scanners.base_scanner import Finding, Severity
from .prompt_templates import (
    VULN_ANALYSIS_PROMPT,
    BATCH_SUMMARY_PROMPT,
    TRIAGE_PROMPT,
    format_findings_for_batch,
)

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """
    AI-powered vulnerability analysis engine.
    Uses OpenAI-compatible LLM APIs to deeply analyze scanner findings.

    Supports:
        - OpenAI API (gpt-4, gpt-4-turbo, etc.)
        - Azure OpenAI
        - Ollama (local models)
        - Any OpenAI-compatible endpoint
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.provider = self.config.get("provider", "openai")
        self.model = self.config.get("model", "gpt-4")
        self.temperature = self.config.get("temperature", 0.1)
        self.max_tokens = self.config.get("max_tokens", 4096)
        self._client = None

        # Resolve API key
        api_key = self.config.get("api_key", "")
        if api_key.startswith("${") and api_key.endswith("}"):
            env_var = api_key[2:-1]
            api_key = os.environ.get(env_var, "")
        self.api_key = api_key
        self.base_url = self.config.get("base_url", None)

    @property
    def client(self):
        """Lazy-initialize the OpenAI client."""
        if self._client is None:
            self._client = self._create_client()
        return self._client

    def _create_client(self):
        """Create an OpenAI-compatible client based on provider config."""
        if self.provider in ("openai", "azure"):
            try:
                from openai import OpenAI, AzureOpenAI
            except ImportError:
                raise RuntimeError(
                    "openai 包未安装。运行: pip install openai\n"
                    "或使用 provider: 'ollama' 配合本地模型。"
                )

            if self.provider == "azure":
                return AzureOpenAI(
                    api_key=self.api_key,
                    api_version=self.config.get("api_version", "2024-02-01"),
                    azure_endpoint=self.base_url or "",
                )
            else:
                kwargs = {"api_key": self.api_key}
                if self.base_url:
                    kwargs["base_url"] = self.base_url
                return OpenAI(**kwargs)

        elif self.provider == "ollama":
            try:
                from openai import OpenAI
            except ImportError:
                raise RuntimeError("openai 包未安装。运行: pip install openai")
            # Ollama exposes OpenAI-compatible API at localhost:11434/v1
            base_url = self.base_url or "http://localhost:11434/v1"
            return OpenAI(api_key="ollama", base_url=base_url)

        else:
            # Generic OpenAI-compatible endpoint
            try:
                from openai import OpenAI
            except ImportError:
                raise RuntimeError("openai 包未安装。运行: pip install openai")
            return OpenAI(
                api_key=self.api_key or "dummy",
                base_url=self.base_url or "https://api.openai.com/v1",
            )

    def analyze_finding(
        self,
        finding: Finding,
        source_code: str,
        triage_first: bool = True,
    ) -> dict:
        """
        Deep-analyze a single finding using LLM.

        Args:
            finding: The Finding to analyze.
            source_code: Full contract source code.
            triage_first: If True, do a quick triage first to skip obvious false positives.

        Returns:
            dict matching the AI analysis schema from prompt_templates.
        """
        # Optional triage: quick check to skip obvious non-issues
        if triage_first and finding.severity in (Severity.LOW, Severity.INFO):
            triage_result = self._triage(finding)
            if not triage_result.get("worth_analyzing", True):
                logger.info(
                    f"Skipping finding #{finding.line} ({finding.vuln_type}): "
                    f"{triage_result.get('reason', 'triage filter')}"
                )
                return {
                    "is_vulnerability": False,
                    "severity": "info",
                    "title": "Not a vulnerability (triage filtered)",
                    "analysis": triage_result.get("reason", "Filtered by quick triage"),
                    "skipped_by_triage": True,
                }

        # Construct the full analysis prompt
        prompt = VULN_ANALYSIS_PROMPT.format(
            source_code=source_code[:8000],  # Truncate very large contracts
            vuln_type=finding.vuln_type,
            file=finding.file,
            line=finding.line,
            function_name=finding.function_name or "N/A",
            contract_name=finding.contract_name or "N/A",
            scanner=finding.scanner.value,
            confidence=finding.confidence,
            code_snippet=finding.code_snippet,
            description=finding.description,
        )

        response_text = self._call_llm(prompt)
        return self._parse_json_response(response_text)

    def analyze_batch(
        self,
        findings: list[Finding],
        source_code: str,
        contract_name: str = "Unknown",
        solc_version: str = "unknown",
        file_path: str = "<unknown>",
    ) -> dict:
        """
        Generate a batch summary analysis for all findings of a contract.

        Args:
            findings: List of findings to summarize.
            source_code: Full contract source code.
            contract_name: Name of the contract.
            solc_version: Solidity compiler version.
            file_path: File path for reference.

        Returns:
            dict with overall_risk, summary, recommendations, etc.
        """
        if not findings:
            return {
                "overall_risk": "safe",
                "summary": "未发现任何可疑点，合约看起来安全。但仍建议进行人工审计。",
                "critical_issues": [],
                "recommendations_priority": [],
                "contract_hardening_suggestions": [
                    "添加 ReentrancyGuard 防止重入攻击",
                    "使用 OpenZeppelin 的 Ownable 进行权限管理",
                    "对所有外部调用使用 require 检查返回值",
                ],
            }

        findings_summary = format_findings_for_batch(findings)
        prompt = BATCH_SUMMARY_PROMPT.format(
            contract_name=contract_name,
            file=file_path,
            solc_version=solc_version,
            findings_summary=findings_summary[:6000],
        )

        response_text = self._call_llm(prompt)
        return self._parse_json_response(response_text)

    def analyze_all(
        self,
        findings: list[Finding],
        source_code: str,
        contract_name: str = "Unknown",
        solc_version: str = "unknown",
        file_path: str = "<unknown>",
        on_progress: callable = None,
    ) -> tuple[list[Finding], dict]:
        """
        Full analysis pipeline:
        1. Analyze each finding individually
        2. Generate batch summary
        3. Attach AI analysis to each finding

        Args:
            findings: All findings from scanners.
            source_code: Full contract source code.
            on_progress: Optional callback(finding_index, total) for progress reporting.

        Returns:
            (findings_with_ai_analysis, batch_summary_dict)
        """
        total = len(findings)
        logger.info(f"开始 AI 深度分析，共 {total} 个可疑点...")

        for i, finding in enumerate(findings):
            if on_progress:
                on_progress(i, total)

            logger.info(
                f"  [{i + 1}/{total}] 分析: {finding.vuln_type} "
                f"@ line {finding.line} ({finding.scanner.value})"
            )
            try:
                ai_result = self.analyze_finding(finding, source_code)
                finding.ai_analysis = ai_result
            except Exception as e:
                logger.warning(f"  AI 分析失败: {e}")
                finding.ai_analysis = {
                    "is_vulnerability": None,
                    "severity": finding.severity.value,
                    "title": "AI analysis failed",
                    "analysis": f"Error: {e}",
                }

        # Generate batch summary
        logger.info("生成批量摘要报告...")
        try:
            batch_summary = self.analyze_batch(
                findings, source_code, contract_name, solc_version, file_path
            )
        except Exception as e:
            logger.warning(f"批量摘要生成失败: {e}")
            batch_summary = {
                "overall_risk": "unknown",
                "summary": f"Batch summary generation failed: {e}",
                "critical_issues": [],
                "recommendations_priority": [],
                "contract_hardening_suggestions": [],
            }

        if on_progress:
            on_progress(total, total)

        return findings, batch_summary

    # ── Internal Methods ───────────────────────────────────────────────────────────

    def _triage(self, finding: Finding) -> dict:
        """Quick triage to decide if a finding is worth deep analysis."""
        prompt = TRIAGE_PROMPT.format(
            vuln_type=finding.vuln_type,
            line=finding.line,
            code_snippet=finding.code_snippet,
            description=finding.description,
        )
        try:
            response = self._call_llm(prompt, max_tokens=200)
            return self._parse_json_response(response)
        except Exception:
            return {"worth_analyzing": True, "reason": "triage failed, analyzing anyway"}

    def _call_llm(self, prompt: str, max_tokens: int = None) -> str:
        """Call the LLM and return the raw text response."""
        tokens = max_tokens or self.max_tokens

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "你是一个专业的智能合约安全审计AI。"
                            "你的输出必须严格遵循要求的JSON格式。"
                            "不要输出任何不在JSON结构中的额外文字。"
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=self.temperature,
                max_tokens=tokens,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.error(f"LLM API 调用失败: {e}")
            raise

    def _parse_json_response(self, text: str) -> dict:
        """
        Extract JSON from LLM response.
        Handles cases where LLM wraps JSON in markdown code blocks.
        """
        if not text:
            return {"error": "empty_response"}

        # Try direct JSON parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try extracting from ```json ... ``` blocks
        json_block_pattern = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
        match = json_block_pattern.search(text)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Try finding first { ... } in the text
        brace_pattern = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.DOTALL)
        match = brace_pattern.search(text)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

        # Fallback: return raw text as analysis
        logger.warning("无法解析 LLM 响应为 JSON，返回原始文本")
        return {
            "is_vulnerability": None,
            "severity": "info",
            "title": "Parse failed",
            "analysis": text[:2000],
            "raw_response": True,
        }
