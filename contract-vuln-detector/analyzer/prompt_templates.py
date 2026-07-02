"""
Prompt templates for AI vulnerability analysis.
These templates guide the LLM to produce structured, actionable analysis.
"""

# ── Single Finding Deep Analysis ─────────────────────────────────────────────────
VULN_ANALYSIS_PROMPT = """\
你是一个高级智能合约安全审计专家，专注于 EVM 兼容链上的 Solidity 合约漏洞分析。
你的任务是判断一个扫描工具发现的可疑点是否是真正的安全漏洞，并给出详细分析。

## 合约源码

```solidity
{source_code}
```

## 可疑点信息

- **漏洞类型**: {vuln_type}
- **所在文件**: {file}
- **代码位置**: 第 {line} 行
- **所在函数**: {function_name}
- **所在合约**: {contract_name}
- **扫描工具**: {scanner}
- **工具置信度**: {confidence}
- **代码片段**:
```
{code_snippet}
```
- **工具描述**: {description}

## 请严格按以下 JSON 格式输出分析结果

```json
{{
  "is_vulnerability": true 或 false,
  "severity": "critical/high/medium/low/info",
  "title": "一句话漏洞标题",
  "analysis": "详细分析：为什么这是/不是一个漏洞，考虑合约上下文",
  "attack_path": "攻击者如何利用此漏洞，给出具体攻击步骤（如果是真正漏洞）",
  "impact": "潜在影响：资金损失/权限丢失/数据篡改/拒绝服务等",
  "affected_assets": "受影响的资产或功能",
  "exploitability": "exploitable/unlikely/theoretical",
  "prerequisites": "利用此漏洞需要满足的前提条件",
  "fix_recommendation": "具体修复建议",
  "fix_code": "修复后的代码示例（如果适用）",
  "references": ["相关 CWE/SWC 链接或已知攻击案例"]
}}
```

注意：
1. 务必结合完整的合约上下文判断，不要仅凭代码片段做结论
2. 考虑 Solidity 版本差异（如 0.8.x 已内置溢出检查）
3. 考虑是否有其他保护机制（如 ReentrancyGuard、Ownable 等）
4. 如果确定不是漏洞，在 analysis 中说明原因
5. fix_code 应是可直接替换原代码的完整修改
"""


# ── Batch Summary Prompt ─────────────────────────────────────────────────────────
BATCH_SUMMARY_PROMPT = """\
你是一个智能合约安全审计报告撰写专家。
以下是扫描工具对一个合约发现的所有可疑点，请生成一份简洁的安全摘要。

## 合约信息
- **合约名称**: {contract_name}
- **文件**: {file}
- **Solidity 版本**: {solc_version}

## 可疑点列表

{findings_summary}

## 请生成以下 JSON 格式的摘要报告

```json
{{
  "overall_risk": "critical/high/medium/low/safe",
  "summary": "一段话概括合约整体安全状况",
  "critical_issues": ["列出最关键的问题"],
  "recommendations_priority": ["按优先级排列的修复建议"],
  "contract_hardening_suggestions": ["合约加固的通用建议"]
}}
```
"""


# ── Quick Triage Prompt (for fast pre-filtering) ────────────────────────────────
TRIAGE_PROMPT = """\
快速判断以下可疑点是否值得深入分析。
仅输出 JSON: {{"worth_analyzing": true/false, "reason": "一句话原因"}}

漏洞类型: {vuln_type}
代码位置: 第 {line} 行
代码片段:
```
{code_snippet}
```
工具描述: {description}
"""


def format_findings_for_batch(findings: list) -> str:
    """Format a list of findings into a readable summary for the batch prompt."""
    lines = []
    for i, f in enumerate(findings, 1):
        lines.append(
            f"### 可疑点 #{i}\n"
            f"- 类型: {f.vuln_type}\n"
            f"- 严重程度: {f.severity.value}\n"
            f"- 位置: 第 {f.line} 行"
            f"{f' ({f.function_name})' if f.function_name else ''}\n"
            f"- 描述: {f.description}\n"
            f"- 代码片段:\n```\n{f.code_snippet}\n```\n"
        )
    return "\n".join(lines)
