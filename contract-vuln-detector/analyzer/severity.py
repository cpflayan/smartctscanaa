"""
Severity scoring module.
Aggregates scanner confidence + AI analysis to produce final severity rating.
"""

import logging
from typing import Optional

from scanners.base_scanner import Severity, Finding

logger = logging.getLogger(__name__)


# Weights for final score calculation
WEIGHT_SCANNER_SEVERITY = 0.30
WEIGHT_SCANNER_CONFIDENCE = 0.15
WEIGHT_AI_IS_VULN = 0.30
WEIGHT_AI_SEVERITY = 0.25


class SeverityScorer:
    """
    Computes a final severity score for each Finding by combining:
    - Scanner's initial severity assessment
    - Scanner confidence level
    - AI analysis verdict (is_vulnerability flag)
    - AI-assessed severity level
    """

    # Numeric mapping for severity levels (higher = more severe)
    SEVERITY_SCORES = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.8,
        Severity.MEDIUM: 0.5,
        Severity.LOW: 0.25,
        Severity.INFO: 0.1,
    }

    def __init__(self, thresholds: dict = None):
        """
        Args:
            thresholds: Custom thresholds for severity levels.
                        Default: {critical: 0.85, high: 0.65, medium: 0.40, low: 0.20}
        """
        self.thresholds = thresholds or {
            "critical": 0.85,
            "high": 0.65,
            "medium": 0.40,
            "low": 0.20,
        }

    def score(self, finding: Finding) -> dict:
        """
        Compute final severity score for a finding.

        Args:
            finding: A Finding object, optionally with ai_analysis populated.

        Returns:
            dict with keys:
                - score: float 0.0-1.0
                - severity: Severity enum
                - is_confirmed: bool (AI confirmed it's a real vulnerability)
                - breakdown: dict of component scores
        """
        # Component 1: Scanner severity (normalized 0-1)
        scanner_sev_score = self.SEVERITY_SCORES.get(finding.severity, 0.1)

        # Component 2: Scanner confidence
        scanner_conf = max(0.0, min(1.0, finding.confidence))

        # Component 3 & 4: AI analysis (if available)
        ai_is_vuln_score = 0.5  # Neutral default when no AI analysis
        ai_sev_score = scanner_sev_score  # Default to scanner's assessment

        ai_analysis = finding.ai_analysis
        is_confirmed = False

        if ai_analysis:
            # AI verdict: is this a real vulnerability?
            ai_is_vuln = ai_analysis.get("is_vulnerability", None)
            if ai_is_vuln is True:
                ai_is_vuln_score = 1.0
                is_confirmed = True
            elif ai_is_vuln is False:
                ai_is_vuln_score = 0.0
                is_confirmed = False
            else:
                ai_is_vuln_score = 0.5  # Uncertain

            # AI severity assessment
            ai_severity_str = ai_analysis.get("severity", "")
            if ai_severity_str:
                try:
                    ai_sev = Severity.from_str(ai_severity_str)
                    ai_sev_score = self.SEVERITY_SCORES.get(ai_sev, 0.1)
                except Exception:
                    ai_sev_score = scanner_sev_score

        # Weighted final score
        final_score = (
            WEIGHT_SCANNER_SEVERITY * scanner_sev_score
            + WEIGHT_SCANNER_CONFIDENCE * scanner_conf
            + WEIGHT_AI_IS_VULN * ai_is_vuln_score
            + WEIGHT_AI_SEVERITY * ai_sev_score
        )

        # Map score to severity level
        final_severity = self._score_to_severity(final_score)

        # If AI explicitly says not a vulnerability, cap at INFO
        if ai_analysis and ai_analysis.get("is_vulnerability") is False:
            final_severity = Severity.INFO
            final_score = min(final_score, 0.15)

        return {
            "score": round(final_score, 4),
            "severity": final_severity,
            "is_confirmed": is_confirmed,
            "breakdown": {
                "scanner_severity": round(scanner_sev_score, 3),
                "scanner_confidence": round(scanner_conf, 3),
                "ai_is_vuln": round(ai_is_vuln_score, 3),
                "ai_severity": round(ai_sev_score, 3),
            },
        }

    def _score_to_severity(self, score: float) -> Severity:
        """Map a 0-1 score to a Severity level."""
        if score >= self.thresholds["critical"]:
            return Severity.CRITICAL
        elif score >= self.thresholds["high"]:
            return Severity.HIGH
        elif score >= self.thresholds["medium"]:
            return Severity.MEDIUM
        elif score >= self.thresholds["low"]:
            return Severity.LOW
        else:
            return Severity.INFO

    def rank_findings(self, findings: list[Finding]) -> list[tuple[Finding, dict]]:
        """
        Score and rank all findings, returning sorted by severity (most severe first).

        Returns:
            List of (finding, score_result) tuples, sorted descending by score.
        """
        scored = [(f, self.score(f)) for f in findings]
        scored.sort(key=lambda x: x[1]["score"], reverse=True)
        return scored

    def summary_stats(self, scored_findings: list[tuple[Finding, dict]]) -> dict:
        """Generate summary statistics from scored findings."""
        total = len(scored_findings)
        by_severity = {sev.value: 0 for sev in Severity}
        confirmed = 0
        false_positives = 0

        for finding, result in scored_findings:
            by_severity[result["severity"].value] += 1
            if result["is_confirmed"]:
                confirmed += 1
            if finding.ai_analysis and finding.ai_analysis.get("is_vulnerability") is False:
                false_positives += 1

        return {
            "total_findings": total,
            "by_severity": by_severity,
            "confirmed_vulnerabilities": confirmed,
            "false_positives": false_positives,
            "avg_score": (
                round(sum(r["score"] for _, r in scored_findings) / total, 4)
                if total > 0 else 0.0
            ),
        }
