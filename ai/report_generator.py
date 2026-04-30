import logging
from datetime import datetime
from typing import List, Dict
from collections import Counter

import anthropic

from models import Alert, AlertSeverity
from ai import ai_config, prompt_templates
from ai.ai_analyzer import AlertAnalysis

logger = logging.getLogger(__name__)

_REPORT_SYSTEM = """You are a senior security analyst writing an executive summary for a CISO and security leadership team.

Write 3–4 sentences covering:
1. The overall threat posture based on the alerts provided
2. The most significant threats and their potential business impact
3. The top recommended priority for the security team

Be direct and non-technical enough for executive audiences. Do not use bullet points. Return plain prose only."""


class ReportGenerator:
    def __init__(self):
        if not ai_config.ANTHROPIC_API_KEY:
            raise ValueError("ANTHROPIC_API_KEY environment variable is not set")
        self._client = anthropic.Anthropic(api_key=ai_config.ANTHROPIC_API_KEY)

    def generate_report(self, alerts: List[Alert], analyses: List[AlertAnalysis]) -> str:
        analysis_map: Dict[str, AlertAnalysis] = {a.alert_id: a for a in analyses}
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        severity_counts = Counter(a.severity.value for a in alerts)
        type_counts = Counter(a.alert_type.value for a in alerts)
        total_tokens = sum(a.tokens_used for a in analyses)
        total_cache = sum(a.cache_read_tokens for a in analyses)

        critical = [a for a in alerts if a.severity == AlertSeverity.CRITICAL]
        high = [a for a in alerts if a.severity == AlertSeverity.HIGH]
        medium = [a for a in alerts if a.severity == AlertSeverity.MEDIUM]
        low = [a for a in alerts if a.severity == AlertSeverity.LOW]

        executive_summary = self._generate_executive_summary(alerts, analyses)

        sections = [
            f"# Network Security Report",
            f"**Generated:** {timestamp}  ",
            f"**Total Alerts:** {len(alerts)}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            executive_summary,
            "",
            "---",
            "",
            "## Alert Statistics",
            "",
            "### By Severity",
            "",
            self._severity_table(severity_counts),
            "",
            "### By Type",
            "",
            self._type_table(type_counts),
            "",
            "---",
            "",
        ]

        if critical or high:
            sections += [
                "## Critical & High Priority Alerts",
                "",
            ]
            for alert in critical + high:
                analysis = analysis_map.get(alert.alert_id)
                sections += self._format_alert_detail(alert, analysis)

        if medium or low:
            sections += [
                "## Medium & Low Priority Alerts",
                "",
                "| Alert ID | Type | Severity | Source IP | Priority | False Positive |",
                "|----------|------|----------|-----------|----------|----------------|",
            ]
            for alert in medium + low:
                analysis = analysis_map.get(alert.alert_id)
                fp = analysis.false_positive_likelihood if analysis else "—"
                priority = analysis.priority if analysis else "—"
                sections.append(
                    f"| `{alert.alert_id}` | {alert.alert_type.value} | {alert.severity.value} "
                    f"| {alert.source_ip or '—'} | {priority} | {fp} |"
                )
            sections.append("")
            sections.append("---")
            sections.append("")

        all_actions = []
        for analysis in analyses:
            all_actions.extend(analysis.recommended_actions)
        deduplicated = list(dict.fromkeys(all_actions))

        sections += [
            "## Consolidated Recommended Actions",
            "",
        ]
        for i, action in enumerate(deduplicated, 1):
            sections.append(f"{i}. {action}")

        sections += [
            "",
            "---",
            "",
            "## Report Metadata",
            "",
            f"- Alerts analyzed: {len(analyses)}",
            f"- Total tokens used: {total_tokens:,}",
            f"- Cache hits (tokens): {total_cache:,}",
            f"- Errors during analysis: {sum(1 for a in analyses if a.error)}",
        ]

        return "\n".join(sections)

    def _generate_executive_summary(self, alerts: List[Alert], analyses: List[AlertAnalysis]) -> str:
        severity_counts = Counter(a.severity.value for a in alerts)
        type_counts = Counter(a.alert_type.value for a in alerts)

        immediate = [a for a in analyses if a.priority == "immediate"]

        prompt_lines = [
            f"Alert summary: {len(alerts)} total alerts.",
            f"Severity breakdown: {dict(severity_counts)}.",
            f"Alert types: {dict(type_counts)}.",
        ]
        if immediate:
            prompt_lines.append(f"Alerts requiring immediate action: {len(immediate)}.")

        for a in analyses[:5]:
            if a.threat_assessment:
                prompt_lines.append(f"Key finding: {a.threat_assessment}")

        user_prompt = "\n".join(prompt_lines)

        try:
            with self._client.messages.stream(
                model=ai_config.MODEL,
                max_tokens=ai_config.MAX_TOKENS_REPORT,
                thinking={"type": "adaptive"},
                output_config={"effort": "high"},
                system=[{
                    "type": "text",
                    "text": _REPORT_SYSTEM,
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{"role": "user", "content": user_prompt}],
                timeout=ai_config.REQUEST_TIMEOUT,
            ) as stream:
                return stream.get_final_message().content[0].text
        except Exception as e:
            logger.error("Failed to generate executive summary: %s", e)
            critical_count = severity_counts.get("critical", 0)
            high_count = severity_counts.get("high", 0)
            return (
                f"This report covers {len(alerts)} security alerts detected during the monitoring period. "
                f"There are {critical_count} critical and {high_count} high severity alerts requiring attention. "
                f"Review the detailed sections below for specific findings and recommended actions."
            )

    @staticmethod
    def _severity_table(counts: Counter) -> str:
        order = ["critical", "high", "medium", "low"]
        rows = ["| Severity | Count |", "|----------|-------|"]
        for sev in order:
            c = counts.get(sev, 0)
            rows.append(f"| {sev.capitalize()} | {c} |")
        return "\n".join(rows)

    @staticmethod
    def _type_table(counts: Counter) -> str:
        rows = ["| Alert Type | Count |", "|------------|-------|"]
        for alert_type, count in counts.most_common():
            rows.append(f"| {alert_type} | {count} |")
        return "\n".join(rows)

    @staticmethod
    def _format_alert_detail(alert: Alert, analysis: AlertAnalysis | None) -> List[str]:
        lines = [
            f"### [{alert.severity.value.upper()}] {alert.alert_type.value} — `{alert.alert_id}`",
            "",
            f"**Source:** {alert.source_ip or '—'}  ",
            f"**Destination:** {alert.destination_ip or '—'}  ",
            f"**Time:** {alert.timestamp.isoformat()}  ",
            f"**Description:** {alert.description}",
            "",
        ]
        if analysis and not analysis.error:
            lines += [
                f"**Threat Assessment:** {analysis.threat_assessment}",
                "",
                f"**Context:** {analysis.context}",
                "",
                "**Recommended Actions:**",
                "",
            ]
            for action in analysis.recommended_actions:
                lines.append(f"- {action}")
            lines += [
                "",
                f"**False Positive Likelihood:** {analysis.false_positive_likelihood}  ",
                f"**Response Priority:** {analysis.priority}",
                "",
            ]
        else:
            lines += [
                "_AI analysis unavailable — manual review required._",
                "",
            ]
        return lines
