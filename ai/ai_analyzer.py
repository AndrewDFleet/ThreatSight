import json
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import List, Optional

import anthropic

from models import Alert
from ai import ai_config, prompt_templates

logger = logging.getLogger(__name__)


@dataclass
class AlertAnalysis:
    alert_id: str
    threat_assessment: str
    recommended_actions: List[str]
    context: str
    false_positive_likelihood: str  # low | medium | high
    priority: str                   # immediate | high | medium | low
    tokens_used: int = 0
    cache_read_tokens: int = 0
    error: Optional[str] = None


class AIAnalyzer:
    def __init__(self):
        if not ai_config.ANTHROPIC_API_KEY:
            raise ValueError("ANTHROPIC_API_KEY environment variable is not set")
        self._client = anthropic.Anthropic(api_key=ai_config.ANTHROPIC_API_KEY)
        self._request_timestamps: List[float] = []
        self._lock = threading.Lock()

    def analyze_alert(self, alert: Alert) -> AlertAnalysis:
        for attempt in range(ai_config.MAX_RETRIES):
            try:
                self._enforce_rate_limit()
                return self._call_claude(alert)
            except anthropic.RateLimitError:
                if attempt == ai_config.MAX_RETRIES - 1:
                    logger.error("Rate limit exceeded after %d retries for alert %s", ai_config.MAX_RETRIES, alert.alert_id)
                    return self._fallback_analysis(alert, "rate_limit_exceeded")
                delay = ai_config.RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning("Rate limited, retrying in %.1fs (attempt %d/%d)", delay, attempt + 1, ai_config.MAX_RETRIES)
                time.sleep(delay)
            except anthropic.APIStatusError as e:
                if e.status_code >= 500 and attempt < ai_config.MAX_RETRIES - 1:
                    delay = ai_config.RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning("Server error %d, retrying in %.1fs", e.status_code, delay)
                    time.sleep(delay)
                else:
                    logger.error("API error for alert %s: %s", alert.alert_id, e)
                    return self._fallback_analysis(alert, f"api_error_{e.status_code}")
            except Exception as e:
                logger.error("Unexpected error analyzing alert %s: %s", alert.alert_id, e)
                return self._fallback_analysis(alert, str(e))
        return self._fallback_analysis(alert, "max_retries_exceeded")

    def analyze_batch(self, alerts: List[Alert]) -> List[AlertAnalysis]:
        return [self.analyze_alert(alert) for alert in alerts]

    def _enforce_rate_limit(self) -> None:
        with self._lock:
            now = time.monotonic()
            window = 60.0
            self._request_timestamps = [t for t in self._request_timestamps if now - t < window]

            if len(self._request_timestamps) >= ai_config.REQUESTS_PER_MINUTE:
                oldest = self._request_timestamps[0]
                sleep_for = window - (now - oldest) + 0.05
                if sleep_for > 0:
                    logger.debug("Rate limit: sleeping %.2fs", sleep_for)
                    time.sleep(sleep_for)
                now = time.monotonic()
                self._request_timestamps = [t for t in self._request_timestamps if now - t < window]

            self._request_timestamps.append(time.monotonic())

    def _call_claude(self, alert: Alert) -> AlertAnalysis:
        response = self._client.messages.create(
            model=ai_config.MODEL,
            max_tokens=ai_config.MAX_TOKENS_ANALYSIS,
            thinking={"type": "adaptive"},
            output_config={"effort": "medium"},
            system=[{
                "type": "text",
                "text": prompt_templates.SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": prompt_templates.build_alert_prompt(alert)}],
            timeout=ai_config.REQUEST_TIMEOUT,
        )
        return self._parse_response(alert.alert_id, response)

    def _parse_response(self, alert_id: str, response) -> AlertAnalysis:
        usage = response.usage
        tokens_used = usage.input_tokens + usage.output_tokens
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0

        raw_text = ""
        for block in response.content:
            if block.type == "text":
                raw_text = block.text
                break

        text = raw_text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        if "{" in text and "}" in text:
            start = text.index("{")
            end = text.rindex("}") + 1
            text = text[start:end]

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse JSON response for alert %s: %s\nRaw: %s", alert_id, e, raw_text[:200])
            return AlertAnalysis(
                alert_id=alert_id,
                threat_assessment="Unable to parse AI response.",
                recommended_actions=["Manual review required"],
                context="AI response parsing failed.",
                false_positive_likelihood="medium",
                priority="medium",
                tokens_used=tokens_used,
                cache_read_tokens=cache_read,
                error="json_parse_error",
            )

        return AlertAnalysis(
            alert_id=alert_id,
            threat_assessment=data.get("threat_assessment", ""),
            recommended_actions=data.get("recommended_actions", []),
            context=data.get("context", ""),
            false_positive_likelihood=data.get("false_positive_likelihood", "medium"),
            priority=data.get("priority", "medium"),
            tokens_used=tokens_used,
            cache_read_tokens=cache_read,
        )

    @staticmethod
    def _fallback_analysis(alert: Alert, error: str) -> AlertAnalysis:
        return AlertAnalysis(
            alert_id=alert.alert_id,
            threat_assessment=f"Automated AI analysis unavailable ({error}). Manual review required for {alert.alert_type.value} alert with {alert.severity.value} severity.",
            recommended_actions=[
                "Review alert manually in the security dashboard",
                "Apply standard response procedure for this alert type",
            ],
            context="AI analysis could not be completed. Rely on detector metadata and manual investigation.",
            false_positive_likelihood="medium",
            priority="high" if alert.severity.value in ("high", "critical") else "medium",
            error=error,
        )
