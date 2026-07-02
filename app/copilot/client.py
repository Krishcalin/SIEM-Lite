"""Claude client wrapper for the AI SOC copilot.

Thin layer over the official ``anthropic`` SDK. The SDK is imported lazily so the
whole app runs without the dependency when the copilot is disabled. High-level
helpers (`explain_alert`, `summarize_case`, `generate_sigma`) build their prompts
via the pure `prompts` module and take a client object with a `.complete()`
method — so they can be unit-tested with a fake client, no network required.
"""
from __future__ import annotations

import os
from typing import Any, Optional

from ..config import settings
from . import prompts


class CopilotError(RuntimeError):
    """Raised when a copilot completion cannot be produced."""


def _resolve_key() -> str:
    """Explicit COPILOT_API_KEY wins; otherwise fall back to ANTHROPIC_API_KEY."""
    return settings.copilot_api_key or os.getenv("ANTHROPIC_API_KEY", "")


def anthropic_available() -> bool:
    try:
        import anthropic  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def is_configured() -> bool:
    """True when the copilot is enabled, has a key, and the SDK is importable."""
    return bool(settings.copilot_enabled and _resolve_key() and anthropic_available())


class CopilotClient:
    """Wraps a single Claude model + key. One `.complete()` call per request."""

    def __init__(self, model: str, api_key: str = "", max_tokens: int = 1024):
        self.model = model
        self.api_key = api_key
        self.max_tokens = max_tokens

    def complete(self, system: str, user: str, max_tokens: Optional[int] = None) -> str:
        """Send one non-streaming message and return the concatenated text blocks."""
        try:
            import anthropic
        except Exception as e:  # noqa: BLE001
            raise CopilotError("anthropic SDK not installed (pip install anthropic)") from e

        client = anthropic.Anthropic(api_key=self.api_key) if self.api_key else anthropic.Anthropic()
        try:
            resp = client.messages.create(
                model=self.model,
                max_tokens=max_tokens or self.max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.APIError as e:  # network / auth / rate-limit / bad request
            raise CopilotError(f"Claude API error: {e}") from e
        except Exception as e:  # noqa: BLE001 — never leak a raw traceback to the UI
            raise CopilotError(f"copilot request failed: {e}") from e

        text = "".join(
            b.text for b in resp.content if getattr(b, "type", None) == "text"
        ).strip()
        if not text:
            raise CopilotError("Claude returned no text (possibly refused or truncated)")
        return text


def build_client() -> CopilotClient:
    """Construct a client from settings (call only when `is_configured()`)."""
    return CopilotClient(
        model=settings.copilot_model,
        api_key=_resolve_key(),
        max_tokens=settings.copilot_max_tokens,
    )


# --------------------------------------------------------------------------- #
#  High-level operations (client injected → unit-testable)                    #
# --------------------------------------------------------------------------- #
def explain_alert(client: Any, alert: dict, related: Optional[list[dict]] = None) -> str:
    system, user = prompts.build_alert_explain(alert, related)
    return client.complete(system, user)


def summarize_case(
    client: Any, case: dict, alerts: list[dict], notes: Optional[list[dict]] = None
) -> str:
    system, user = prompts.build_case_summary(case, alerts, notes)
    return client.complete(system, user)


def generate_sigma(client: Any, description: str, sample_event: Optional[str] = None) -> dict:
    """Return {raw, yaml, valid, error} for a natural-language rule request."""
    system, user = prompts.build_sigma_from_nl(description, sample_event)
    raw = client.complete(system, user, max_tokens=1500)
    rule_yaml = prompts.extract_yaml(raw)
    if not rule_yaml:
        return {"raw": raw, "yaml": None, "valid": False,
                "error": "No YAML rule found in the response."}
    ok, msg = prompts.valid_sigma(rule_yaml)
    return {"raw": raw, "yaml": rule_yaml, "valid": ok, "error": None if ok else msg}
