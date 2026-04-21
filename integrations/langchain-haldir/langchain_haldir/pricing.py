"""
LLM cost estimation — model-name → ($/1M input, $/1M output).

Why this module exists:

  Without LLM cost tracking, a Haldir `spend_limit` only applies to
  tool calls that carry an explicit `cost_usd`. LLM tokens are where
  agents actually burn money — often 10-100x the tool-call cost. An
  agent with a $5 spend cap that only counts tool-call fees will
  happily spend $50 in LLM tokens and think it's under budget.

  This table maps model identifiers (as LangChain reports them) to
  a per-million-token rate for prompt + completion. The callback
  uses it on `on_llm_end` to convert `llm_output.token_usage` into a
  dollar figure we write to the audit log with `cost_usd` set.

Scope:

  Pricing is quoted in USD per 1M tokens and reflects the
  public list price as of document date. Not sourced from a live API
  (Anthropic / OpenAI / Google all publish static pricing pages).
  Refresh when providers change pricing. Overestimate-safe — if a
  model isn't in the table, we fall back to a conservative default
  that lets the budget fire early rather than late.

Format:

  PRICING[model_key] = {"prompt": usd_per_1m_input, "completion": usd_per_1m_output}

Lookup is case-insensitive + prefix-tolerant so LangChain's various
internal model aliases ("gpt-4o-mini-2024-07-18", "gpt-4o-mini") all
hit the same row.

Contributing: when OpenAI/Anthropic/Google release a new model,
add the row to PRICING and update CHANGELOG.md.
"""

from __future__ import annotations


# Conservative fallback if a model isn't in the table. Set to the
# highest-tier rate we know about so undetected models bill HIGH
# (budget fires early) rather than LOW (budget fires too late and
# the agent over-runs).
_FALLBACK = {"prompt": 15.00, "completion": 75.00}


# Prices in USD per 1,000,000 tokens. Last refreshed: 2026-04-20.
#
# Keys are lowercase prefix patterns matched against
# LangChain's reported model_name. The LONGEST matching prefix wins,
# so "gpt-4o-mini" takes precedence over "gpt-4" when the model is
# "gpt-4o-mini-2024-07-18".
PRICING: dict[str, dict[str, float]] = {
    # ── OpenAI ────────────────────────────────────────────────────
    "gpt-4o-mini":         {"prompt": 0.15,  "completion": 0.60},
    "gpt-4o":              {"prompt": 2.50,  "completion": 10.00},
    "gpt-4-turbo":         {"prompt": 10.00, "completion": 30.00},
    "gpt-4":               {"prompt": 30.00, "completion": 60.00},
    "gpt-3.5-turbo":       {"prompt": 0.50,  "completion": 1.50},
    "o1-mini":             {"prompt": 3.00,  "completion": 12.00},
    "o1-preview":          {"prompt": 15.00, "completion": 60.00},
    "o1":                  {"prompt": 15.00, "completion": 60.00},

    # ── Anthropic ─────────────────────────────────────────────────
    "claude-3-5-haiku":    {"prompt": 0.80,  "completion": 4.00},
    "claude-3-haiku":      {"prompt": 0.25,  "completion": 1.25},
    "claude-3-5-sonnet":   {"prompt": 3.00,  "completion": 15.00},
    "claude-3-sonnet":     {"prompt": 3.00,  "completion": 15.00},
    "claude-3-7-sonnet":   {"prompt": 3.00,  "completion": 15.00},
    "claude-3-opus":       {"prompt": 15.00, "completion": 75.00},
    "claude-opus-4":       {"prompt": 15.00, "completion": 75.00},
    "claude-sonnet-4":     {"prompt": 3.00,  "completion": 15.00},
    "claude-haiku-4":      {"prompt": 1.00,  "completion": 5.00},

    # ── Google ────────────────────────────────────────────────────
    "gemini-1.5-flash":    {"prompt": 0.075, "completion": 0.30},
    "gemini-1.5-pro":      {"prompt": 1.25,  "completion": 5.00},
    "gemini-2.0-flash":    {"prompt": 0.10,  "completion": 0.40},
    "gemini-2.5-pro":      {"prompt": 1.25,  "completion": 10.00},

    # ── Meta (via Together / Fireworks / Groq) ────────────────────
    "llama-3.1-70b":       {"prompt": 0.60,  "completion": 0.60},
    "llama-3.1-8b":        {"prompt": 0.10,  "completion": 0.10},
    "llama-3.3-70b":       {"prompt": 0.60,  "completion": 0.60},

    # ── DeepSeek ──────────────────────────────────────────────────
    "deepseek-chat":       {"prompt": 0.27,  "completion": 1.10},
    "deepseek-reasoner":   {"prompt": 0.55,  "completion": 2.19},

    # ── Mistral ───────────────────────────────────────────────────
    "mistral-large":       {"prompt": 2.00,  "completion": 6.00},
    "mistral-small":       {"prompt": 0.20,  "completion": 0.60},
}


def price_for(model_name: str | None) -> dict[str, float]:
    """Return {prompt, completion} USD-per-1M-tokens for a model name.

    Matching strategy: longest-prefix. That way specific variants
    ("gpt-4o-mini-2024-07-18") resolve to their base pricing row
    without us having to enumerate every dated variant."""
    if not model_name:
        return _FALLBACK
    key = model_name.lower().strip()
    # Try exact + longest-prefix match.
    best: tuple[int, dict[str, float]] | None = None
    for pattern, rates in PRICING.items():
        if key.startswith(pattern):
            if best is None or len(pattern) > best[0]:
                best = (len(pattern), rates)
    return best[1] if best else _FALLBACK


def cost_usd(model_name: str | None,
             prompt_tokens: int,
             completion_tokens: int) -> float:
    """Compute USD cost for a single LLM call.

    Returns 0.0 gracefully on None / missing inputs — callers should
    pass zeros rather than omit the arguments, but defend anyway so a
    surprise field shape never crashes the callback."""
    prompt_tokens = int(prompt_tokens or 0)
    completion_tokens = int(completion_tokens or 0)
    if prompt_tokens <= 0 and completion_tokens <= 0:
        return 0.0
    rates = price_for(model_name)
    return round(
        (prompt_tokens / 1_000_000.0) * rates["prompt"]
        + (completion_tokens / 1_000_000.0) * rates["completion"],
        6,
    )
