"""Model specifications and cost data for routing decisions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from threading import Lock


class ModelTier(Enum):
    """Model tiers ordered by capability and cost."""

    HAIKU = "haiku"
    SONNET = "sonnet"
    OPUS = "opus"


@dataclass(frozen=True)
class ModelSpec:
    """Immutable model specification."""

    id: str
    tier: ModelTier
    input_cost_per_m: float
    output_cost_per_m: float
    context_window: int
    output_limit: int
    coding_score: float
    reasoning_score: float
    tool_use_score: float
    instruction_following: float
    avg_latency_ms: int
    reliability: float

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return (
            (input_tokens / 1_000_000) * self.input_cost_per_m
            + (output_tokens / 1_000_000) * self.output_cost_per_m
        )


KNOWN_MODELS: dict[str, ModelSpec] = {
    "anthropic/claude-haiku-4.5": ModelSpec(
        id="anthropic/claude-haiku-4.5",
        tier=ModelTier.HAIKU,
        input_cost_per_m=0.25,
        output_cost_per_m=1.25,
        context_window=200_000,
        output_limit=8192,
        coding_score=0.72,
        reasoning_score=0.70,
        tool_use_score=0.85,
        instruction_following=0.80,
        avg_latency_ms=800,
        reliability=0.98,
    ),
    "anthropic/claude-sonnet-4.5": ModelSpec(
        id="anthropic/claude-sonnet-4.5",
        tier=ModelTier.SONNET,
        input_cost_per_m=3.00,
        output_cost_per_m=15.00,
        context_window=200_000,
        output_limit=16384,
        coding_score=0.89,
        reasoning_score=0.88,
        tool_use_score=0.92,
        instruction_following=0.91,
        avg_latency_ms=1500,
        reliability=0.97,
    ),
    "anthropic/claude-opus-4.5": ModelSpec(
        id="anthropic/claude-opus-4.5",
        tier=ModelTier.OPUS,
        input_cost_per_m=15.00,
        output_cost_per_m=75.00,
        context_window=200_000,
        output_limit=32768,
        coding_score=0.95,
        reasoning_score=0.97,
        tool_use_score=0.96,
        instruction_following=0.96,
        avg_latency_ms=3000,
        reliability=0.96,
    ),
    "anthropic/claude-opus-4.6": ModelSpec(
        id="anthropic/claude-opus-4.6",
        tier=ModelTier.OPUS,
        input_cost_per_m=15.00,
        output_cost_per_m=75.00,
        context_window=200_000,
        output_limit=32768,
        coding_score=0.97,
        reasoning_score=0.98,
        tool_use_score=0.97,
        instruction_following=0.97,
        avg_latency_ms=3000,
        reliability=0.96,
    ),
}

_DEFAULT_TIER_MODELS: dict[ModelTier, str] = {
    ModelTier.HAIKU: "anthropic/claude-haiku-4.5",
    ModelTier.SONNET: "anthropic/claude-sonnet-4.5",
    ModelTier.OPUS: "anthropic/claude-opus-4.5",
}

MODEL_REGISTRY: dict[ModelTier, ModelSpec] = {
    tier: KNOWN_MODELS[model_id] for tier, model_id in _DEFAULT_TIER_MODELS.items()
}

_REGISTRY_LOCK = Lock()
_TIER_ORDER = [ModelTier.HAIKU, ModelTier.SONNET, ModelTier.OPUS]

_TIER_DEFAULTS: dict[ModelTier, dict] = {
    ModelTier.HAIKU: dict(
        input_cost_per_m=0.25,
        output_cost_per_m=1.25,
        context_window=200_000,
        output_limit=8192,
        coding_score=0.72,
        reasoning_score=0.70,
        tool_use_score=0.85,
        instruction_following=0.80,
        avg_latency_ms=800,
        reliability=0.98,
    ),
    ModelTier.SONNET: dict(
        input_cost_per_m=3.00,
        output_cost_per_m=15.00,
        context_window=200_000,
        output_limit=16384,
        coding_score=0.89,
        reasoning_score=0.88,
        tool_use_score=0.92,
        instruction_following=0.91,
        avg_latency_ms=1500,
        reliability=0.97,
    ),
    ModelTier.OPUS: dict(
        input_cost_per_m=15.00,
        output_cost_per_m=75.00,
        context_window=200_000,
        output_limit=32768,
        coding_score=0.95,
        reasoning_score=0.97,
        tool_use_score=0.96,
        instruction_following=0.96,
        avg_latency_ms=3000,
        reliability=0.96,
    ),
}


def get_model_id(tier: ModelTier) -> str:
    return MODEL_REGISTRY[tier].id


def configure_tier(tier: ModelTier, model_id: str) -> None:
    if not model_id or not model_id.strip():
        raise ValueError("model_id must be a non-empty string")

    model_id = model_id.strip()
    with _REGISTRY_LOCK:
        known = KNOWN_MODELS.get(model_id)
        if known is not None:
            MODEL_REGISTRY[tier] = replace(known, tier=tier, id=model_id)
        else:
            defaults = _TIER_DEFAULTS[tier]
            MODEL_REGISTRY[tier] = ModelSpec(id=model_id, tier=tier, **defaults)


def get_known_models() -> dict[str, dict]:
    result: dict[str, dict] = {}
    for model_id, spec in KNOWN_MODELS.items():
        result[model_id] = {
            "id": spec.id,
            "tier": spec.tier.value,
            "input_cost_per_m": spec.input_cost_per_m,
            "output_cost_per_m": spec.output_cost_per_m,
            "context_window": spec.context_window,
            "output_limit": spec.output_limit,
            "coding_score": spec.coding_score,
            "reasoning_score": spec.reasoning_score,
        }
    return result

