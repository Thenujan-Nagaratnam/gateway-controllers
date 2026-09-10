from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from headroom import CompressConfig, compress
from apip_sdk_core import (
    BodyProcessingMode,
    ProcessingMode,
    RequestPolicy,
    UpstreamRequestModifications,
)

LOGGER = logging.getLogger(__name__)

DEFAULT_JSON_PATH = "$.messages"
DEFAULT_MODEL_LIMIT = 200000
DYNAMIC_METADATA_NAMESPACE = "headroom_compressor"


class JSONPathError(ValueError):
    """Raised when the configured JSONPath cannot be resolved safely."""


@dataclass(frozen=True)
class PolicyParams:
    json_path: str
    model: str | None
    model_limit: int
    target_ratio: float | None
    compress_user_messages: bool
    protect_recent: int | None
    min_tokens_to_compress: int | None


class HeadroomCompressorPolicy(RequestPolicy):
    """Compress the request's message history via Headroom before it reaches the LLM."""

    def __init__(self, policy_params: PolicyParams):
        self._params = policy_params

    def mode(self) -> ProcessingMode:
        return ProcessingMode(request_body_mode=BodyProcessingMode.BUFFER)

    def on_request_body(self, execution_ctx, req_ctx, params):
        if req_ctx.body is None or not req_ctx.body.present or req_ctx.body.content is None:
            return None

        body_bytes = req_ctx.body.content or b""
        if not body_bytes:
            return None

        try:
            payload = json.loads(body_bytes)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            LOGGER.warning("HeadroomCompressor: request body is not valid JSON: %s", exc)
            return None

        try:
            messages = extract_value_from_jsonpath(payload, self._params.json_path)
        except JSONPathError as exc:
            LOGGER.warning(
                "HeadroomCompressor: failed to extract messages from jsonPath %s: %s",
                self._params.json_path,
                exc,
            )
            return None

        if not isinstance(messages, list) or not messages:
            return None

        model = self._params.model or extract_model(payload)
        if not model:
            LOGGER.debug(
                "HeadroomCompressor: no model available (param or request body), skipping compression"
            )
            return None

        config = CompressConfig(compress_user_messages=self._params.compress_user_messages)
        if self._params.target_ratio is not None:
            config.target_ratio = self._params.target_ratio
        if self._params.protect_recent is not None:
            config.protect_recent = self._params.protect_recent
        if self._params.min_tokens_to_compress is not None:
            config.min_tokens_to_compress = self._params.min_tokens_to_compress

        try:
            result = compress(
                messages,
                model=model,
                model_limit=self._params.model_limit,
                config=config,
            )
        except Exception as exc:  # pragma: no cover - defensive guard for library/runtime issues
            LOGGER.warning("HeadroomCompressor: compression failed, passing through unchanged: %s", exc)
            return None

        if result.messages == messages:
            return None

        try:
            set_value_at_jsonpath(payload, self._params.json_path, result.messages)
        except JSONPathError as exc:
            LOGGER.warning(
                "HeadroomCompressor: failed to write compressed messages back to jsonPath %s: %s",
                self._params.json_path,
                exc,
            )
            return None

        try:
            updated_body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
        except (TypeError, ValueError) as exc:
            LOGGER.warning("HeadroomCompressor: failed to marshal updated JSON payload: %s", exc)
            return None

        dynamic_metadata = {
            DYNAMIC_METADATA_NAMESPACE: {
                "tokens_before": result.tokens_before,
                "tokens_after": result.tokens_after,
                "tokens_saved": result.tokens_saved,
                "compression_ratio": result.compression_ratio,
                "transforms_applied": list(result.transforms_applied),
            }
        }
        return UpstreamRequestModifications(body=updated_body, dynamic_metadata=dynamic_metadata)


def get_policy(metadata, params):
    normalized = normalize_params(params)
    return HeadroomCompressorPolicy(normalized)


def normalize_params(params: dict[str, Any] | None) -> PolicyParams:
    params = params or {}

    json_path = params.get("jsonPath", DEFAULT_JSON_PATH)
    if not isinstance(json_path, str) or not json_path.strip():
        LOGGER.warning(
            "HeadroomCompressor: invalid jsonPath %r, falling back to %s", json_path, DEFAULT_JSON_PATH
        )
        json_path = DEFAULT_JSON_PATH
    else:
        json_path = json_path.strip()

    model = params.get("model")
    if model is not None and (not isinstance(model, str) or not model.strip()):
        LOGGER.warning(
            "HeadroomCompressor: invalid model %r, falling back to auto-detection from the request body",
            model,
        )
        model = None
    elif isinstance(model, str):
        model = model.strip()

    model_limit = coerce_int(params.get("modelLimit"), DEFAULT_MODEL_LIMIT)

    target_ratio = coerce_float_or_none(params.get("targetRatio"))
    if target_ratio is not None and not (0.0 < target_ratio <= 1.0):
        LOGGER.warning("HeadroomCompressor: targetRatio %r out of range (0, 1], ignoring", target_ratio)
        target_ratio = None

    compress_user_messages = params.get("compressUserMessages", False)
    if not isinstance(compress_user_messages, bool):
        LOGGER.warning(
            "HeadroomCompressor: compressUserMessages must be a boolean, got %s, defaulting to False",
            type(compress_user_messages).__name__,
        )
        compress_user_messages = False

    protect_recent = coerce_int_or_none(params.get("protectRecent"))
    min_tokens_to_compress = coerce_int_or_none(params.get("minTokensToCompress"))

    return PolicyParams(
        json_path=json_path,
        model=model,
        model_limit=model_limit,
        target_ratio=target_ratio,
        compress_user_messages=compress_user_messages,
        protect_recent=protect_recent,
        min_tokens_to_compress=min_tokens_to_compress,
    )


def extract_model(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    model = payload.get("model")
    if isinstance(model, str) and model.strip():
        return model.strip()
    return None


def coerce_int(value: Any, default: int) -> int:
    parsed = coerce_int_or_none(value)
    return default if parsed is None else parsed


def coerce_int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def coerce_float_or_none(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def extract_value_from_jsonpath(data: Any, json_path: str) -> Any:
    current = data
    for component in split_json_path(json_path):
        current = get_path_component(current, component)
    return current


def set_value_at_jsonpath(data: Any, json_path: str, value: Any) -> None:
    components = split_json_path(json_path)
    if not components:
        raise JSONPathError("empty JSONPath")

    current = data
    for component in components[:-1]:
        current = get_path_component(current, component)

    final_component = components[-1]
    if not isinstance(current, dict):
        raise JSONPathError(f"invalid structure for key: {final_component}")
    if final_component not in current:
        raise JSONPathError(f"key not found: {final_component}")
    current[final_component] = value


def split_json_path(json_path: str) -> list[str]:
    if not isinstance(json_path, str):
        raise JSONPathError("jsonPath must be a string")
    parts = json_path.split(".")
    if parts and parts[0] == "$":
        parts = parts[1:]
    if not parts or any(not part for part in parts):
        raise JSONPathError("empty JSONPath")
    return parts


def get_path_component(current: Any, component: str) -> Any:
    if not isinstance(current, dict):
        raise JSONPathError(f"invalid structure for key: {component}")
    if component not in current:
        raise JSONPathError(f"key not found: {component}")
    return current[component]
