from __future__ import annotations

import importlib
import json
import sys
import types
import unittest
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Any


class HeaderProcessingMode(Enum):
    SKIP = "SKIP"
    PROCESS = "PROCESS"


class BodyProcessingMode(Enum):
    SKIP = "SKIP"
    BUFFER = "BUFFER"
    STREAM = "STREAM"


@dataclass
class ProcessingMode:
    request_header_mode: HeaderProcessingMode = HeaderProcessingMode.SKIP
    request_body_mode: BodyProcessingMode = BodyProcessingMode.SKIP
    response_header_mode: HeaderProcessingMode = HeaderProcessingMode.SKIP
    response_body_mode: BodyProcessingMode = BodyProcessingMode.SKIP


class RequestPolicy:
    pass


@dataclass
class UpstreamRequestModifications:
    body: bytes | None = None
    dynamic_metadata: dict[str, dict[str, object]] = field(default_factory=dict)


@dataclass
class CompressConfig:
    compress_user_messages: bool = False
    compress_system_messages: bool = True
    protect_recent: int = 4
    protect_analysis_context: bool = True
    frozen_message_count: int = 0
    target_ratio: float | None = None
    min_tokens_to_compress: int = 250
    kompress_model: str | None = None
    savings_profile: str | None = None


@dataclass
class CompressResult:
    messages: list[dict[str, Any]]
    tokens_before: int = 0
    tokens_after: int = 0
    tokens_saved: int = 0
    compression_ratio: float = 0.0
    transforms_applied: list[str] = field(default_factory=list)


class FakeCompressState:
    calls: list[dict[str, Any]] = []
    behavior: str = "compress"  # "compress" | "noop" | "raise"


def fake_compress(messages, model="claude-sonnet-4-5-20250929", model_limit=200000, optimize=True, hooks=None, config=None, **kwargs):
    FakeCompressState.calls.append(
        {"messages": messages, "model": model, "model_limit": model_limit, "config": config}
    )
    if FakeCompressState.behavior == "raise":
        raise RuntimeError("boom")
    if FakeCompressState.behavior == "noop":
        return CompressResult(messages=messages)

    compressed = []
    for m in messages:
        content = m.get("content", "")
        if isinstance(content, str) and len(content) > 4:
            compressed.append({**m, "content": content[: len(content) // 2]})
        else:
            compressed.append(dict(m))
    return CompressResult(
        messages=compressed,
        tokens_before=100,
        tokens_after=50,
        tokens_saved=50,
        compression_ratio=0.5,
        transforms_applied=["kompress"],
    )


def install_dependency_stubs() -> None:
    sdk_module = types.ModuleType("apip_sdk_core")
    sdk_module.BodyProcessingMode = BodyProcessingMode
    sdk_module.ProcessingMode = ProcessingMode
    sdk_module.RequestPolicy = RequestPolicy
    sdk_module.UpstreamRequestModifications = UpstreamRequestModifications
    sys.modules["apip_sdk_core"] = sdk_module

    headroom_module = types.ModuleType("headroom")
    headroom_module.compress = fake_compress
    headroom_module.CompressConfig = CompressConfig
    headroom_module.CompressResult = CompressResult
    sys.modules["headroom"] = headroom_module


def load_policy_module():
    install_dependency_stubs()
    src_dir = Path(__file__).resolve().parent.parent / "src"
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    sys.modules.pop("headroom_compressor_v0", None)
    sys.modules.pop("headroom_compressor_v0.policy", None)
    return importlib.import_module("headroom_compressor_v0.policy")


policy = load_policy_module()


def request_context(payload: object | bytes | str, present: bool = True):
    if isinstance(payload, bytes):
        body = payload
    elif isinstance(payload, str):
        body = payload.encode("utf-8")
    else:
        body = json.dumps(payload).encode("utf-8")
    return SimpleNamespace(body=SimpleNamespace(content=body, present=present))


class HeadroomCompressorPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        FakeCompressState.calls.clear()
        FakeCompressState.behavior = "compress"
        self._logger_disabled = policy.LOGGER.disabled
        policy.LOGGER.disabled = True

    def tearDown(self) -> None:
        policy.LOGGER.disabled = self._logger_disabled

    def test_mode_buffers_request_body_only(self) -> None:
        instance = policy.get_policy(metadata={}, params={})

        mode = instance.mode()

        self.assertEqual(HeaderProcessingMode.SKIP, mode.request_header_mode)
        self.assertEqual(BodyProcessingMode.BUFFER, mode.request_body_mode)
        self.assertEqual(HeaderProcessingMode.SKIP, mode.response_header_mode)
        self.assertEqual(BodyProcessingMode.SKIP, mode.response_body_mode)

    def test_normalize_params_defaults(self) -> None:
        params = policy.normalize_params({})

        self.assertEqual(policy.DEFAULT_JSON_PATH, params.json_path)
        self.assertIsNone(params.model)
        self.assertEqual(policy.DEFAULT_MODEL_LIMIT, params.model_limit)
        self.assertIsNone(params.target_ratio)
        self.assertFalse(params.compress_user_messages)
        self.assertIsNone(params.protect_recent)
        self.assertIsNone(params.min_tokens_to_compress)

    def test_normalize_params_coerces_and_validates(self) -> None:
        params = policy.normalize_params(
            {
                "jsonPath": " $.data.messages ",
                "model": " gpt-4o ",
                "modelLimit": 128000.0,
                "targetRatio": 0.4,
                "compressUserMessages": True,
                "protectRecent": 2,
                "minTokensToCompress": 100,
            }
        )

        self.assertEqual("$.data.messages", params.json_path)
        self.assertEqual("gpt-4o", params.model)
        self.assertEqual(128000, params.model_limit)
        self.assertEqual(0.4, params.target_ratio)
        self.assertTrue(params.compress_user_messages)
        self.assertEqual(2, params.protect_recent)
        self.assertEqual(100, params.min_tokens_to_compress)

    def test_normalize_params_falls_back_on_invalid_values(self) -> None:
        params = policy.normalize_params(
            {
                "jsonPath": "   ",
                "model": "   ",
                "targetRatio": 1.5,
                "compressUserMessages": "yes",
            }
        )

        self.assertEqual(policy.DEFAULT_JSON_PATH, params.json_path)
        self.assertIsNone(params.model)
        self.assertIsNone(params.target_ratio)
        self.assertFalse(params.compress_user_messages)

    def test_returns_none_when_body_absent_not_present_or_not_json(self) -> None:
        instance = policy.get_policy(metadata={}, params={})

        self.assertIsNone(instance.on_request_body(None, SimpleNamespace(body=None), {}))
        self.assertIsNone(
            instance.on_request_body(
                None, request_context({"messages": [], "model": "gpt-4o"}, present=False), {}
            )
        )
        self.assertIsNone(instance.on_request_body(None, request_context(b"{not json"), {}))
        self.assertEqual([], FakeCompressState.calls)

    def test_returns_none_when_jsonpath_does_not_resolve(self) -> None:
        instance = policy.get_policy(metadata={}, params={"jsonPath": "$.data.messages"})

        action = instance.on_request_body(
            None, request_context({"messages": [{"role": "user", "content": "hi"}], "model": "gpt-4o"}), {}
        )

        self.assertIsNone(action)
        self.assertEqual([], FakeCompressState.calls)

    def test_returns_none_when_messages_is_missing_empty_or_not_a_list(self) -> None:
        instance = policy.get_policy(metadata={}, params={})

        self.assertIsNone(
            instance.on_request_body(None, request_context({"messages": [], "model": "gpt-4o"}), {})
        )
        self.assertIsNone(
            instance.on_request_body(None, request_context({"messages": "not-a-list", "model": "gpt-4o"}), {})
        )
        self.assertEqual([], FakeCompressState.calls)

    def test_returns_none_when_no_model_available(self) -> None:
        instance = policy.get_policy(metadata={}, params={})

        action = instance.on_request_body(
            None, request_context({"messages": [{"role": "user", "content": "hello world"}]}), {}
        )

        self.assertIsNone(action)
        self.assertEqual([], FakeCompressState.calls)

    def test_model_from_request_body_used_when_param_omitted(self) -> None:
        instance = policy.get_policy(metadata={}, params={})

        instance.on_request_body(
            None,
            request_context({"model": "gpt-4o", "messages": [{"role": "user", "content": "hello world!!"}]}),
            {},
        )

        self.assertEqual(1, len(FakeCompressState.calls))
        self.assertEqual("gpt-4o", FakeCompressState.calls[0]["model"])

    def test_model_param_overrides_request_body_model(self) -> None:
        instance = policy.get_policy(metadata={}, params={"model": "claude-sonnet-4-5-20250929"})

        instance.on_request_body(
            None,
            request_context({"model": "gpt-4o", "messages": [{"role": "user", "content": "hello world!!"}]}),
            {},
        )

        self.assertEqual("claude-sonnet-4-5-20250929", FakeCompressState.calls[0]["model"])

    def test_compresses_default_messages_path_and_sets_metadata(self) -> None:
        instance = policy.get_policy(metadata={}, params={})

        action = instance.on_request_body(
            None,
            request_context(
                {
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": "hello world, this is long enough"}],
                }
            ),
            {},
        )

        self.assertIsInstance(action, UpstreamRequestModifications)
        updated_payload = json.loads(action.body)
        self.assertEqual("hello world, thi", updated_payload["messages"][0]["content"])

        metadata = action.dynamic_metadata[policy.DYNAMIC_METADATA_NAMESPACE]
        self.assertEqual(100, metadata["tokens_before"])
        self.assertEqual(50, metadata["tokens_after"])
        self.assertEqual(50, metadata["tokens_saved"])
        self.assertEqual(0.5, metadata["compression_ratio"])
        self.assertEqual(["kompress"], metadata["transforms_applied"])

    def test_compresses_custom_jsonpath(self) -> None:
        instance = policy.get_policy(metadata={}, params={"jsonPath": "$.data.messages"})

        action = instance.on_request_body(
            None,
            request_context(
                {
                    "model": "gpt-4o",
                    "data": {"messages": [{"role": "user", "content": "hello world, this is long enough"}]},
                }
            ),
            {},
        )

        updated_payload = json.loads(action.body)
        self.assertEqual("hello world, thi", updated_payload["data"]["messages"][0]["content"])

    def test_returns_none_when_compression_is_a_noop(self) -> None:
        FakeCompressState.behavior = "noop"
        instance = policy.get_policy(metadata={}, params={})

        action = instance.on_request_body(
            None,
            request_context({"model": "gpt-4o", "messages": [{"role": "user", "content": "hello world!!"}]}),
            {},
        )

        self.assertIsNone(action)

    def test_returns_none_when_compress_raises(self) -> None:
        FakeCompressState.behavior = "raise"
        instance = policy.get_policy(metadata={}, params={})

        action = instance.on_request_body(
            None,
            request_context({"model": "gpt-4o", "messages": [{"role": "user", "content": "hello world!!"}]}),
            {},
        )

        self.assertIsNone(action)

    def test_config_knobs_forwarded_to_compress_config(self) -> None:
        instance = policy.get_policy(
            metadata={},
            params={
                "targetRatio": 0.6,
                "compressUserMessages": True,
                "protectRecent": 1,
                "minTokensToCompress": 10,
            },
        )

        instance.on_request_body(
            None,
            request_context({"model": "gpt-4o", "messages": [{"role": "user", "content": "hello world!!"}]}),
            {},
        )

        used_config = FakeCompressState.calls[0]["config"]
        self.assertEqual(0.6, used_config.target_ratio)
        self.assertTrue(used_config.compress_user_messages)
        self.assertEqual(1, used_config.protect_recent)
        self.assertEqual(10, used_config.min_tokens_to_compress)

    def test_extract_and_set_value_at_jsonpath(self) -> None:
        payload = {"data": {"messages": [{"role": "user", "content": "hi"}]}}

        self.assertEqual(
            payload["data"]["messages"],
            policy.extract_value_from_jsonpath(payload, "$.data.messages"),
        )

        policy.set_value_at_jsonpath(payload, "$.data.messages", [{"role": "user", "content": "bye"}])
        self.assertEqual([{"role": "user", "content": "bye"}], payload["data"]["messages"])

    def test_jsonpath_helpers_reject_missing_keys(self) -> None:
        payload = {"messages": []}

        with self.assertRaises(policy.JSONPathError):
            policy.extract_value_from_jsonpath(payload, "$.data.messages")

        with self.assertRaises(policy.JSONPathError):
            policy.set_value_at_jsonpath(payload, "$.data.messages", [])


if __name__ == "__main__":
    unittest.main()
