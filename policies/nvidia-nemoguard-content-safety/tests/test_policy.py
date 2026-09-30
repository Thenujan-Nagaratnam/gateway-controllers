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


class BodyProcessingMode(Enum):
    SKIP = "SKIP"
    BUFFER = "BUFFER"
    STREAM = "STREAM"


@dataclass
class ProcessingMode:
    request_body_mode: BodyProcessingMode = BodyProcessingMode.SKIP
    response_body_mode: BodyProcessingMode = BodyProcessingMode.SKIP


class RequestPolicy:
    pass


class ResponsePolicy:
    pass


@dataclass
class UpstreamRequestModifications:
    body: bytes | None = None
    dynamic_metadata: dict = field(default_factory=dict)


@dataclass
class DownstreamResponseModifications:
    body: bytes | None = None
    headers: dict = field(default_factory=dict)


@dataclass
class ImmediateResponse:
    status_code: int = 200
    headers: dict = field(default_factory=dict)
    body: bytes | None = None


class FakeHTTPResponse:
    def __init__(self, data: dict, status_code: int = 200):
        self._data = data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")

    def json(self):
        return self._data


class FakeRequests:
    post_calls: list[dict] = []
    _response: FakeHTTPResponse | None = None
    _error: Exception | None = None

    @classmethod
    def post(cls, url, headers=None, json=None, timeout=None):
        cls.post_calls.append({"url": url, "headers": headers, "json": json, "timeout": timeout})
        if cls._error is not None:
            raise cls._error
        return cls._response

    @classmethod
    def reset(cls, response: FakeHTTPResponse | None = None, error: Exception | None = None):
        cls.post_calls.clear()
        cls._response = response
        cls._error = error


def nemoguard_response(
    user_safety: str = "safe",
    response_safety: str | None = None,
    categories: str = "",
) -> FakeHTTPResponse:
    result: dict = {"User Safety": user_safety}
    if response_safety is not None:
        result["Response Safety"] = response_safety
    if categories:
        result["Safety Categories"] = categories
    return FakeHTTPResponse({
        "choices": [{"message": {"content": json.dumps(result)}}]
    })


def install_dependency_stubs() -> None:
    sdk_module = types.ModuleType("apip_sdk_core")
    sdk_module.BodyProcessingMode = BodyProcessingMode
    sdk_module.ProcessingMode = ProcessingMode
    sdk_module.RequestPolicy = RequestPolicy
    sdk_module.ResponsePolicy = ResponsePolicy
    sdk_module.UpstreamRequestModifications = UpstreamRequestModifications
    sdk_module.DownstreamResponseModifications = DownstreamResponseModifications
    sdk_module.ImmediateResponse = ImmediateResponse
    sys.modules["apip_sdk_core"] = sdk_module

    requests_module = types.ModuleType("requests")
    requests_module.post = FakeRequests.post
    sys.modules["requests"] = requests_module


def load_policy_module():
    install_dependency_stubs()
    src_dir = Path(__file__).resolve().parent.parent / "src"
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    sys.modules.pop("nvidia_nemoguard_content_safety_v0", None)
    sys.modules.pop("nvidia_nemoguard_content_safety_v0.policy", None)
    return importlib.import_module("nvidia_nemoguard_content_safety_v0.policy")


policy = load_policy_module()

ENDPOINT = "https://nemoguard.example.com"


def request_context(payload: object | bytes | str | None = None, present: bool = True):
    if payload is None:
        return SimpleNamespace(body=None)
    if isinstance(payload, bytes):
        body = payload
    elif isinstance(payload, str):
        body = payload.encode("utf-8")
    else:
        body = json.dumps(payload).encode("utf-8")
    return SimpleNamespace(body=SimpleNamespace(content=body, present=present))


def response_context(
    response_payload: object | bytes | None = None,
    request_payload: object | None = None,
    response_present: bool = True,
):
    if response_payload is None:
        res_body = SimpleNamespace(body=None)
        return SimpleNamespace(body=None, request_body=None)
    if isinstance(response_payload, bytes):
        res_bytes = response_payload
    else:
        res_bytes = json.dumps(response_payload).encode("utf-8")
    res_body = SimpleNamespace(content=res_bytes, present=response_present)

    if request_payload is not None:
        req_bytes = json.dumps(request_payload).encode("utf-8")
        req_body = SimpleNamespace(content=req_bytes, present=True)
    else:
        req_body = None

    return SimpleNamespace(body=res_body, request_body=req_body)


class NemoGuardPolicyTest(unittest.TestCase):

    def setUp(self) -> None:
        FakeRequests.reset()
        self._logger_disabled = policy.LOGGER.disabled
        policy.LOGGER.disabled = True

    def tearDown(self) -> None:
        policy.LOGGER.disabled = self._logger_disabled

    def _make_policy(self, **kwargs):
        params = {"endpoint": ENDPOINT}
        params.update(kwargs)
        return policy.get_policy(metadata={}, params=params)

    # --- mode ---

    def test_mode_buffers_both_request_and_response(self) -> None:
        instance = self._make_policy()
        mode = instance.mode()
        self.assertEqual(BodyProcessingMode.BUFFER, mode.request_body_mode)
        self.assertEqual(BodyProcessingMode.BUFFER, mode.response_body_mode)

    # --- normalize_system_params ---

    def test_normalize_system_params_applies_defaults(self) -> None:
        params = policy.normalize_system_params({"endpoint": "https://host"})
        self.assertEqual("https://host", params.endpoint)
        self.assertEqual("", params.api_key)
        self.assertEqual(policy._DEFAULT_MODEL, params.model)
        self.assertEqual(30, params.timeout)

    def test_normalize_system_params_strips_trailing_slash(self) -> None:
        params = policy.normalize_system_params({"endpoint": "  https://host/  "})
        self.assertEqual("https://host", params.endpoint)

    def test_normalize_system_params_coerces_string_timeout(self) -> None:
        params = policy.normalize_system_params({"endpoint": "x", "timeout": "60"})
        self.assertEqual(60, params.timeout)

    def test_normalize_system_params_falls_back_for_invalid_timeout(self) -> None:
        params = policy.normalize_system_params({"endpoint": "x", "timeout": -5})
        self.assertEqual(30, params.timeout)

    def test_normalize_system_params_falls_back_for_blank_model(self) -> None:
        params = policy.normalize_system_params({"endpoint": "x", "model": "  "})
        self.assertEqual(policy._DEFAULT_MODEL, params.model)

    # --- normalize_request_params ---

    def test_normalize_request_params_applies_defaults(self) -> None:
        params = policy.normalize_request_params({})
        self.assertTrue(params.request.enabled)
        self.assertEqual(policy._DEFAULT_REQUEST_JSON_PATH, params.request.json_path)
        self.assertEqual(400, params.request.block_status_code)
        self.assertIsNone(params.request.blocked_codes)
        self.assertFalse(params.request.passthrough_on_error)
        self.assertFalse(params.request.show_assessment)

        self.assertFalse(params.response.enabled)
        self.assertEqual(policy._DEFAULT_RESPONSE_JSON_PATH, params.response.json_path)

    def test_normalize_request_params_respects_enabled_false(self) -> None:
        params = policy.normalize_request_params({"request": {"enabled": False}})
        self.assertFalse(params.request.enabled)

    def test_normalize_request_params_respects_response_enabled(self) -> None:
        params = policy.normalize_request_params({"response": {"enabled": True}})
        self.assertTrue(params.response.enabled)

    def test_normalize_request_params_clamps_block_status_code(self) -> None:
        params = policy.normalize_request_params({"request": {"blockStatusCode": 200}})
        self.assertEqual(400, params.request.block_status_code)

    def test_normalize_request_params_string_false_for_passthrough(self) -> None:
        params = policy.normalize_request_params({"request": {"passthroughOnError": "false"}})
        self.assertFalse(params.request.passthrough_on_error)

    def test_normalize_request_params_string_true_for_show_assessment(self) -> None:
        params = policy.normalize_request_params({"request": {"showAssessment": "true"}})
        self.assertTrue(params.request.show_assessment)

    def test_normalize_request_params_non_dict_cfg_uses_defaults(self) -> None:
        params = policy.normalize_request_params({"request": "not-a-dict"})
        self.assertTrue(params.request.enabled)

    # --- _blocked_codes ---

    def test_blocked_codes_returns_none_when_no_categories(self) -> None:
        self.assertIsNone(policy._blocked_codes({}))

    def test_blocked_codes_returns_none_for_non_dict(self) -> None:
        self.assertIsNone(policy._blocked_codes(None))

    def test_blocked_codes_returns_frozenset_for_partial_config(self) -> None:
        codes = policy._blocked_codes({"violence": True, "profanity": False})
        self.assertIsInstance(codes, frozenset)
        self.assertIn("S1", codes)
        self.assertNotIn("S12", codes)

    def test_blocked_codes_defaults_unlisted_categories_to_blocked(self) -> None:
        codes = policy._blocked_codes({"violence": False})
        self.assertIsNotNone(codes)
        self.assertNotIn("S1", codes)
        self.assertIn("S2", codes)

    # --- _build_nemoguard_prompt ---

    def test_build_prompt_includes_user_text(self) -> None:
        prompt = policy._build_nemoguard_prompt("hello world")
        self.assertIn("user: hello world", prompt)
        self.assertNotIn("agent:", prompt)

    def test_build_prompt_includes_assistant_text_when_provided(self) -> None:
        prompt = policy._build_nemoguard_prompt("question", "answer")
        self.assertIn("user: question", prompt)
        self.assertIn("agent: answer", prompt)

    def test_build_prompt_includes_safety_policy(self) -> None:
        prompt = policy._build_nemoguard_prompt("text")
        self.assertIn("S1: Violence", prompt)
        self.assertIn("S23: Immoral/Unethical", prompt)

    # --- _resolve_jsonpath ---

    def test_resolve_jsonpath_simple_key(self) -> None:
        self.assertEqual("hi", policy._resolve_jsonpath({"content": "hi"}, "$.content"))

    def test_resolve_jsonpath_array_positive_index(self) -> None:
        data = {"messages": [{"content": "first"}, {"content": "second"}]}
        self.assertEqual("first", policy._resolve_jsonpath(data, "$.messages[0].content"))

    def test_resolve_jsonpath_array_negative_index(self) -> None:
        data = {"choices": [{"message": {"content": "reply"}}]}
        self.assertEqual("reply", policy._resolve_jsonpath(data, "$.choices[0].message.content"))

    def test_resolve_jsonpath_returns_none_for_missing_key(self) -> None:
        self.assertIsNone(policy._resolve_jsonpath({}, "$.missing"))

    def test_resolve_jsonpath_returns_none_for_unclosed_bracket(self) -> None:
        self.assertIsNone(policy._resolve_jsonpath({"messages": [{}]}, "$.messages[0.content"))

    def test_resolve_jsonpath_returns_none_for_non_integer_index(self) -> None:
        self.assertIsNone(policy._resolve_jsonpath({"messages": [{}]}, "$.messages[abc].content"))

    # --- request passthrough cases ---

    def test_request_returns_none_when_body_is_absent(self) -> None:
        instance = self._make_policy()
        self.assertIsNone(instance.on_request_body(None, request_context(None), {}))

    def test_request_returns_none_when_body_not_present(self) -> None:
        instance = self._make_policy()
        ctx = request_context({"messages": [{"content": "hello"}]}, present=False)
        self.assertIsNone(instance.on_request_body(None, ctx, {}))

    def test_request_returns_none_when_body_is_not_valid_json(self) -> None:
        instance = self._make_policy()
        self.assertIsNone(instance.on_request_body(None, request_context(b"not json"), {}))

    def test_request_returns_none_when_jsonpath_resolves_to_non_string(self) -> None:
        instance = self._make_policy()
        ctx = request_context({"messages": [{"content": 42}]})
        self.assertIsNone(instance.on_request_body(None, ctx, {}))

    def test_request_returns_none_when_request_disabled(self) -> None:
        instance = self._make_policy()
        ctx = request_context({"messages": [{"content": "hello"}]})
        self.assertIsNone(instance.on_request_body(None, ctx, {"request": {"enabled": False}}))

    # --- request blocking ---

    def test_blocks_request_when_content_is_unsafe(self) -> None:
        FakeRequests.reset(response=nemoguard_response("unsafe", categories="Violence"))
        instance = self._make_policy()

        result = instance.on_request_body(
            None,
            request_context({"messages": [{"role": "user", "content": "violent text"}]}),
            {},
        )

        self.assertIsInstance(result, ImmediateResponse)
        self.assertEqual(400, result.status_code)
        body = json.loads(result.body)
        self.assertEqual("NVIDIA_NEMOGUARD_CONTENT_SAFETY", body["type"])
        self.assertEqual("GUARDRAIL_INTERVENED", body["message"]["action"])
        self.assertEqual("REQUEST", body["message"]["direction"])

    def test_blocks_request_with_openai_error_on_llm_api(self) -> None:
        FakeRequests.reset(response=nemoguard_response("unsafe", categories="Violence"))
        instance = self._make_policy()
        ctx = request_context({"messages": [{"role": "user", "content": "violent text"}]})
        ctx.shared = SimpleNamespace(api_kind="LlmProvider")

        result = instance.on_request_body(None, ctx, {})

        self.assertIsInstance(result, ImmediateResponse)
        self.assertEqual(400, result.status_code)
        error = json.loads(result.body)["error"]
        self.assertEqual("Unsafe content detected.", error["message"])
        self.assertEqual("invalid_request_error", error["type"])
        self.assertIsNone(error["param"])
        self.assertEqual("guardrail_intervened", error["code"])
        self.assertEqual("REQUEST", error["guardrail"]["direction"])
        self.assertEqual("NeMo Guard Content Safety", error["guardrail"]["name"])

    def test_service_error_is_openai_server_error_on_llm_api(self) -> None:
        FakeRequests.reset(error=RuntimeError("down"))
        instance = self._make_policy()
        ctx = request_context({"messages": [{"role": "user", "content": "hi"}]})
        ctx.shared = SimpleNamespace(api_kind="LlmProxy")

        result = instance.on_request_body(None, ctx, {"request": {"passthroughOnError": False}})

        self.assertIsInstance(result, ImmediateResponse)
        self.assertEqual(503, result.status_code)
        error = json.loads(result.body)["error"]
        self.assertEqual("server_error", error["type"])
        self.assertIsNone(error["code"])

    def test_passes_request_when_content_is_safe(self) -> None:
        FakeRequests.reset(response=nemoguard_response("safe"))
        instance = self._make_policy()

        result = instance.on_request_body(
            None,
            request_context({"messages": [{"role": "user", "content": "Hello!"}]}),
            {},
        )

        self.assertIsNone(result)

    def test_custom_block_status_code_used_for_request(self) -> None:
        FakeRequests.reset(response=nemoguard_response("unsafe", categories="Violence"))
        instance = self._make_policy()

        result = instance.on_request_body(
            None,
            request_context({"messages": [{"content": "bad text"}]}),
            {"request": {"blockStatusCode": 403}},
        )

        self.assertIsInstance(result, ImmediateResponse)
        self.assertEqual(403, result.status_code)

    def test_show_assessment_includes_categories_in_request_block(self) -> None:
        FakeRequests.reset(response=nemoguard_response("unsafe", categories="Violence, Profanity"))
        instance = self._make_policy()

        result = instance.on_request_body(
            None,
            request_context({"messages": [{"content": "bad text"}]}),
            {"request": {"showAssessment": True}},
        )

        body = json.loads(result.body)
        self.assertIn("assessments", body["message"])
        self.assertIn("S1", body["message"]["assessments"]["categories"])

    def test_assessment_not_included_by_default_for_request(self) -> None:
        FakeRequests.reset(response=nemoguard_response("unsafe", categories="Violence"))
        instance = self._make_policy()

        result = instance.on_request_body(
            None,
            request_context({"messages": [{"content": "bad text"}]}),
            {},
        )

        body = json.loads(result.body)
        self.assertNotIn("assessments", body["message"])

    def test_passes_through_when_detected_category_is_not_blocked(self) -> None:
        FakeRequests.reset(response=nemoguard_response("unsafe", categories="Violence"))
        instance = self._make_policy()

        result = instance.on_request_body(
            None,
            request_context({"messages": [{"content": "bad text"}]}),
            {"request": {"categories": {"violence": False}}},
        )

        self.assertIsNone(result)

    def test_blocks_when_any_detected_category_is_blocked(self) -> None:
        FakeRequests.reset(response=nemoguard_response("unsafe", categories="Violence, Profanity"))
        instance = self._make_policy()

        result = instance.on_request_body(
            None,
            request_context({"messages": [{"content": "bad text"}]}),
            {"request": {"categories": {"violence": False, "profanity": True}}},
        )

        self.assertIsInstance(result, ImmediateResponse)

    # --- request error handling ---

    def test_returns_503_on_nemoguard_request_error_by_default(self) -> None:
        FakeRequests.reset(error=ConnectionError("Connection refused"))
        instance = self._make_policy()

        result = instance.on_request_body(
            None,
            request_context({"messages": [{"content": "hello"}]}),
            {},
        )

        self.assertIsInstance(result, ImmediateResponse)
        self.assertEqual(503, result.status_code)
        body = json.loads(result.body)
        self.assertEqual("SERVICE_UNAVAILABLE", body["message"]["action"])

    def test_passes_through_request_on_error_with_passthrough_flag(self) -> None:
        FakeRequests.reset(error=ConnectionError("Connection refused"))
        instance = self._make_policy()

        result = instance.on_request_body(
            None,
            request_context({"messages": [{"content": "hello"}]}),
            {"request": {"passthroughOnError": True}},
        )

        self.assertIsNone(result)

    def test_string_false_passthrough_on_error_is_fail_closed(self) -> None:
        FakeRequests.reset(error=ConnectionError("Connection refused"))
        instance = self._make_policy()

        result = instance.on_request_body(
            None,
            request_context({"messages": [{"content": "hello"}]}),
            {"request": {"passthroughOnError": "false"}},
        )

        self.assertIsInstance(result, ImmediateResponse)
        self.assertEqual(503, result.status_code)

    # --- response passthrough cases ---

    def test_response_returns_none_when_response_disabled(self) -> None:
        instance = self._make_policy()
        ctx = response_context({"choices": [{"message": {"content": "reply"}}]})
        self.assertIsNone(instance.on_response_body(None, ctx, {}))

    def test_response_returns_none_when_body_is_absent(self) -> None:
        instance = self._make_policy()
        self.assertIsNone(instance.on_response_body(None, response_context(None), {"response": {"enabled": True}}))

    def test_response_returns_none_when_body_is_not_valid_json(self) -> None:
        instance = self._make_policy()
        ctx = response_context(b"not json")
        self.assertIsNone(instance.on_response_body(None, ctx, {"response": {"enabled": True}}))

    def test_response_returns_none_when_jsonpath_resolves_to_non_string(self) -> None:
        instance = self._make_policy()
        ctx = response_context({"choices": [{"message": {"content": 42}}]})
        self.assertIsNone(instance.on_response_body(None, ctx, {"response": {"enabled": True}}))

    # --- response blocking ---

    def test_blocks_response_when_content_is_unsafe(self) -> None:
        FakeRequests.reset(response=nemoguard_response("safe", response_safety="unsafe", categories="Violence"))
        instance = self._make_policy()

        ctx = response_context(
            response_payload={"choices": [{"message": {"content": "violent reply"}}]},
            request_payload={"messages": [{"role": "user", "content": "question"}]},
        )

        result = instance.on_response_body(
            None,
            ctx,
            {"response": {"enabled": True}},
        )

        self.assertIsInstance(result, ImmediateResponse)
        self.assertEqual(200, result.status_code)
        body = json.loads(result.body)
        self.assertEqual("NVIDIA_NEMOGUARD_CONTENT_SAFETY", body["type"])
        self.assertEqual("GUARDRAIL_INTERVENED", body["message"]["action"])
        self.assertEqual("RESPONSE", body["message"]["direction"])

    def test_response_block_is_400_openai_error_on_llm_api(self) -> None:
        FakeRequests.reset(response=nemoguard_response("safe", response_safety="unsafe", categories="Violence"))
        instance = self._make_policy()
        ctx = response_context(
            response_payload={"choices": [{"message": {"content": "violent reply"}}]},
            request_payload={"messages": [{"role": "user", "content": "question"}]},
        )
        ctx.shared = SimpleNamespace(api_kind="LlmProvider")

        result = instance.on_response_body(None, ctx, {"response": {"enabled": True}})

        self.assertIsInstance(result, ImmediateResponse)
        self.assertEqual(400, result.status_code)
        error = json.loads(result.body)["error"]
        self.assertEqual("guardrail_intervened", error["code"])
        self.assertEqual("RESPONSE", error["guardrail"]["direction"])

    def test_passes_response_when_content_is_safe(self) -> None:
        FakeRequests.reset(response=nemoguard_response("safe", response_safety="safe"))
        instance = self._make_policy()

        ctx = response_context(
            response_payload={"choices": [{"message": {"content": "safe reply"}}]},
            request_payload={"messages": [{"role": "user", "content": "question"}]},
        )

        result = instance.on_response_body(
            None,
            ctx,
            {"response": {"enabled": True}},
        )

        self.assertIsNone(result)

    def test_show_assessment_includes_categories_in_response_block(self) -> None:
        FakeRequests.reset(response=nemoguard_response("safe", response_safety="unsafe", categories="Profanity"))
        instance = self._make_policy()

        ctx = response_context(
            response_payload={"choices": [{"message": {"content": "bad reply"}}]},
            request_payload={"messages": [{"role": "user", "content": "question"}]},
        )

        result = instance.on_response_body(
            None,
            ctx,
            {"response": {"enabled": True, "showAssessment": True}},
        )

        body = json.loads(result.body)
        self.assertIn("assessments", body["message"])

    # --- response error handling ---

    def test_returns_503_on_nemoguard_response_error_by_default(self) -> None:
        FakeRequests.reset(error=ConnectionError("Connection refused"))
        instance = self._make_policy()

        ctx = response_context(
            response_payload={"choices": [{"message": {"content": "reply"}}]},
            request_payload={"messages": [{"role": "user", "content": "question"}]},
        )

        result = instance.on_response_body(
            None,
            ctx,
            {"response": {"enabled": True}},
        )

        self.assertIsInstance(result, ImmediateResponse)
        self.assertEqual(503, result.status_code)

    def test_passes_through_response_on_error_with_passthrough_flag(self) -> None:
        FakeRequests.reset(error=ConnectionError("Connection refused"))
        instance = self._make_policy()

        ctx = response_context(
            response_payload={"choices": [{"message": {"content": "reply"}}]},
            request_payload={"messages": [{"role": "user", "content": "question"}]},
        )

        result = instance.on_response_body(
            None,
            ctx,
            {"response": {"enabled": True, "passthroughOnError": True}},
        )

        self.assertIsNone(result)

    # --- HTTP call details ---

    def test_sends_api_key_as_bearer_token(self) -> None:
        FakeRequests.reset(response=nemoguard_response("safe"))
        instance = self._make_policy(apiKey="my-secret")

        instance.on_request_body(
            None,
            request_context({"messages": [{"content": "hello"}]}),
            {},
        )

        self.assertEqual("Bearer my-secret", FakeRequests.post_calls[0]["headers"]["Authorization"])

    def test_does_not_send_auth_header_without_api_key(self) -> None:
        FakeRequests.reset(response=nemoguard_response("safe"))
        instance = self._make_policy()

        instance.on_request_body(
            None,
            request_context({"messages": [{"content": "hello"}]}),
            {},
        )

        self.assertNotIn("Authorization", FakeRequests.post_calls[0]["headers"])

    def test_posts_to_correct_endpoint_url(self) -> None:
        FakeRequests.reset(response=nemoguard_response("safe"))
        instance = self._make_policy()

        instance.on_request_body(
            None,
            request_context({"messages": [{"content": "hello"}]}),
            {},
        )

        self.assertEqual(f"{ENDPOINT}/v1/chat/completions", FakeRequests.post_calls[0]["url"])

    def test_uses_configured_timeout(self) -> None:
        FakeRequests.reset(response=nemoguard_response("safe"))
        instance = self._make_policy(timeout=45)

        instance.on_request_body(
            None,
            request_context({"messages": [{"content": "hello"}]}),
            {},
        )

        self.assertEqual(45, FakeRequests.post_calls[0]["timeout"])

    def test_response_context_user_message_included_in_prompt(self) -> None:
        FakeRequests.reset(response=nemoguard_response("safe", response_safety="safe"))
        instance = self._make_policy()

        ctx = response_context(
            response_payload={"choices": [{"message": {"content": "assistant reply"}}]},
            request_payload={"messages": [{"role": "user", "content": "my question"}]},
        )

        instance.on_response_body(None, ctx, {"response": {"enabled": True}})

        prompt_content = FakeRequests.post_calls[0]["json"]["messages"][0]["content"]
        self.assertIn("my question", prompt_content)
        self.assertIn("assistant reply", prompt_content)


if __name__ == "__main__":
    unittest.main()
