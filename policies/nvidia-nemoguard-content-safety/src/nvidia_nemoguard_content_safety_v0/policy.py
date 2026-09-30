# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import json
import logging
import re as _re
from dataclasses import dataclass
from typing import Any

import requests as http_client

from apip_sdk_core import (
    BodyProcessingMode,
    DownstreamResponseModifications,
    ImmediateResponse,
    ProcessingMode,
    RequestPolicy,
    ResponsePolicy,
    UpstreamRequestModifications,
)

LOGGER = logging.getLogger(__name__)


_LLM_API_KINDS = frozenset({"LlmProvider", "LlmProxy"})


def _status(status_code: int, llm: bool) -> int:
    """Preserve configured error statuses; only turn an otherwise-successful LLM
    guardrail intervention into an HTTP error."""
    return 400 if llm and status_code < 400 else status_code


def _is_llm_api(ctx) -> bool:
    """Whether the request belongs to an LLM API, whose clients expect OpenAI-compatible errors."""
    return getattr(getattr(ctx, "shared", None), "api_kind", "") in _LLM_API_KINDS


def _error_body(msg: dict, status_code: int, llm: bool) -> bytes:
    """Render a guardrail error: OpenAI-compatible for LLM APIs, the legacy
    {"type": "NVIDIA_NEMOGUARD_CONTENT_SAFETY", "message": {...}} shape for other API kinds."""
    if not llm:
        return json.dumps({"type": "NVIDIA_NEMOGUARD_CONTENT_SAFETY", "message": msg}).encode()
    intervened = msg.get("action") == "GUARDRAIL_INTERVENED"
    error_type = "server_error" if not intervened and status_code >= 500 else "invalid_request_error"
    guardrail = {"name": msg.get("interveningGuardrail", "NeMo Guard Content Safety")}
    for key in ("direction", "assessments"):
        if key in msg:
            guardrail[key] = msg[key]
    return json.dumps({
        "error": {
            "message": msg.get("actionReason", ""),
            "type": error_type,
            "param": None,
            "code": "guardrail_intervened" if intervened else None,
            "guardrail": guardrail,
        }
    }).encode()

_DEFAULT_MODEL = "nemoguard"
_DEFAULT_REQUEST_JSON_PATH = "$.messages[-1].content"
_DEFAULT_RESPONSE_JSON_PATH = "$.choices[0].message.content"

_PASSTHROUGH_REQUEST: UpstreamRequestModifications | None = None
_PASSTHROUGH_RESPONSE: DownstreamResponseModifications | None = None

_SAFETY_POLICY = """\
S1: Violence
S2: Sexual
S3: Criminal Planning/Confessions
S4: Guns and Illegal Weapons
S5: Controlled/Regulated Substances
S6: Suicide and Self Harm
S7: Sexual (minor)
S8: Hate/Identity Hate
S9: PII/Privacy
S10: Harassment
S11: Threat
S12: Profanity
S13: Needs Caution
S14: Other
S15: Manipulation
S16: Fraud/Deception
S17: Malware
S18: High Risk Gov Decision Making
S19: Political/Misinformation/Conspiracy
S20: Copyright/Trademark/Plagiarism
S21: Unauthorized Advice
S22: Illegal Activity
S23: Immoral/Unethical"""

_CATEGORY_NAME_TO_CODE: dict[str, str] = {
    "violence": "S1",
    "sexual": "S2",
    "criminal planning/confessions": "S3",
    "criminal planning": "S3",
    "guns and illegal weapons": "S4",
    "controlled/regulated substances": "S5",
    "suicide and self harm": "S6",
    "sexual (minor)": "S7",
    "hate/identity hate": "S8",
    "pii/privacy": "S9",
    "harassment": "S10",
    "threat": "S11",
    "profanity": "S12",
    "needs caution": "S13",
    "other": "S14",
    "manipulation": "S15",
    "fraud/deception": "S16",
    "malware": "S17",
    "high risk gov decision making": "S18",
    "political/misinformation/conspiracy": "S19",
    "copyright/trademark/plagiarism": "S20",
    "unauthorized advice": "S21",
    "illegal activity": "S22",
    "immoral/unethical": "S23",
}

_CATEGORY_CODES: dict[str, str] = {
    "violence": "S1",
    "sexual": "S2",
    "criminal_planning": "S3",
    "guns_weapons": "S4",
    "regulated_substances": "S5",
    "suicide_self_harm": "S6",
    "sexual_minor": "S7",
    "hate_identity": "S8",
    "pii_privacy": "S9",
    "harassment": "S10",
    "threat": "S11",
    "profanity": "S12",
    "needs_caution": "S13",
    "other": "S14",
    "manipulation": "S15",
    "fraud_deception": "S16",
    "malware": "S17",
    "high_risk_gov": "S18",
    "misinformation": "S19",
    "copyright": "S20",
    "unauthorized_advice": "S21",
    "illegal_activity": "S22",
    "immoral_unethical": "S23",
}


@dataclass(frozen=True)
class SystemParams:
    endpoint: str
    api_key: str
    model: str
    timeout: int


@dataclass(frozen=True)
class PhaseParams:
    enabled: bool
    json_path: str
    block_status_code: int
    blocked_codes: frozenset[str] | None
    passthrough_on_error: bool
    show_assessment: bool


@dataclass(frozen=True)
class RequestParams:
    request: PhaseParams
    response: PhaseParams


class NemoGuardContentSafetyPolicy(RequestPolicy, ResponsePolicy):
    """Content safety guardrail using NVIDIA NeMo Guard."""

    def __init__(self, system_params: SystemParams) -> None:
        self._params = system_params

    def mode(self) -> ProcessingMode:
        return ProcessingMode(
            request_body_mode=BodyProcessingMode.BUFFER,
            response_body_mode=BodyProcessingMode.BUFFER,
        )

    def on_request_body(self, execution_ctx, req_ctx, params):
        req_params = normalize_request_params(params)
        if not req_params.request.enabled:
            return _PASSTHROUGH_REQUEST

        if not (req_ctx.body and req_ctx.body.present and req_ctx.body.content):
            return _PASSTHROUGH_REQUEST

        try:
            body_data = json.loads(req_ctx.body.content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _PASSTHROUGH_REQUEST

        user_text = _resolve_jsonpath(body_data, req_params.request.json_path)
        if not user_text or not isinstance(user_text, str):
            return _PASSTHROUGH_REQUEST

        try:
            unsafe, category_codes = _call_nemoguard(
                self._params,
                messages=[{"role": "user", "content": user_text}],
                check_phase="request",
            )
        except Exception as exc:
            LOGGER.warning(
                "nemoguard request error (request_id=%s): %s",
                getattr(execution_ctx, "request_id", None),
                exc,
            )
            if req_params.request.passthrough_on_error:
                return _PASSTHROUGH_REQUEST
            return ImmediateResponse(
                status_code=503,
                headers={"content-type": "application/json"},
                body=_error_body({"action": "SERVICE_UNAVAILABLE", "actionReason": "Content safety service unavailable."}, 503, _is_llm_api(req_ctx)),
            )

        if unsafe:
            if (
                req_params.request.blocked_codes is not None
                and category_codes
                and not any(c in req_params.request.blocked_codes for c in category_codes)
            ):
                return _PASSTHROUGH_REQUEST
            msg: dict = {
                "action": "GUARDRAIL_INTERVENED",
                "interveningGuardrail": "NeMo Guard Content Safety",
                "actionReason": "Unsafe content detected.",
                "direction": "REQUEST",
            }
            if req_params.request.show_assessment and category_codes:
                msg["assessments"] = {"categories": category_codes}
            return ImmediateResponse(
                status_code=_status(req_params.request.block_status_code, _is_llm_api(req_ctx)),
                headers={"content-type": "application/json"},
                body=_error_body(msg, req_params.request.block_status_code, _is_llm_api(req_ctx)),
            )

        return _PASSTHROUGH_REQUEST

    def on_response_body(self, execution_ctx, res_ctx, params):
        req_params = normalize_request_params(params)
        if not req_params.response.enabled:
            return _PASSTHROUGH_RESPONSE

        if not (res_ctx.body and res_ctx.body.present and res_ctx.body.content):
            return _PASSTHROUGH_RESPONSE

        messages: list[dict] = []

        if res_ctx.request_body and res_ctx.request_body.present and res_ctx.request_body.content:
            req_json_path = req_params.request.json_path
            try:
                req_data = json.loads(res_ctx.request_body.content)
                user_text = _resolve_jsonpath(req_data, req_json_path)
                if user_text and isinstance(user_text, str):
                    messages.append({"role": "user", "content": user_text})
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        try:
            res_data = json.loads(res_ctx.body.content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _PASSTHROUGH_RESPONSE

        assistant_text = _resolve_jsonpath(res_data, req_params.response.json_path)
        if not assistant_text or not isinstance(assistant_text, str):
            return _PASSTHROUGH_RESPONSE

        messages.append({"role": "assistant", "content": assistant_text})

        try:
            unsafe, category_codes = _call_nemoguard(
                self._params,
                messages=messages,
                check_phase="response",
            )
        except Exception as exc:
            LOGGER.warning(
                "nemoguard response error (request_id=%s): %s",
                getattr(execution_ctx, "request_id", None),
                exc,
            )
            if req_params.response.passthrough_on_error:
                return _PASSTHROUGH_RESPONSE
            return ImmediateResponse(
                status_code=503,
                headers={"content-type": "application/json"},
                body=_error_body({"action": "SERVICE_UNAVAILABLE", "actionReason": "Content safety service unavailable."}, 503, _is_llm_api(res_ctx)),
            )

        if unsafe:
            if req_params.response.blocked_codes is not None and not any(
                c in req_params.response.blocked_codes for c in category_codes
            ):
                return _PASSTHROUGH_RESPONSE
            msg: dict = {
                "action": "GUARDRAIL_INTERVENED",
                "interveningGuardrail": "NeMo Guard Content Safety",
                "actionReason": "Unsafe content detected.",
                "direction": "RESPONSE",
            }
            if req_params.response.show_assessment and category_codes:
                msg["assessments"] = {"categories": category_codes}
            return ImmediateResponse(
                status_code=_status(200, _is_llm_api(res_ctx)),
                headers={"content-type": "application/json"},
                body=_error_body(msg, 200, _is_llm_api(res_ctx)),
            )

        return _PASSTHROUGH_RESPONSE


def get_policy(metadata, params):
    return NemoGuardContentSafetyPolicy(normalize_system_params(params))


def normalize_system_params(params: dict[str, Any] | None) -> SystemParams:
    params = params or {}

    endpoint = params.get("endpoint", "")
    if not isinstance(endpoint, str):
        LOGGER.warning("NemoGuard: invalid endpoint %r, using empty string", endpoint)
        endpoint = ""
    endpoint = endpoint.strip().rstrip("/")

    api_key = params.get("apiKey", "")
    if not isinstance(api_key, str):
        api_key = ""

    model = params.get("model", _DEFAULT_MODEL)
    if not isinstance(model, str) or not model.strip():
        LOGGER.warning("NemoGuard: invalid model %r, falling back to %s", model, _DEFAULT_MODEL)
        model = _DEFAULT_MODEL
    else:
        model = model.strip()

    timeout = _coerce_int_in_range(params.get("timeout", 30), lo=1, hi=120, default=30)

    return SystemParams(endpoint=endpoint, api_key=api_key, model=model, timeout=timeout)


def normalize_request_params(params: dict[str, Any] | None) -> RequestParams:
    params = params or {}

    req_cfg = params.get("request", {})
    if not isinstance(req_cfg, dict):
        req_cfg = {}

    res_cfg = params.get("response", {})
    if not isinstance(res_cfg, dict):
        res_cfg = {}

    return RequestParams(
        request=_normalize_phase_params(
            req_cfg,
            default_enabled=True,
            default_json_path=_DEFAULT_REQUEST_JSON_PATH,
        ),
        response=_normalize_phase_params(
            res_cfg,
            default_enabled=False,
            default_json_path=_DEFAULT_RESPONSE_JSON_PATH,
        ),
    )


def _normalize_phase_params(
    cfg: dict,
    *,
    default_enabled: bool,
    default_json_path: str,
) -> PhaseParams:
    enabled = _coerce_bool(cfg.get("enabled"), default=default_enabled)

    json_path = cfg.get("jsonPath", default_json_path)
    if not isinstance(json_path, str) or not json_path.strip():
        json_path = default_json_path
    else:
        json_path = json_path.strip()

    block_status_code = _coerce_int_in_range(
        cfg.get("blockStatusCode", 400), lo=400, hi=599, default=400
    )
    blocked_codes = _blocked_codes(cfg.get("categories", {}))
    passthrough_on_error = _coerce_bool(cfg.get("passthroughOnError"), default=False)
    show_assessment = _coerce_bool(cfg.get("showAssessment"), default=False)

    return PhaseParams(
        enabled=enabled,
        json_path=json_path,
        block_status_code=block_status_code,
        blocked_codes=blocked_codes,
        passthrough_on_error=passthrough_on_error,
        show_assessment=show_assessment,
    )


def _blocked_codes(categories_cfg: Any) -> frozenset[str] | None:
    """Return the set of S-codes to block, or None to block all categories."""
    if not isinstance(categories_cfg, dict) or not categories_cfg:
        return None
    return frozenset(
        code
        for key, code in _CATEGORY_CODES.items()
        if _coerce_bool(categories_cfg.get(key), default=True)
    )


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() in ("true", "1", "yes"):
            return True
        if value.lower() in ("false", "0", "no"):
            return False
    if isinstance(value, int):
        return bool(value)
    return default


def _coerce_int_in_range(value: Any, lo: int, hi: int, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int) and lo <= value <= hi:
        return value
    if isinstance(value, float) and value.is_integer() and lo <= int(value) <= hi:
        return int(value)
    if isinstance(value, str):
        try:
            f = float(value)
            if f.is_integer() and lo <= int(f) <= hi:
                return int(f)
        except ValueError:
            pass
    return default


def _build_nemoguard_prompt(user_text: str, assistant_text: str | None = None) -> str:
    """Build the structured prompt required by the NVIDIA NeMo Guard model."""
    task = (
        "Check if there is unsafe content in the user or agent messages in the below "
        "conversation in accordance with our safety policy with the below categories. "
        "Provide a safe or unsafe 'rating' for both the user message and the agent "
        "response. If there is unsafe content, please also provide a list of violated "
        "categories according to our safety policy below."
    )

    conversation_lines = [f"user: {user_text}"]
    if assistant_text:
        conversation_lines.append(f"agent: {assistant_text}")

    output_schema = (
        '{"User Safety": safe or unsafe rating for the user message, '
        '"Response Safety": safe or unsafe rating for the agent response. '
        "Omit if no agent response present. "
        '"Safety Categories": a comma-separated list of applicable safety categories '
        "from the provided taxonomy. Omit if all safe.}"
    )

    return (
        f"Task: {task}\n"
        f"<BEGIN UNSAFE CONTENT CATEGORIES>\n{_SAFETY_POLICY}\n<END UNSAFE CONTENT CATEGORIES>\n"
        f"<BEGIN CONVERSATION>\n{chr(10).join(conversation_lines)}\n<END CONVERSATION>\n"
        f"Provide your safety assessment for the above conversation in the below output JSON format:\n"
        f"{output_schema}\n"
        f"Do not include anything other than the output JSON in your response.\n"
        f"Output JSON:"
    )


def _call_nemoguard(
    params: SystemParams,
    messages: list[dict],
    check_phase: str = "request",
) -> tuple[bool, list[str]]:
    """Call the NeMo Guard endpoint. Returns (unsafe, [category_codes]).

    check_phase="request"  → inspects "User Safety" in the response JSON.
    check_phase="response" → inspects "Response Safety" in the response JSON.
    """
    user_text = next((m["content"] for m in messages if m["role"] == "user"), None)
    assistant_text = next((m["content"] for m in messages if m["role"] == "assistant"), None)

    if not user_text:
        return False, []

    prompt = _build_nemoguard_prompt(user_text, assistant_text)

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if params.api_key:
        headers["Authorization"] = f"Bearer {params.api_key}"

    payload = {
        "model": params.model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 200,
        "temperature": 0,
    }

    response = http_client.post(
        f"{params.endpoint}/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=params.timeout,
    )
    response.raise_for_status()
    data = response.json()

    raw: str = data["choices"][0]["message"]["content"].strip()

    try:
        result: dict = json.loads(raw)
    except json.JSONDecodeError:
        match = _re.search(r"\{.*\}", raw, _re.DOTALL)
        if not match:
            LOGGER.warning("nemoguard: could not parse model response as JSON: %r", raw[:200])
            return False, []
        result = json.loads(match.group())

    safety_key = "User Safety" if check_phase == "request" else "Response Safety"
    unsafe = result.get(safety_key, "safe").strip().lower() == "unsafe"

    if not unsafe:
        return False, []

    cats_str: str = result.get("Safety Categories", "")
    category_codes: list[str] = [
        _CATEGORY_NAME_TO_CODE.get(name.strip().lower(), name.strip())
        for name in cats_str.split(",")
        if name.strip()
    ]
    return True, category_codes


def _resolve_jsonpath(data: Any, path: str) -> Any:
    """Resolve a simple dotted JSONPath expression against *data*.

    Handles the patterns used throughout this codebase, e.g.:
      ``$.messages[-1].content``         →  data["messages"][-1]["content"]
      ``$.choices[0].message.content``   →  data["choices"][0]["message"]["content"]
    """
    if not path or path == "$":
        return data

    path = path.lstrip("$").lstrip(".")

    segments: list[str | int] = []
    buf = ""
    i = 0
    while i < len(path):
        ch = path[i]
        if ch == "[":
            if buf:
                segments.append(buf)
                buf = ""
            try:
                j = path.index("]", i)
            except ValueError:
                return None
            try:
                segments.append(int(path[i + 1 : j]))
            except ValueError:
                return None
            i = j + 1
            if i < len(path) and path[i] == ".":
                i += 1
        elif ch == ".":
            if buf:
                segments.append(buf)
                buf = ""
            i += 1
        else:
            buf += ch
            i += 1
    if buf:
        segments.append(buf)

    current = data
    for seg in segments:
        if current is None:
            return None
        if isinstance(seg, int):
            if isinstance(current, list) and -len(current) <= seg < len(current):
                current = current[seg]
            else:
                return None
        else:
            current = current.get(seg) if isinstance(current, dict) else None
    return current
