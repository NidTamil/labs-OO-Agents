# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed request preparation for DeepSeek's Anthropic-compatible API.

Compatibility source: https://api-docs.deepseek.com/guides/anthropic_api/
(checked 2026-10-21). This is a local compatibility boundary, not provider
certification or native admission. Dispatch belongs to the controller.

Only the model changes. Cache hints are preserved even though the endpoint
ignores them. Ignored fields that would change meaningful semantics are rejected,
including thinking budgets, parallel-tool restrictions and tool-error markers.
File IDs and server tools require separate provider custody and are outside this
native subset. Existing thinking signatures are opaque and remain untouched.
"""

from __future__ import annotations

import base64
import binascii
import math
from copy import deepcopy
from typing import Any
from urllib.parse import urlsplit

DEEPSEEK_NATIVE_BASE_URL = "https://api.deepseek.com/anthropic"
DEEPSEEK_NATIVE_MODEL = "deepseek-flash"
MAX_OUTPUT_TOKENS = 128000


def _require(condition: bool, location: str) -> None:
    if not condition:
        # Never include values or caller-supplied field names in diagnostics.
        raise ValueError(f"DeepSeek native request unsupported or malformed at {location}")


def _object(value: Any, allowed: set[str], required: set[str], location: str) -> None:
    _require(type(value) is dict, location)
    _require(required <= value.keys() <= allowed, location)


def _string(value: Any, location: str, *, nonempty: bool = False) -> None:
    _require(type(value) is str and (not nonempty or bool(value)), location)


def _json_value(value: Any) -> None:
    """Reject non-JSON Python objects before deepcopy can execute custom hooks."""
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float:
        _require(math.isfinite(value), "JSON value")
    elif type(value) is list:
        for item in value:
            _json_value(item)
    elif type(value) is dict:
        for key, item in value.items():
            _require(type(key) is str, "JSON object key")
            _json_value(item)
    else:
        _require(False, "JSON value")


def _cache_hint(block: dict[str, Any], location: str) -> None:
    if "cache_control" not in block:
        return
    hint = block["cache_control"]
    _object(hint, {"type", "ttl"}, {"type"}, location)
    _require(hint["type"] == "ephemeral", location)
    if "ttl" in hint:
        _require(hint["ttl"] in ("5m", "1h"), location)


def _text(block: dict[str, Any], location: str) -> None:
    _object(block, {"type", "text", "cache_control", "citations"}, {"type", "text"}, location)
    _string(block["text"], location)
    _require(block.get("citations", []) == [], location)
    _cache_hint(block, location)


def _image(block: dict[str, Any], location: str) -> None:
    _object(block, {"type", "source", "cache_control"}, {"type", "source"}, location)
    source = block["source"]
    location = f"{location}.source"
    _require(type(source) is dict, location)
    if source.get("type") == "base64":
        _object(source, {"type", "media_type", "data"}, {"type", "media_type", "data"}, location)
        _require(
            source["media_type"] in ("image/jpeg", "image/png", "image/gif", "image/webp"), location
        )
        _string(source["data"], location, nonempty=True)
        try:
            base64.b64decode(source["data"], validate=True)
        except (ValueError, binascii.Error):
            _require(False, location)
    elif source.get("type") == "url":
        _object(source, {"type", "url"}, {"type", "url"}, location)
        _string(source["url"], location, nonempty=True)
        try:
            url = urlsplit(source["url"])
            valid = url.scheme in ("http", "https") and bool(url.hostname)
        except ValueError:
            valid = False
        _require(valid, location)
    else:
        # A GLM file identifier cannot be assumed to identify a DeepSeek upload.
        _require(False, location)
    _cache_hint(block, location)


def _result_content(content: Any, location: str) -> None:
    if type(content) is str:
        return
    _require(type(content) is list, location)
    for index, block in enumerate(content):
        where = f"{location}[{index}]"
        _require(type(block) is dict, where)
        if block.get("type") == "text":
            _text(block, where)
        elif block.get("type") == "image":
            _image(block, where)
        else:
            _require(False, where)


def _messages(messages: Any) -> None:
    _require(type(messages) is list and bool(messages), "messages")
    seen_calls: set[str] = set()
    pending: set[str] = set()
    for index, message in enumerate(messages):
        location = f"messages[{index}]"
        _object(message, {"role", "content"}, {"role", "content"}, location)
        role = message["role"]
        _require(role in ("user", "assistant"), location)
        _require(role != "assistant" or not pending, location)
        content = message["content"]
        if type(content) is str:
            _require(not pending, location)
            continue
        _require(type(content) is list and bool(content), f"{location}.content")
        ordinary_user_content = False
        for offset, block in enumerate(content):
            where = f"{location}.content[{offset}]"
            _require(type(block) is dict, where)
            kind = block.get("type")
            if kind == "text":
                _text(block, where)
            elif kind == "image":
                _require(role == "user", where)
                _image(block, where)
            elif kind == "thinking":
                _require(role == "assistant", where)
                _object(block, {"type", "thinking", "signature"}, {"type", "thinking"}, where)
                _string(block["thinking"], where)
                if "signature" in block:
                    _string(block["signature"], where)
            elif kind == "tool_use":
                _require(role == "assistant", where)
                fields = {"type", "id", "name", "input"}
                _object(block, fields | {"cache_control"}, fields, where)
                _string(block["id"], where, nonempty=True)
                _string(block["name"], where, nonempty=True)
                _require(type(block["input"]) is dict and block["id"] not in seen_calls, where)
                seen_calls.add(block["id"])
                pending.add(block["id"])
                _cache_hint(block, where)
            elif kind == "tool_result":
                _require(role == "user" and not ordinary_user_content, where)
                _object(
                    block,
                    {"type", "tool_use_id", "content", "is_error", "cache_control"},
                    {"type", "tool_use_id"},
                    where,
                )
                _string(block["tool_use_id"], where, nonempty=True)
                _require(block["tool_use_id"] in pending, where)
                _require(block.get("is_error", False) is False, where)
                _result_content(block.get("content", ""), where)
                _cache_hint(block, where)
                pending.remove(block["tool_use_id"])
            else:
                _require(False, where)
            if role == "user" and kind != "tool_result":
                ordinary_user_content = True
                _require(not pending, where)
        if role == "user":
            _require(not pending, location)
    _require(not pending, "messages unresolved tool_use")


def _tools(tools: Any) -> set[str]:
    _require(type(tools) is list, "tools")
    names: set[str] = set()
    for index, tool in enumerate(tools):
        location = f"tools[{index}]"
        _object(
            tool,
            {"name", "input_schema", "description", "cache_control"},
            {"name", "input_schema"},
            location,
        )
        _string(tool["name"], location, nonempty=True)
        _require(tool["name"] not in names, location)
        names.add(tool["name"])
        _require(type(tool["input_schema"]) is dict, location)
        _require(tool["input_schema"].get("type") == "object", location)
        if "description" in tool:
            _string(tool["description"], location)
        _cache_hint(tool, location)
    return names


def _tool_choice(choice: Any, names: set[str]) -> None:
    location = "tool_choice"
    _object(choice, {"type", "name", "disable_parallel_tool_use"}, {"type"}, location)
    _require(choice["type"] in ("auto", "none", "any", "tool"), location)
    _require(choice.get("disable_parallel_tool_use", False) is False, location)
    if choice["type"] == "tool":
        _string(choice.get("name"), location, nonempty=True)
        _require(choice["name"] in names, location)
    else:
        _require("name" not in choice, location)
        if choice["type"] == "any":
            _require(bool(names), location)


def prepare_deepseek_native_request(payload: dict[str, Any]) -> dict[str, Any]:
    """Copy an admitted GLM generation body for the fixed DeepSeek native route.

    Raises ValueError before dispatch for unsupported or malformed semantics.
    The original body and all its descendants remain unchanged. This function
    does not establish task/credential custody, perform requests or accept
    count-token bodies; those remain separate controller responsibilities.
    """
    try:
        _json_value(payload)
    except RecursionError:
        raise ValueError("DeepSeek native request cyclic or excessively nested") from None
    required = {"model", "messages", "max_tokens", "stream", "thinking", "output_config"}
    allowed = required | {
        "system",
        "tools",
        "tool_choice",
        "metadata",
        "temperature",
        "top_p",
        "stop_sequences",
    }
    _object(payload, allowed, required, "request fields")
    _require(payload["model"] in ("glm-5.3", "glm-5.3[1m]"), "model")
    _require(
        type(payload["max_tokens"]) is int and 1 <= payload["max_tokens"] <= MAX_OUTPUT_TOKENS,
        "max_tokens",
    )
    _require(payload["stream"] is True, "stream")
    _object(payload["thinking"], {"type"}, {"type"}, "thinking")
    _require(payload["thinking"]["type"] in ("enabled", "adaptive"), "thinking")
    _object(payload["output_config"], {"effort"}, {"effort"}, "output_config")
    _require(payload["output_config"]["effort"] == "max", "output_config")

    if "system" in payload:
        system = payload["system"]
        if type(system) is not str:
            _require(type(system) is list, "system")
            for index, block in enumerate(system):
                where = f"system[{index}]"
                _require(type(block) is dict and block.get("type") == "text", where)
                _text(block, where)
    if "metadata" in payload:
        _object(payload["metadata"], {"user_id"}, set(), "metadata")
        if "user_id" in payload["metadata"]:
            _string(payload["metadata"]["user_id"], "metadata.user_id")
    for field, lower, upper in (("temperature", 0, 2), ("top_p", 0.95, 1)):
        if field in payload:
            value = payload[field]
            _require(type(value) in (int, float) and lower <= value <= upper, field)
    if "stop_sequences" in payload:
        stops = payload["stop_sequences"]
        _require(type(stops) is list, "stop_sequences")
        for stop in stops:
            _string(stop, "stop_sequences", nonempty=True)

    names = _tools(payload.get("tools", []))
    if "tool_choice" in payload:
        _tool_choice(payload["tool_choice"], names)
    _messages(payload["messages"])
    prepared = deepcopy(payload)
    prepared["model"] = DEEPSEEK_NATIVE_MODEL
    return prepared
