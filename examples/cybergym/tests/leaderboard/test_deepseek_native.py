# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline compatibility checks for the native DeepSeek takeover boundary."""

import importlib.util
from copy import deepcopy

import pytest


def prepare(payload):
    from nooa_cybergym.leaderboard.deepseek_native import prepare_deepseek_native_request

    return prepare_deepseek_native_request(payload)


def request():
    return {
        "model": "glm-5.3",
        "stream": True,
        "max_tokens": 128000,
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": "max"},
        "metadata": {"user_id": '{"session_id":"native-session"}'},
        "system": [{"type": "text", "text": "Keep the task's existing instructions."}],
        "tools": [
            {
                "name": "Read",
                "description": "Read a file.",
                "input_schema": {
                    "type": "object",
                    "properties": {"file_path": {"type": "string"}},
                    "required": ["file_path"],
                },
            }
        ],
        "messages": [
            {"role": "user", "content": "Continue the same task."},
            {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "Check the files.", "signature": "original"},
                    {"type": "text", "text": "I will inspect both files."},
                    {
                        "type": "tool_use",
                        "id": "read-a",
                        "name": "Read",
                        "input": {"file_path": "a"},
                    },
                    {
                        "type": "tool_use",
                        "id": "read-b",
                        "name": "Read",
                        "input": {"file_path": "b"},
                    },
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "read-b", "content": "Second file."},
                    {
                        "type": "tool_result",
                        "tool_use_id": "read-a",
                        "content": [{"type": "text", "text": "First file."}],
                    },
                    {"type": "text", "text": "Keep this follow-up too."},
                ],
            },
        ],
    }


def test_compatibility_module_exists():
    assert importlib.util.find_spec("nooa_cybergym.leaderboard.deepseek_native") is not None


@pytest.mark.parametrize("model", ["glm-5.3", "glm-5.3[1m]"])
@pytest.mark.parametrize("thinking", ["adaptive", "enabled"])
def test_preserves_full_native_conversation_and_changes_only_model(model, thinking):
    payload = request()
    payload["model"] = model
    payload["thinking"]["type"] = thinking
    original = deepcopy(payload)
    expected = deepcopy(payload)
    expected["model"] = "deepseek-flash"

    result = prepare(payload)

    assert result == expected
    assert payload == original
    result["messages"][1]["content"][2]["input"]["file_path"] = "changed"
    result["tools"][0]["input_schema"]["required"].append("other")
    assert payload == original


def test_preserves_missing_thinking_signature_without_manufacturing_one():
    payload = request()
    del payload["messages"][1]["content"][0]["signature"]
    assert prepare(payload)["messages"] == payload["messages"]


@pytest.mark.parametrize("limit", [1, 128000])
def test_accepts_output_boundaries(limit):
    payload = request()
    payload["max_tokens"] = limit
    assert prepare(payload)["max_tokens"] == limit


@pytest.mark.parametrize("limit", [0, -1, 128001, True, False, 1.0, "1000", None])
def test_rejects_invalid_output_boundaries(limit):
    payload = request()
    payload["max_tokens"] = limit
    with pytest.raises(ValueError, match="max_tokens"):
        prepare(payload)


@pytest.mark.parametrize("model", ["deepseek-flash", "glm-5.2", "claude-sonnet-4", "", None, []])
def test_rejects_undeclared_source_model(model):
    payload = request()
    payload["model"] = model
    with pytest.raises(ValueError, match="model"):
        prepare(payload)


@pytest.mark.parametrize(
    "field", ["model", "stream", "max_tokens", "thinking", "output_config", "messages"]
)
def test_rejects_missing_native_generation_fields(field):
    payload = request()
    del payload[field]
    with pytest.raises(ValueError):
        prepare(payload)


@pytest.mark.parametrize(
    "field,value",
    [
        ("stream", False),
        ("stream", 1),
        ("thinking", {"type": "disabled"}),
        ("thinking", {"type": "enabled", "budget_tokens": 4000}),
        ("thinking", {"type": "adaptive", "display": "summarized"}),
        ("output_config", {"effort": "high"}),
        ("output_config", {"effort": "max", "format": {"type": "json_schema"}}),
        ("top_k", 40),
        ("container", "existing-container"),
        ("mcp_servers", []),
        ("service_tier", "auto"),
        ("context_management", {"edits": []}),
        ("metadata", {"user_id": "session", "important_instruction": "preserve"}),
        ("metadata", {"user_id": 1}),
        ("temperature", True),
        ("temperature", -0.1),
        ("temperature", 2.1),
        ("top_p", 0.94),
        ("top_p", 1.1),
        ("stop_sequences", "stop"),
        ("stop_sequences", ["stop", 1]),
    ],
)
def test_rejects_unsupported_or_malformed_request_semantics(field, value):
    payload = request()
    payload[field] = value
    original = deepcopy(payload)
    with pytest.raises(ValueError):
        prepare(payload)
    assert payload == original


def test_preserves_supported_optional_settings_and_harmless_cache_hints():
    payload = request()
    payload.update(temperature=0.5, top_p=0.95, stop_sequences=["STOP"])
    cached = [
        payload["system"][0],
        payload["tools"][0],
        payload["messages"][1]["content"][1],
        payload["messages"][1]["content"][2],
        payload["messages"][2]["content"][0],
    ]
    for block in cached:
        block["cache_control"] = {"type": "ephemeral", "ttl": "1h"}
    payload["messages"][1]["content"][1]["citations"] = []
    payload["messages"][2]["content"][0]["is_error"] = False
    payload["tool_choice"] = {"type": "auto", "disable_parallel_tool_use": False}
    expected = deepcopy(payload)
    expected["model"] = "deepseek-flash"
    assert prepare(payload) == expected


@pytest.mark.parametrize(
    "choice",
    [{"type": "auto"}, {"type": "none"}, {"type": "any"}, {"type": "tool", "name": "Read"}],
)
def test_preserves_supported_tool_choice(choice):
    payload = request()
    payload["tool_choice"] = choice
    assert prepare(payload)["tool_choice"] == choice


@pytest.mark.parametrize(
    "choice",
    [
        "auto",
        {},
        {"type": "required"},
        {"type": "tool"},
        {"type": "tool", "name": "Undeclared"},
        {"type": "auto", "name": "Read"},
        {"type": "auto", "disable_parallel_tool_use": True},
        {"type": "auto", "disable_parallel_tool_use": 0},
        {"type": "auto", "future_policy": True},
    ],
)
def test_rejects_unsupported_tool_choice(choice):
    payload = request()
    payload["tool_choice"] = choice
    with pytest.raises(ValueError, match="tool_choice"):
        prepare(payload)


@pytest.mark.parametrize(
    "block",
    [
        {"type": "document"},
        {"type": "redacted_thinking", "data": "opaque"},
        {"type": "mcp_tool_use"},
        {"type": "mcp_tool_result"},
        {"type": "code_execution_tool_result"},
        {"type": "container_upload"},
        {"type": "search_result"},
        {"type": "server_tool_use"},
        {"type": "text", "text": "source", "citations": [{"type": "char_location"}]},
        {"type": "text", "text": 42},
        {"type": "text", "text": "x", "cache_control": {"type": "unexpected"}},
        {"type": "thinking", "thinking": "reasoning", "signature": 42},
        {"type": "unknown"},
        "text",
        None,
    ],
)
def test_rejects_unsupported_or_malformed_content_without_dropping_it(block):
    payload = request()
    payload["messages"][1]["content"].insert(0, block)
    with pytest.raises(ValueError, match="content"):
        prepare(payload)


@pytest.mark.parametrize(
    "messages",
    [
        [],
        {},
        [{"role": "system", "content": "misplaced system instruction"}],
        [{"role": "user", "content": []}],
        [{"role": "user", "content": 123}],
        [{"role": "user", "content": "x", "unknown": True}],
        [{"role": "user", "content": [{"type": "thinking", "thinking": "x"}]}],
        [
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "unknown", "content": "x"}],
            }
        ],
    ],
)
def test_rejects_malformed_messages(messages):
    payload = request()
    payload["messages"] = messages
    with pytest.raises(ValueError, match="messages"):
        prepare(payload)


@pytest.mark.parametrize(
    "corruption",
    [
        "missing_result",
        "duplicate_result",
        "unknown_result",
        "duplicate_call",
        "error_result",
        "nested_unsupported",
    ],
)
def test_rejects_broken_tool_history_or_lost_error_semantics(corruption):
    payload = request()
    calls = payload["messages"][1]["content"]
    results = payload["messages"][2]["content"]
    if corruption == "missing_result":
        results.pop(0)
    elif corruption == "duplicate_result":
        results.insert(0, deepcopy(results[0]))
    elif corruption == "unknown_result":
        results[0]["tool_use_id"] = "unknown"
    elif corruption == "duplicate_call":
        calls[3]["id"] = calls[2]["id"]
    elif corruption == "error_result":
        results[0]["is_error"] = True
    else:
        results[0]["content"] = [{"type": "document", "source": {}}]
    with pytest.raises(ValueError, match="messages"):
        prepare(payload)


@pytest.mark.parametrize(
    "tools",
    [
        {},
        [{"name": "Read"}],
        [{"name": "Read", "input_schema": []}],
        [{"name": "Read", "input_schema": {"type": "string"}}],
        [{"name": "Read", "input_schema": {"type": "object"}, "strict": True}],
        [{"name": "Read", "input_schema": {"type": "object"}, "defer_loading": True}],
        [{"name": "Read", "input_schema": {"type": "object"}, "description": None}],
        [{"type": "bash_20250124", "name": "bash"}],
    ],
)
def test_rejects_malformed_or_unsupported_tool_definitions(tools):
    payload = request()
    payload["tools"] = tools
    with pytest.raises(ValueError, match="tools"):
        prepare(payload)


def test_rejects_duplicate_tool_names():
    payload = request()
    payload["tools"].append(deepcopy(payload["tools"][0]))
    with pytest.raises(ValueError, match="tools"):
        prepare(payload)


@pytest.mark.parametrize(
    "source",
    [
        {"type": "base64", "media_type": "image/png", "data": "aW1hZ2U="},
        {"type": "url", "url": "https://example.org/test.png"},
    ],
)
def test_preserves_supported_images_in_user_message_and_tool_result(source):
    payload = request()
    block = {"type": "image", "source": source}
    payload["messages"][0]["content"] = [block]
    payload["messages"][2]["content"][1]["content"].append(deepcopy(block))
    assert prepare(payload)["messages"] == payload["messages"]


@pytest.mark.parametrize(
    "source",
    [
        {"type": "file", "file_id": "file-from-other-provider"},
        {"type": "url", "url": "file:///private"},
        {"type": "base64", "media_type": "application/pdf", "data": "aW1hZ2U="},
        {"type": "base64", "media_type": "image/png", "data": 123},
        {"type": "url"},
    ],
)
def test_rejects_unsupported_or_provider_local_images(source):
    payload = request()
    payload["messages"][0]["content"] = [{"type": "image", "source": source}]
    with pytest.raises(ValueError, match="source"):
        prepare(payload)


@pytest.mark.parametrize("system", ["system instructions", [{"type": "text", "text": "system"}]])
def test_preserves_supported_system_content(system):
    payload = request()
    payload["system"] = system
    assert prepare(payload)["system"] == system


@pytest.mark.parametrize("system", [None, 7, [{"type": "image", "source": {}}], [{"type": "text"}]])
def test_rejects_malformed_system_content(system):
    payload = request()
    payload["system"] = system
    with pytest.raises(ValueError, match="system"):
        prepare(payload)


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), object(), {1: "non-string key"}])
def test_rejects_non_json_nested_values(invalid):
    payload = request()
    payload["messages"][1]["content"][2]["input"]["file_path"] = invalid
    with pytest.raises(ValueError):
        prepare(payload)


def test_rejects_cyclic_payload():
    payload = request()
    payload["messages"].append(payload)
    with pytest.raises(ValueError):
        prepare(payload)


def test_error_does_not_include_prompt_content():
    payload = request()
    payload["messages"][0]["content"] = {"PRIVATE_TASK_SECRET": "private"}
    with pytest.raises(ValueError) as caught:
        prepare(payload)
    assert "PRIVATE_TASK_SECRET" not in str(caught.value)
