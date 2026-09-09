# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared utilities for the NOOA CyberGym agent.

Infrastructure that doesn't belong in the agent classes:
LLM client creation, reasoning effort, tracing, summarizer installation.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from nooa import Agent, hidden

with hidden:
    from nooa.agents.summarization import TokenBudgetSummarizer, context_budget
    from nooa.atif import enable_atif, install_atif
    from nooa.config.summarizer_config import TokenBudgetConfig
    from nooa.tracing import (
        enable_tracing,
        exporters,
        flush_traces,
        set_session,
        shutdown_traces,
    )
    from nooa.unifiedllm import (
        HttpConfig,
        ResponsesClient,
        RetryConfig,
        get_llm_client,
        get_registry_config,
        resolve_api_key_from_config,
    )

logger = logging.getLogger("nooa_cybergym")

DEFAULT_API_BASE = "https://inference-api.nvidia.com/v1"
DEFAULT_TRACE_DIR = "/logs/artifacts/traces"
DEFAULT_TRAJECTORY_PATH = "/logs/agent/trajectory.json"
USE_BATCHING = False
BATCH_REQUEST_TIMEOUT_S = int(os.environ.get("NOOA_CYBERGYM_REQUEST_TIMEOUT_S", "3900"))
OUTPUT_TOKEN_MARGIN = int(os.environ.get("NOOA_CYBERGYM_OUTPUT_TOKEN_MARGIN", "64000"))
REASONING_OUTPUT_FLOOR = int(os.environ.get("NOOA_CYBERGYM_REASONING_OUTPUT_FLOOR", "16384"))
SUMMARY_MAX_OUTPUT_TOKENS = int(os.environ.get("NOOA_CYBERGYM_SUMMARY_MAX_OUTPUT_TOKENS", "16384"))


# ---------------------------------------------------------------------------
# LLM client creation
# ---------------------------------------------------------------------------


@hidden
def make_llm(
    model_name: str,
    *,
    max_tokens: int = 32768,
    reasoning_effort: str | None = None,
    retry_config: RetryConfig | None = None,
    provider_scoped: bool = False,
    inherit_reasoning_effort: bool = True,
):
    """Create an LLM client for the given model, optionally with reasoning effort."""
    if reasoning_effort is None and inherit_reasoning_effort:
        reasoning_effort = os.environ.get("NOOA_CYBERGYM_REASONING_EFFORT")
    client_kwargs = (
        _provider_scoped_llm_client_kwargs(model_name, max_tokens)
        if provider_scoped
        else _llm_client_kwargs(max_tokens)
    )
    llm = get_llm_client(
        model_name,
        retry_config=retry_config or RetryConfig(max_retries=3),
        **client_kwargs,
    )
    if reasoning_effort:
        _apply_reasoning_effort(llm, reasoning_effort)
    return llm


@hidden
def _llm_client_kwargs(max_output_tokens: int) -> dict[str, object]:
    api_base = (
        os.environ.get("OPENAI_BASE_URL") or os.environ.get("OPENAI_API_BASE") or DEFAULT_API_BASE
    )
    api_key = os.environ.get("NVIDIA_INTERNAL_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        sys.exit(
            "ERROR: no LLM API key set in container env. Configure "
            "NVIDIA_INTERNAL_API_KEY or OPENAI_API_KEY."
        )
    kwargs = _common_llm_client_kwargs(max_output_tokens)
    kwargs.update(
        {
            "api_base": api_base,
            "api_key": api_key,
        }
    )
    if USE_BATCHING:
        # get_llm_client only copies selected YAML keys from llm_config.yaml.
        # Pass request transport overrides here so every model uses the
        # internal gateway batch queue and gets a timeout long enough for it.
        kwargs.update(
            {
                "http_config": HttpConfig(read_timeout=BATCH_REQUEST_TIMEOUT_S),
                "extra_headers": {"X-Inference-Priority": "batch"},
                "timeout": BATCH_REQUEST_TIMEOUT_S,
            }
        )
    return kwargs


@hidden
def _provider_scoped_llm_client_kwargs(
    model_name: str, max_output_tokens: int
) -> dict[str, object]:
    """Resolve an alternate model's own endpoint and credential without fallback.

    Escalation reviewers may use a different provider from the worker.  Both
    fields are mandatory so a missing provider credential can never fall back
    to ``OPENAI_API_KEY`` and be sent to the wrong endpoint.
    """
    config = get_registry_config(model_name)
    api_base = config.get("api_base")
    api_key_env = config.get("api_key_env")
    if not isinstance(api_base, str) or not api_base:
        raise ValueError(
            f"provider-scoped model {model_name!r} must declare api_base in llm_config.yaml"
        )
    if not isinstance(api_key_env, str) or not api_key_env:
        raise ValueError(
            f"provider-scoped model {model_name!r} must declare api_key_env in llm_config.yaml"
        )
    api_key = resolve_api_key_from_config(
        model_name,
        config,
        allowed_env_vars={api_key_env},
    )
    if not api_key:
        raise RuntimeError(
            f"provider-scoped model {model_name!r} requires credential env {api_key_env!r}"
        )

    configured_max_tokens = config.get("max_tokens")
    if isinstance(configured_max_tokens, int) and configured_max_tokens > 0:
        max_output_tokens = min(max_output_tokens, configured_max_tokens)
    kwargs = _common_llm_client_kwargs(max_output_tokens)
    kwargs.update({"api_base": api_base, "api_key": api_key})
    return kwargs


@hidden
def _common_llm_client_kwargs(max_output_tokens: int) -> dict[str, object]:
    return {
        "max_tokens": max_output_tokens,
        "output_token_margin": OUTPUT_TOKEN_MARGIN,
        "reasoning_output_floor": REASONING_OUTPUT_FLOOR,
        "usage_log_path": "/logs/artifacts/llm_usage.jsonl",
    }


@hidden
def _apply_reasoning_effort(llm, reasoning_effort: str) -> None:
    config = _llm_config(llm)
    if config is None:
        logger.warning(
            "LLM client has no mutable config; could not apply reasoning_effort=%r",
            reasoning_effort,
        )
        return
    if _is_responses_llm(llm):
        config["reasoning"] = {"effort": reasoning_effort}
    else:
        config["reasoning_effort"] = reasoning_effort
        allowed = list(config.get("allowed_openai_params", []))
        if "reasoning_effort" not in allowed:
            allowed.append("reasoning_effort")
        config["allowed_openai_params"] = allowed


@hidden
def _llm_config(llm) -> dict[str, object] | None:
    config = getattr(llm, "config", None)
    if isinstance(config, dict):
        return config
    for attr in ("client", "_client", "llm", "_llm", "wrapped", "_wrapped"):
        inner = getattr(llm, attr, None)
        inner_config = getattr(inner, "config", None)
        if isinstance(inner_config, dict):
            return inner_config
    return None


@hidden
def _is_responses_llm(llm) -> bool:
    if isinstance(llm, ResponsesClient):
        return True
    candidates = [llm]
    for attr in ("client", "_client", "llm", "_llm", "wrapped", "_wrapped"):
        inner = getattr(llm, attr, None)
        if inner is not None:
            candidates.append(inner)
    for candidate in candidates:
        registry_config = getattr(candidate, "_registry_config", None)
        if isinstance(registry_config, dict) and registry_config.get("client_type") == "responses":
            return True
        config = getattr(candidate, "config", None)
        if isinstance(config, dict) and config.get("client_type") == "responses":
            return True
    return False


# ---------------------------------------------------------------------------
# Summarizer
# ---------------------------------------------------------------------------


@hidden
def install_summarizer(agent: Agent, llm) -> None:
    """Install a non-reasoning summarizer triggered by reserved output room."""
    context_window = llm.context_window
    budget = context_budget(llm, 0.8)
    summary_llm = make_llm(
        llm.model,
        max_tokens=SUMMARY_MAX_OUTPUT_TOKENS,
        reasoning_effort="none",
    )
    summary_config = _llm_config(summary_llm)
    if summary_config is not None:
        summary_config.pop("reasoning", None)
        summary_config.pop("reasoning_effort", None)
        if _is_responses_llm(summary_llm):
            summary_config["reasoning"] = {"effort": "none"}
        else:
            extra_body = dict(summary_config.get("extra_body", {}))
            extra_body["thinking"] = {"type": "disabled"}
            summary_config["extra_body"] = extra_body
    logger.info(
        "context_window=%s summarizer_budget=%d output_margin=%d reasoning_floor=%d agent=%s",
        context_window,
        budget,
        OUTPUT_TOKEN_MARGIN,
        REASONING_OUTPUT_FLOOR,
        type(agent).__name__,
    )
    TokenBudgetSummarizer.install(
        agent,
        llm=summary_llm,
        config=TokenBudgetConfig(
            max_tokens=budget,
            context_window=context_window,
            output_margin=OUTPUT_TOKEN_MARGIN,
            reasoning_output_floor=REASONING_OUTPUT_FLOOR,
        ),
    )


# ---------------------------------------------------------------------------
# Tracing
# ---------------------------------------------------------------------------


@hidden
def configure_tracing(agent, model_name: str) -> None:
    """Set up compact journal + ATIF tracing for one Harbor trial."""
    trace_dir = os.environ.get("NOOA_CYBERGYM_TRACE_DIR") or DEFAULT_TRACE_DIR
    trajectory_path = os.environ.get("NOOA_CYBERGYM_TRAJECTORY_PATH") or DEFAULT_TRAJECTORY_PATH
    otlp_endpoint = os.environ.get("NOOA_CYBERGYM_OTLP_ENDPOINT")
    session_id = os.environ.get("NOOA_CYBERGYM_SESSION_ID") or "nooa-cybergym-trial"

    enabled: list[str] = []
    try:
        Path(trace_dir).mkdir(parents=True, exist_ok=True)
        Path(trajectory_path).parent.mkdir(parents=True, exist_ok=True)

        active_exporters = [exporters.journal_file(trace_dir)]
        enabled.append(f"journal-file:{trace_dir}")

        if otlp_endpoint:
            active_exporters.append(exporters.journal(endpoint=otlp_endpoint))
            enabled.append(f"journal:{otlp_endpoint}")

        enable_tracing(exporters=active_exporters)
        set_session(session_id)

        # Install ATIF on the orchestrator: single trajectory file, cascades
        # to standalone @strategy functions in this async context.
        atif_uninstall = install_atif(
            agent.event_manager,
            path=trajectory_path,
            session_id=session_id,
            agent_name="nooa-cybergym",
            agent_version="0.1.0",
            agent_model_name=model_name,
            cascade_to_standalones=True,
        )
        agent._atif_uninstall = atif_uninstall
        enabled.append(f"atif:{trajectory_path}")

        # Auto-instrument sub-agents (Finder/Expander) created after this point.
        # Each gets its own exporter, nested under the orchestrator.
        enable_atif(output_dir=Path(trace_dir) / "atif_subagents", agent_version="0.1.0")
        enabled.append("atif:subagents(auto)")

        logger.info("tracing -> %s", ", ".join(enabled))
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "tracing setup failed (%s: %s); continuing without traces",
            type(exc).__name__,
            exc,
        )


@hidden
def shutdown_tracing() -> None:
    """Flush and shut down all tracing exporters."""
    try:
        flush_traces()
        shutdown_traces()
    except Exception as exc:  # noqa: BLE001
        logger.warning("tracing shutdown failed (%s: %s)", type(exc).__name__, exc)
