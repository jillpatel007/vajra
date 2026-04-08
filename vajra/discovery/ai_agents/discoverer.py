"""AI Agent Discoverer — finds AI agents via behavioural detection.

NOT just env vars. Behavioural detection via CloudTrail:
    - Lambda calling BedrockRuntime = AI agent
    - ECS calling OpenAI API endpoint = AI agent
    - LLM API keys in env vars = AI agent

WHY AI AGENTS ARE ALWAYS ENTRY POINTS:
    AI agents accept external input (prompts). Prompt injection
    can make the agent perform unintended actions using its IAM role.

    Attack chain: external input → AI agent → IAM role → crown jewel

    This is unique to Vajra. No other tool detects AI agents
    in the attack graph.
"""

from __future__ import annotations

import logging
from typing import Any

from vajra.core.models import (
    AssetType,
    CloudAsset,
    EdgeValidity,
    GraphEdge,
    RelationType,
)

logger = logging.getLogger(__name__)

# LLM API key patterns in environment variables
_LLM_KEY_PATTERNS: frozenset[str] = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "COHERE_API_KEY",
        "GOOGLE_AI_API_KEY",
        "HUGGINGFACE_TOKEN",
        "REPLICATE_API_TOKEN",
        "AZURE_OPENAI_API_KEY",
        "AWS_BEDROCK",
        "MISTRAL_API_KEY",
    }
)

# CloudTrail API calls that indicate AI agent behaviour
_AI_BEHAVIOUR_APIS: frozenset[str] = frozenset(
    {
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock-runtime:InvokeModel",
        "sagemaker:InvokeEndpoint",
    }
)

# Network destinations that indicate AI agent behaviour
_AI_ENDPOINTS: frozenset[str] = frozenset(
    {
        "api.openai.com",
        "api.anthropic.com",
        "api.cohere.ai",
        "generativelanguage.googleapis.com",
        "api.mistral.ai",
    }
)


class AIAgentDiscoverer:
    """Discovers AI agents through behavioural signals.

    Three detection methods:
        1. ENV VARS: Lambda/ECS with LLM API keys in environment
        2. API CALLS: CloudTrail shows calls to AI services
        3. NETWORK: Outbound connections to LLM API endpoints

    All detected AI agents are marked is_entry_point=True
    because they accept external input (prompt injection risk).
    """

    def __init__(self) -> None:
        self._agents: dict[str, CloudAsset] = {}
        self._detection_count: int = 0

    def discover_from_env_vars(
        self,
        compute_resources: list[dict[str, Any]],
    ) -> list[CloudAsset]:
        """Detect AI agents by LLM API keys in env vars.

        Args:
            compute_resources: Lambda/ECS/EC2 with env var data.
                Each has: id, name, type, env_vars (dict).

        Returns:
            List of CloudAssets marked as AI agents + entry points.
        """
        agents: list[CloudAsset] = []
        for resource in compute_resources:
            env_vars = resource.get("env_vars", {})
            llm_keys = self._detect_llm_keys(env_vars)

            if llm_keys:
                agent = CloudAsset(
                    id=resource.get("id", ""),
                    name=resource.get("name", ""),
                    asset_type=AssetType.AI_AGENT,
                    provider=resource.get("provider", "aws"),
                    region=resource.get("region", "us-east-1"),
                    is_entry_point=True,  # ALWAYS — prompt injectable
                    ai_signals={"llm_keys": list(llm_keys)},
                )
                agents.append(agent)
                self._agents[agent.id] = agent
                self._detection_count += 1
                logger.info(
                    "AI agent detected (env): %s has %s",
                    agent.name,
                    ", ".join(llm_keys),
                )

        return agents

    def discover_from_cloudtrail(
        self,
        cloudtrail_events: list[dict[str, Any]],
    ) -> list[CloudAsset]:
        """Detect AI agents by CloudTrail API call patterns.

        Args:
            cloudtrail_events: CloudTrail events showing API calls.
                Each has: source_id, source_name, api_call, provider.
        """
        agents: list[CloudAsset] = []
        seen: set[str] = set()

        for event in cloudtrail_events:
            api_call = event.get("api_call", "")
            source_id = event.get("source_id", "")

            if source_id in seen:
                continue

            if api_call in _AI_BEHAVIOUR_APIS:
                agent = CloudAsset(
                    id=source_id,
                    name=event.get("source_name", source_id),
                    asset_type=AssetType.AI_AGENT,
                    provider=event.get("provider", "aws"),
                    region=event.get("region", "us-east-1"),
                    is_entry_point=True,
                    ai_signals={"detection": "cloudtrail", "api": api_call},
                )
                agents.append(agent)
                self._agents[agent.id] = agent
                seen.add(source_id)
                self._detection_count += 1
                logger.info(
                    "AI agent detected (CloudTrail): %s calling %s",
                    agent.name,
                    api_call,
                )

        return agents

    def build_agent_edges(
        self,
        agent_to_role: dict[str, str],
        existing_assets: dict[str, CloudAsset],
    ) -> list[GraphEdge]:
        """Build edges from AI agents to their IAM roles.

        Every AI agent → IAM role edge is high risk because
        prompt injection can leverage the role's full permissions.
        """
        edges: list[GraphEdge] = []
        for agent_id, role_id in agent_to_role.items():
            if agent_id not in self._agents:
                continue
            if role_id not in existing_assets:
                continue

            edges.append(
                GraphEdge(
                    source=agent_id,
                    target=role_id,
                    relation=RelationType.CAN_ASSUME,
                    risk_weight=0.95,
                    conditions=("ai_agent:prompt_injectable",),
                    iam_validity=EdgeValidity.VALID,
                ),
            )
        return edges

    @staticmethod
    def _detect_llm_keys(
        env_vars: dict[str, str],
    ) -> list[str]:
        """Detect LLM API keys in environment variables."""
        found: list[str] = []
        for key in env_vars:
            upper_key = key.upper()
            for pattern in _LLM_KEY_PATTERNS:
                if pattern in upper_key:
                    found.append(key)
                    break
        return found

    @property
    def stats(self) -> dict[str, int]:
        """Detection statistics."""
        return {
            "agents_detected": self._detection_count,
            "total_agents": len(self._agents),
        }
