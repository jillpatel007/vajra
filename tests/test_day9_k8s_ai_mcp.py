"""Tests for Day 9 — K8s RBAC, AI Agent Discovery, MCP Security.

PDF requirements:
    - Lambda with ANTHROPIC_API_KEY flagged as entry point
    - K8s ClusterRoleBinding to cluster-admin = CRITICAL edge
    - MCP tool 'write_database' creates edge with risk_weight=0.85
"""

from vajra.core.models import (
    AssetType,
    CloudAsset,
    RelationType,
)
from vajra.discovery.ai_agents.discoverer import AIAgentDiscoverer
from vajra.discovery.ai_agents.mcp_security import MCPSecurityAnalyser
from vajra.discovery.k8s.discoverer import K8sDiscoverer

# ═══════════════════════════════════════════════════════════════════
# K8s RBAC TESTS
# ═══════════════════════════════════════════════════════════════════


class TestK8sDiscoverer:
    """K8s RBAC discovery and edge building."""

    def test_cluster_admin_binding_critical_risk(self) -> None:
        """ClusterRoleBinding to cluster-admin → risk 0.99."""
        from pathlib import Path

        disc = K8sDiscoverer(db_path=Path("fake.duckdb"))

        target = CloudAsset(
            id="target-ns",
            name="production",
            asset_type=AssetType.K8S_CLUSTER_ROLE,
            provider="aws",
            region="default",
        )
        disc._assets["sa-uid-1"] = CloudAsset(
            id="sa-uid-1",
            name="default/webapp",
            asset_type=AssetType.K8S_SERVICE_ACCOUNT,
            provider="aws",
            region="default",
            is_entry_point=True,
        )
        disc._assets["target-ns"] = target

        edges = disc._binding_to_edges(
            {
                "subject_uid": "sa-uid-1",
                "role_name": "cluster-admin",
                "target_uid": "target-ns",
                "type": "ClusterRoleBinding",
            }
        )

        assert len(edges) == 1
        assert edges[0].risk_weight >= 0.99

    def test_service_account_discovered_as_entry_point(self) -> None:
        """ServiceAccounts are always entry points."""
        from pathlib import Path

        disc = K8sDiscoverer(db_path=Path("fake.duckdb"))
        assets, _ = disc.discover_from_rbac(
            service_accounts=[
                {
                    "uid": "sa-1",
                    "name": "webapp",
                    "namespace": "production",
                }
            ],
            role_bindings=[],
            secrets_in_env=[],
        )
        assert len(assets) == 1
        assert assets[0].is_entry_point is True
        assert assets[0].asset_type == AssetType.K8S_SERVICE_ACCOUNT

    def test_secret_env_var_detected(self) -> None:
        """Env var matching secret pattern flagged."""
        assert K8sDiscoverer._has_secret_pattern("ANTHROPIC_API_KEY")
        assert K8sDiscoverer._has_secret_pattern("DB_PASSWORD")
        assert K8sDiscoverer._has_secret_pattern("AWS_SECRET_ACCESS_KEY")
        assert not K8sDiscoverer._has_secret_pattern("APP_NAME")
        assert not K8sDiscoverer._has_secret_pattern("LOG_LEVEL")

    def test_unknown_role_no_edge(self) -> None:
        """Empty role name → no edge (default-DENY)."""
        from pathlib import Path

        disc = K8sDiscoverer(db_path=Path("fake.duckdb"))
        disc._assets["sa-1"] = CloudAsset(
            id="sa-1",
            name="sa",
            asset_type=AssetType.K8S_SERVICE_ACCOUNT,
            provider="aws",
            region="default",
        )
        edges = disc._binding_to_edges(
            {
                "subject_uid": "sa-1",
                "role_name": "",
                "target_uid": "",
                "type": "RoleBinding",
            }
        )
        assert len(edges) == 0


# ═══════════════════════════════════════════════════════════════════
# AI AGENT TESTS
# ═══════════════════════════════════════════════════════════════════


class TestAIAgentDiscoverer:
    """AI agent detection through behavioural signals."""

    def test_lambda_with_anthropic_key_is_agent(self) -> None:
        """Lambda with ANTHROPIC_API_KEY → AI agent + entry point.

        PDF requirement: "Lambda with ANTHROPIC_API_KEY flagged as entry point."
        """
        disc = AIAgentDiscoverer()
        agents = disc.discover_from_env_vars(
            [
                {
                    "id": "lambda-chat",
                    "name": "ChatBot Lambda",
                    "provider": "aws",
                    "region": "us-east-1",
                    "env_vars": {
                        "ANTHROPIC_API_KEY": "sk-ant-***",
                        "APP_NAME": "chatbot",
                    },
                }
            ]
        )
        assert len(agents) == 1
        assert agents[0].is_entry_point is True
        assert agents[0].asset_type == AssetType.AI_AGENT

    def test_openai_key_detected(self) -> None:
        """ECS with OPENAI_API_KEY → AI agent."""
        disc = AIAgentDiscoverer()
        agents = disc.discover_from_env_vars(
            [
                {
                    "id": "ecs-assistant",
                    "name": "AI Assistant",
                    "provider": "aws",
                    "region": "us-east-1",
                    "env_vars": {"OPENAI_API_KEY": "sk-***"},
                }
            ]
        )
        assert len(agents) == 1

    def test_no_llm_keys_not_agent(self) -> None:
        """Lambda without LLM keys → not detected as agent."""
        disc = AIAgentDiscoverer()
        agents = disc.discover_from_env_vars(
            [
                {
                    "id": "lambda-normal",
                    "name": "Normal Lambda",
                    "provider": "aws",
                    "region": "us-east-1",
                    "env_vars": {"APP_NAME": "hello", "LOG_LEVEL": "info"},
                }
            ]
        )
        assert len(agents) == 0

    def test_cloudtrail_bedrock_detection(self) -> None:
        """CloudTrail showing Bedrock calls → AI agent."""
        disc = AIAgentDiscoverer()
        agents = disc.discover_from_cloudtrail(
            [
                {
                    "source_id": "lambda-rag",
                    "source_name": "RAG Pipeline",
                    "api_call": "bedrock:InvokeModel",
                    "provider": "aws",
                    "region": "us-east-1",
                }
            ]
        )
        assert len(agents) == 1
        assert agents[0].is_entry_point is True

    def test_agent_to_role_edge(self) -> None:
        """AI agent → IAM role edge with high risk."""
        disc = AIAgentDiscoverer()
        disc.discover_from_env_vars(
            [
                {
                    "id": "agent-1",
                    "name": "Agent",
                    "provider": "aws",
                    "region": "us-east-1",
                    "env_vars": {"ANTHROPIC_API_KEY": "sk-***"},
                }
            ]
        )
        role = CloudAsset(
            id="role-1",
            name="AgentRole",
            asset_type=AssetType.IAM_ROLE,
            provider="aws",
            region="global",
        )
        edges = disc.build_agent_edges(
            {"agent-1": "role-1"},
            {"role-1": role},
        )
        assert len(edges) == 1
        assert edges[0].relation == RelationType.CAN_ASSUME
        assert edges[0].risk_weight == 0.95


# ═══════════════════════════════════════════════════════════════════
# MCP SECURITY TESTS
# ═══════════════════════════════════════════════════════════════════


class TestMCPSecurity:
    """MCP tool permission analysis."""

    def test_write_database_tool_creates_edge(self) -> None:
        """MCP tool 'write_database' → edge with risk 0.85.

        PDF requirement: "MCP tool 'write_database' creates edge
        to database with risk_weight=0.85."
        """
        analyser = MCPSecurityAnalyser()
        analyser.discover_mcp_servers(
            [
                {
                    "id": "mcp-db",
                    "name": "DB Server",
                    "tools": [{"name": "write_database"}],
                }
            ]
        )
        db = CloudAsset(
            id="db-prod",
            name="ProdDB",
            asset_type=AssetType.RDS_DATABASE,
            provider="aws",
            region="us-east-1",
        )
        edges = analyser.analyse_tools(
            "mcp-db",
            tools=[
                {
                    "name": "write_database",
                    "permissions": ["write_database"],
                    "target_resources": ["db-prod"],
                }
            ],
            target_assets={"db-prod": db},
        )
        assert len(edges) == 1
        assert edges[0].risk_weight == 0.85
        assert edges[0].relation == RelationType.MCP_TOOL_ACCESS

    def test_execute_command_highest_risk(self) -> None:
        """execute_command tool → risk 0.99."""
        analyser = MCPSecurityAnalyser()
        analyser.discover_mcp_servers(
            [
                {
                    "id": "mcp-shell",
                    "name": "Shell Server",
                    "tools": [],
                }
            ]
        )
        target = CloudAsset(
            id="server-1",
            name="Server",
            asset_type=AssetType.EC2_INSTANCE,
            provider="aws",
            region="us-east-1",
        )
        edges = analyser.analyse_tools(
            "mcp-shell",
            tools=[
                {
                    "name": "run_command",
                    "permissions": ["execute_command"],
                    "target_resources": ["server-1"],
                }
            ],
            target_assets={"server-1": target},
        )
        assert len(edges) == 1
        assert edges[0].risk_weight == 0.99

    def test_mcp_server_is_entry_point(self) -> None:
        """MCP servers are always entry points."""
        analyser = MCPSecurityAnalyser()
        servers = analyser.discover_mcp_servers(
            [
                {
                    "id": "mcp-1",
                    "name": "Test MCP",
                    "tools": [],
                }
            ]
        )
        assert len(servers) == 1
        assert servers[0].is_entry_point is True

    def test_blast_radius_calculation(self) -> None:
        """Blast radius counts all reachable resources."""
        analyser = MCPSecurityAnalyser()
        analyser.discover_mcp_servers(
            [
                {
                    "id": "mcp-wide",
                    "name": "Wide Access",
                    "tools": [],
                }
            ]
        )
        radius = analyser.calculate_blast_radius(
            "mcp-wide",
            tools=[
                {
                    "name": "write_db",
                    "permissions": ["write_database"],
                    "target_resources": ["db-1", "db-2"],
                },
                {
                    "name": "read_files",
                    "permissions": ["read_file"],
                    "target_resources": ["fs-1"],
                },
            ],
        )
        assert radius["total_resources"] == 3
        assert radius["writable_resources"] == 2
        assert radius["max_risk"] == 0.85

    def test_read_only_tool_lower_relation(self) -> None:
        """Read-only tool → READS_FROM (not MCP_TOOL_ACCESS)."""
        analyser = MCPSecurityAnalyser()
        analyser.discover_mcp_servers(
            [
                {
                    "id": "mcp-ro",
                    "name": "ReadOnly",
                    "tools": [],
                }
            ]
        )
        target = CloudAsset(
            id="bucket-1",
            name="Bucket",
            asset_type=AssetType.S3_BUCKET,
            provider="aws",
            region="us-east-1",
        )
        edges = analyser.analyse_tools(
            "mcp-ro",
            tools=[
                {
                    "name": "read_data",
                    "permissions": ["read_database"],
                    "target_resources": ["bucket-1"],
                }
            ],
            target_assets={"bucket-1": target},
        )
        assert len(edges) == 1
        assert edges[0].relation == RelationType.READS_FROM
