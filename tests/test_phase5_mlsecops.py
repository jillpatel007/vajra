"""Tests for Phase 5 MLSecOps — Days 21-25.

Enterprise-grade tests with zero shortcuts.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from vajra.discovery.mlops.scanner import MLOpsSecurityScanner
from vajra.mlsecops.adversarial import (
    AdversarialRobustnessTester,
    RobustnessLevel,
)
from vajra.mlsecops.data_integrity import (
    IntegrityStatus,
    TrainingDataIntegrityScanner,
)
from vajra.mlsecops.eu_ai_act import EUAIActComplianceChecker
from vajra.mlsecops.model_lineage import LineageRecord, ModelLineageTracker
from vajra.mlsecops.privacy import MLPrivacyScanner, PrivacyRisk
from vajra.reliability.slos import SLOTracker
from vajra.rules.sast import SASTScanner

# ═══════════════════════════════════════════════════════════════════
# DAY 21: MLOPS SCANNER + DATA INTEGRITY
# ═══════════════════════════════════════════════════════════════════


class TestMLOpsScanner:
    def test_internet_no_vpc_is_entry_point(self) -> None:
        scanner = MLOpsSecurityScanner()
        assets = scanner.scan_training_jobs(
            [
                {
                    "id": "job-1",
                    "name": "training-job",
                    "internet_accessible": True,
                    "vpc_configured": False,
                    "provider": "aws",
                    "region": "us-east-1",
                }
            ]
        )
        assert len(assets) == 1
        assert assets[0].is_entry_point is True

    def test_vpc_configured_not_entry_point(self) -> None:
        scanner = MLOpsSecurityScanner()
        assets = scanner.scan_training_jobs(
            [
                {
                    "id": "job-2",
                    "name": "safe-job",
                    "internet_accessible": True,
                    "vpc_configured": True,
                    "provider": "aws",
                    "region": "us-east-1",
                }
            ]
        )
        assert assets[0].is_entry_point is False

    def test_model_registry_is_crown_jewel(self) -> None:
        scanner = MLOpsSecurityScanner()
        assets = scanner.scan_model_registries(
            [
                {
                    "id": "reg-1",
                    "name": "production-models",
                    "provider": "aws",
                    "region": "us-east-1",
                }
            ]
        )
        assert assets[0].is_crown_jewel is True

    def test_dataset_is_crown_jewel(self) -> None:
        scanner = MLOpsSecurityScanner()
        assets = scanner.scan_datasets(
            [
                {
                    "id": "ds-1",
                    "name": "training-data",
                    "provider": "aws",
                    "region": "us-east-1",
                }
            ]
        )
        assert assets[0].is_crown_jewel is True


class TestDataIntegrity:
    def test_tampered_file_detected(self) -> None:
        tmp = Path(tempfile.mkdtemp()) / "data"
        tmp.mkdir()
        (tmp / "train.csv").write_text("original data")

        scanner = TrainingDataIntegrityScanner()
        manifest = scanner.generate_manifest(tmp)

        # Tamper the file
        (tmp / "train.csv").write_text("POISONED data")

        tampered = scanner.verify_manifest(tmp, manifest)
        assert len(tampered) >= 1
        assert "MODIFIED" in tampered[0]

    def test_distribution_drift_suspicious(self) -> None:
        scanner = TrainingDataIntegrityScanner()
        drift = scanner.check_distribution_drift(
            baseline={"cat": 0.5, "dog": 0.5},
            current={"cat": 0.4, "dog": 0.6},
        )
        assert drift > 0.05  # > 5% = suspicious

    def test_unexpected_writer_flagged(self) -> None:
        scanner = TrainingDataIntegrityScanner(
            authorized_writers=["admin@corp.com"],
        )
        unexpected = scanner.check_write_audit(
            [
                {"principal": "admin@corp.com"},
                {"principal": "hacker@evil.com"},
            ]
        )
        assert "hacker@evil.com" in unexpected

    def test_full_scan_tampered_status(self) -> None:
        tmp = Path(tempfile.mkdtemp()) / "data"
        tmp.mkdir()
        (tmp / "data.csv").write_text("clean")

        scanner = TrainingDataIntegrityScanner()
        manifest = scanner.generate_manifest(tmp)
        (tmp / "data.csv").write_text("POISONED")

        report = scanner.full_scan(
            tmp,
            manifest,
            {},
            {},
            [],
        )
        assert report.status == IntegrityStatus.TAMPERED


# ═══════════════════════════════════════════════════════════════════
# DAY 22: MODEL LINEAGE
# ═══════════════════════════════════════════════════════════════════


class TestModelLineage:
    _KEY = "lineage-test-key-32-chars-exactly"  # noqa: S105

    def test_record_and_verify(self) -> None:
        tracker = ModelLineageTracker(self._KEY)
        record = LineageRecord(
            model_id="model-v1",
            model_hash="abc123",
            data_hash="def456",
            code_commit="a1b2c3d",
            requirements_hash="req789",
        )
        tracker.record_training_run(record)
        assert tracker.verify_model_lineage("model-v1") is True

    def test_tampered_lineage_fails_verify(self) -> None:
        tracker = ModelLineageTracker(self._KEY)
        record = LineageRecord(
            model_id="model-v2",
            model_hash="abc",
            data_hash="def",
            code_commit="123",
            requirements_hash="456",
        )
        tracker.record_training_run(record)
        # Tamper the stored record
        signed = tracker._records["model-v2"]
        signed.payload["model_hash"] = "TAMPERED"
        assert tracker.verify_model_lineage("model-v2") is False

    def test_model_hash_mismatch_detected(self) -> None:
        tracker = ModelLineageTracker(self._KEY)
        record = LineageRecord(
            model_id="model-v3",
            model_hash="original_hash",
            data_hash="data",
            code_commit="commit",
            requirements_hash="req",
        )
        tracker.record_training_run(record)
        assert (
            tracker.check_model_hash(
                "model-v3",
                "different_hash",
            )
            is False
        )

    def test_short_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="32"):
            ModelLineageTracker("short")


# ═══════════════════════════════════════════════════════════════════
# DAY 23: ADVERSARIAL + PRIVACY
# ═══════════════════════════════════════════════════════════════════


class TestAdversarialRobustness:
    def test_fgsm_vulnerable_model(self) -> None:
        tester = AdversarialRobustnessTester()
        original = [{"input_id": f"x{i}", "label": "cat"} for i in range(10)]
        # 4/10 fooled = 40% = CRITICAL
        perturbed = [
            {"input_id": f"x{i}", "label": "dog" if i < 4 else "cat"} for i in range(10)
        ]
        report = tester.fgsm_attack(original, perturbed)
        assert report.attack_success_rate > 0.25
        assert report.robustness_level == RobustnessLevel.CRITICAL

    def test_fgsm_robust_model(self) -> None:
        tester = AdversarialRobustnessTester()
        original = [{"input_id": f"x{i}", "label": "cat"} for i in range(100)]
        # 2/100 fooled = 2% = ROBUST
        perturbed = [
            {"input_id": f"x{i}", "label": "dog" if i < 2 else "cat"}
            for i in range(100)
        ]
        report = tester.fgsm_attack(original, perturbed)
        assert report.robustness_level == RobustnessLevel.ROBUST


class TestPrivacy:
    def test_membership_inference_high_auc(self) -> None:
        scanner = MLPrivacyScanner()
        # Members score much higher than non-members = high AUC
        result = scanner.test_membership_inference(
            member_scores=[0.9, 0.85, 0.88, 0.92, 0.87],
            non_member_scores=[0.3, 0.25, 0.28, 0.32, 0.27],
        )
        assert result.auc > 0.7
        assert result.risk_level == PrivacyRisk.CRITICAL

    def test_membership_inference_low_auc(self) -> None:
        scanner = MLPrivacyScanner()
        # Identical distributions = AUC ~0.5 = good privacy
        result = scanner.test_membership_inference(
            member_scores=[0.5, 0.4, 0.6, 0.45, 0.55],
            non_member_scores=[0.5, 0.4, 0.6, 0.45, 0.55],
        )
        assert result.auc <= 0.6
        assert result.risk_level == PrivacyRisk.LOW

    def test_dp_non_compliant(self) -> None:
        scanner = MLPrivacyScanner()
        result = scanner.check_differential_privacy_compliance(
            epsilon=15.0,
            max_epsilon=10.0,
        )
        assert result.compliant is False

    def test_dp_compliant(self) -> None:
        scanner = MLPrivacyScanner()
        result = scanner.check_differential_privacy_compliance(
            epsilon=5.0,
            max_epsilon=10.0,
        )
        assert result.compliant is True


# ═══════════════════════════════════════════════════════════════════
# DAY 24: EU AI ACT
# ═══════════════════════════════════════════════════════════════════


class TestEUAIAct:
    def test_credit_scoring_is_high_risk(self) -> None:
        checker = EUAIActComplianceChecker()
        result = checker.assess_risk_classification("credit_scoring")
        assert result.risk_level == "high"
        assert len(result.applicable_articles) >= 7
        assert len(result.requirements) >= 8

    def test_minimal_risk_domain(self) -> None:
        checker = EUAIActComplianceChecker()
        result = checker.assess_risk_classification("weather_forecast")
        assert result.risk_level == "minimal"

    def test_technical_documentation_generated(self) -> None:
        checker = EUAIActComplianceChecker()
        doc = checker.generate_technical_documentation(
            system_name="CreditScorer",
            lineage_data={"model_id": "v1", "data_hash": "abc"},
            graph_summary={"paths_found": 3, "minimum_cut": 1},
        )
        assert "CreditScorer" in doc.system_description
        assert doc.risk_assessment["attack_paths"] == 3


# ═══════════════════════════════════════════════════════════════════
# DAY 25: SLOs + SAST
# ═══════════════════════════════════════════════════════════════════


class TestSLOs:
    def test_slo_compliance_tracking(self) -> None:
        tracker = SLOTracker()
        for _ in range(100):
            tracker.record_scan(success=True, latency_seconds=5.0)
        tracker.record_scan(success=False, latency_seconds=60.0)

        statuses = tracker.get_status()
        assert len(statuses) == 3
        # 100/101 = 99.0% < 99.5% target
        assert statuses[0].in_compliance is False

    def test_slo_all_green(self) -> None:
        tracker = SLOTracker()
        for _ in range(200):
            tracker.record_scan(success=True, latency_seconds=2.0)

        statuses = tracker.get_status()
        assert statuses[0].in_compliance is True  # Success rate
        assert statuses[1].in_compliance is True  # Latency


class TestSAST:
    def test_detects_aws_access_key(self) -> None:
        tmp = Path(tempfile.mkdtemp()) / "test.py"
        tmp.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        scanner = SASTScanner()
        findings = scanner.scan_file(tmp)
        assert len(findings) >= 1
        assert findings[0].pattern_name == "aws_access_key"

    def test_detects_private_key(self) -> None:
        tmp = Path(tempfile.mkdtemp()) / "key.pem"
        tmp.write_text("-----BEGIN RSA PRIVATE KEY-----\ndata\n")

        scanner = SASTScanner()
        findings = scanner.scan_file(tmp)
        assert len(findings) >= 1

    def test_skips_allowlisted(self) -> None:
        tmp = Path(tempfile.mkdtemp()) / "test.py"
        tmp.write_text(
            'KEY = "AKIAIOSFODNN7EXAMPLE"' "  # pragma: allowlist secret\n",
        )

        scanner = SASTScanner()
        findings = scanner.scan_file(tmp)
        assert len(findings) == 0

    def test_clean_file_no_findings(self) -> None:
        tmp = Path(tempfile.mkdtemp()) / "clean.py"
        tmp.write_text("def hello():\n    return 'world'\n")

        scanner = SASTScanner()
        findings = scanner.scan_file(tmp)
        assert len(findings) == 0
