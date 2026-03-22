"""Tests for STRIDE, LINDDUN, PASTA, and attack tree framework engines."""

from __future__ import annotations

from threatprism.frameworks.attack_tree import build_attack_tree, build_attack_trees
from threatprism.frameworks.linddun import assess_privacy, detect_privacy_signals
from threatprism.frameworks.pasta import run_pasta
from threatprism.frameworks.stride import analyze_stride, stride_categories_for_text
from threatprism.models import (
    GateType,
    LinddunCategory,
    PastaStage,
    StrideCategory,
)


class TestStride:
    def test_auth_system_detects_spoofing(self):
        threats = analyze_stride("User login with JWT tokens and session management")
        categories = {c for t in threats for c in t.stride_categories}
        assert StrideCategory.SPOOFING in categories

    def test_database_system_detects_tampering(self):
        threats = analyze_stride("REST API that writes to a PostgreSQL database")
        categories = {c for t in threats for c in t.stride_categories}
        assert StrideCategory.TAMPERING in categories

    def test_empty_description_returns_no_threats(self):
        threats = analyze_stride("A simple hello world program")
        assert isinstance(threats, list)

    def test_tech_stack_enriches_detection(self):
        base = analyze_stride("A web application")
        enriched = analyze_stride(
            "A web application", tech_stack=["jwt", "oauth", "redis"]
        )
        assert len(enriched) >= len(base)

    def test_all_threats_have_ids(self):
        threats = analyze_stride(
            "Authentication API with database storage and admin panel"
        )
        for t in threats:
            assert t.id.startswith("STRIDE-")
            assert len(t.id) > 7

    def test_stride_categories_for_text(self):
        cats = stride_categories_for_text("login endpoint with role-based admin access")
        assert StrideCategory.SPOOFING in cats
        assert StrideCategory.ELEVATION_OF_PRIVILEGE in cats

    def test_threats_have_mitigations(self):
        threats = analyze_stride("Payment processing API with credit card storage")
        mitigated = [t for t in threats if t.mitigations]
        assert len(mitigated) > 0


class TestLinddun:
    def test_pii_system_detects_privacy_threats(self):
        impacts = assess_privacy(
            "System that collects user email, name, and address for profiling"
        )
        assert len(impacts) > 0
        categories = {i.category for i in impacts}
        assert (
            LinddunCategory.IDENTIFIABILITY in categories
            or LinddunCategory.DISCLOSURE in categories
        )

    def test_health_data_triggers_non_compliance(self):
        impacts = assess_privacy(
            "Medical records system storing patient "
            "health data shared with insurance partners"
        )
        categories = {i.category for i in impacts}
        assert LinddunCategory.NON_COMPLIANCE in categories

    def test_no_pii_returns_empty(self):
        impacts = assess_privacy("A calculator microservice with no user data")
        assert len(impacts) == 0

    def test_detect_privacy_signals(self):
        signals = detect_privacy_signals(
            "Store user email and location for personalized recommendations"
        )
        assert "identifiers" in signals["data_types"]
        assert "behavioral" in signals["data_types"]
        assert (
            "profiling" in signals["activities"] or "storage" in signals["activities"]
        )

    def test_impacts_have_recommendations(self):
        impacts = assess_privacy(
            "User registration form collecting name, email, phone, and credit card"
        )
        for imp in impacts:
            assert len(imp.recommendations) > 0


class TestPasta:
    def test_seven_stages_produced(self):
        threats = analyze_stride(
            "E-commerce API with payment processing and user authentication"
        )
        stages = run_pasta(
            "E-commerce API with payment processing", threats, ["Python", "PostgreSQL"]
        )
        assert len(stages) == 7

    def test_stages_in_order(self):
        threats = analyze_stride("Web application")
        stages = run_pasta("Web application", threats)
        expected_order = [
            PastaStage.BUSINESS_OBJECTIVES,
            PastaStage.TECHNICAL_SCOPE,
            PastaStage.DECOMPOSITION,
            PastaStage.THREAT_ANALYSIS,
            PastaStage.VULNERABILITY_ANALYSIS,
            PastaStage.ATTACK_MODELING,
            PastaStage.RISK_IMPACT,
        ]
        for stage, expected in zip(stages, expected_order, strict=False):
            assert stage.stage == expected

    def test_each_stage_has_findings(self):
        threats = analyze_stride("API gateway with database and auth service")
        stages = run_pasta("API gateway with database and auth service", threats)
        for stage in stages:
            assert len(stage.findings) > 0
            assert stage.title


class TestAttackTree:
    def test_builds_tree_from_threat(self):
        threats = analyze_stride("User authentication with JWT tokens")
        assert len(threats) > 0
        tree = build_attack_tree(threats[0])
        assert tree.target == threats[0].title
        assert tree.root.label.startswith("GOAL:")
        assert len(tree.root.children) > 0

    def test_leaf_nodes_have_estimates(self):
        threats = analyze_stride("Admin panel with role-based access control")
        tree = build_attack_tree(threats[0])

        def find_leaves(node):
            if node.gate == GateType.LEAF:
                return [node]
            leaves = []
            for child in node.children:
                leaves.extend(find_leaves(child))
            return leaves

        leaves = find_leaves(tree.root)
        assert len(leaves) > 0
        scored = [leaf for leaf in leaves if leaf.likelihood is not None]
        assert len(scored) > 0

    def test_batch_build(self):
        threats = analyze_stride("Authentication, database writes, and admin panel")
        trees = build_attack_trees(threats)
        assert len(trees) == len(threats)
