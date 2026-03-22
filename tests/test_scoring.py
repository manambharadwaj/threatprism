"""Tests for DREAD scoring and report generation."""

from __future__ import annotations

from threatlens.frameworks.dread import aggregate_risk, score_threat, score_threats
from threatlens.frameworks.stride import analyze_stride
from threatlens.models import DreadScore, Severity, StrideCategory, Threat
from threatlens.reports import generate_report


class TestDreadScoring:
    def _sample_threat(self, **overrides) -> Threat:
        defaults = {
            "id": "TEST-001",
            "title": "Test Threat",
            "description": "A test threat for scoring",
            "stride_categories": [StrideCategory.TAMPERING],
            "severity": Severity.HIGH,
        }
        defaults.update(overrides)
        return Threat(**defaults)

    def test_score_produces_valid_range(self):
        threat = self._sample_threat()
        dread = score_threat(threat)
        assert 1 <= dread.damage <= 10
        assert 1 <= dread.reproducibility <= 10
        assert 1 <= dread.exploitability <= 10
        assert 1 <= dread.affected_users <= 10
        assert 1 <= dread.discoverability <= 10
        assert 1 <= dread.overall <= 10

    def test_critical_severity_boosts_scores(self):
        normal = self._sample_threat(severity=Severity.MEDIUM)
        critical = self._sample_threat(severity=Severity.CRITICAL)
        normal_score = score_threat(normal)
        critical_score = score_threat(critical)
        assert critical_score.overall >= normal_score.overall

    def test_context_modifiers_applied(self):
        threat = self._sample_threat(description="Public-facing financial API")
        score_no_ctx = score_threat(threat)
        score_with_ctx = score_threat(threat, "internet-facing PII processing")
        assert (
            score_with_ctx.affected_users >= score_no_ctx.affected_users
            or score_with_ctx.damage >= score_no_ctx.damage
        )

    def test_rating_computed(self):
        score = DreadScore(
            damage=9,
            reproducibility=8,
            exploitability=8,
            affected_users=9,
            discoverability=7,
        )
        assert score.rating == Severity.CRITICAL

        score_low = DreadScore(
            damage=3,
            reproducibility=2,
            exploitability=2,
            affected_users=2,
            discoverability=2,
        )
        assert score_low.rating == Severity.LOW

    def test_batch_scoring_sorted(self):
        threats = analyze_stride(
            "Authentication database with admin panel and public API"
        )
        if len(threats) >= 2:
            scored = score_threats(threats)
            for i in range(len(scored) - 1):
                assert scored[i][1].overall >= scored[i + 1][1].overall

    def test_aggregate_risk(self):
        scores = [
            DreadScore(
                damage=8,
                reproducibility=7,
                exploitability=6,
                affected_users=5,
                discoverability=4,
            ),
            DreadScore(
                damage=3,
                reproducibility=4,
                exploitability=5,
                affected_users=3,
                discoverability=2,
            ),
        ]
        agg = aggregate_risk(scores)
        assert agg["count"] == 2
        assert agg["max"] >= agg["min"]
        assert agg["min"] <= agg["mean"] <= agg["max"]


class TestReportGeneration:
    def test_generates_markdown_report(self):
        threats = analyze_stride(
            "E-commerce platform with user auth, payment API, and product database"
        )
        report = generate_report("Test System", threats)
        assert "# Threat Analysis Report: Test System" in report
        assert "## Executive Summary" in report
        assert "## STRIDE Threat Analysis" in report

    def test_report_includes_all_sections(self):
        threats = analyze_stride("API with JWT auth and PostgreSQL")
        scored = score_threats(threats)
        from threatlens.correlation import correlate_all
        from threatlens.frameworks.attack_tree import build_attack_trees
        from threatlens.frameworks.linddun import assess_privacy
        from threatlens.frameworks.pasta import run_pasta

        privacy = assess_privacy("API handling user email and name")
        pasta = run_pasta("API with JWT auth", threats)
        trees = build_attack_trees(threats[:2]) if len(threats) >= 2 else []
        correlations = correlate_all(threats)

        report = generate_report(
            "Full Report Test",
            threats,
            scored=scored,
            privacy_impacts=privacy,
            pasta_stages=pasta,
            attack_trees=trees,
            correlations=correlations,
        )
        assert "DREAD" in report
        assert "LINDDUN" in report or "Privacy" in report
        assert "PASTA" in report
        assert "Cross-Framework" in report
