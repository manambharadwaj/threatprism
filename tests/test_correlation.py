"""Tests for cross-framework correlation and CWE mapping."""

from __future__ import annotations

from threatlens.correlation import (
    correlate_all,
    correlate_threat,
    framework_coverage_summary,
)
from threatlens.frameworks.stride import analyze_stride
from threatlens.mappings import (
    cwes_for_threat_categories,
    linddun_for_stride,
    mitre_for_threat_categories,
)
from threatlens.models import StrideCategory


class TestMappings:
    def test_spoofing_maps_to_auth_cwes(self):
        cwes = cwes_for_threat_categories([StrideCategory.SPOOFING])
        cwe_ids = {c["id"] for c in cwes}
        assert "CWE-287" in cwe_ids

    def test_tampering_maps_to_injection_cwes(self):
        cwes = cwes_for_threat_categories([StrideCategory.TAMPERING])
        cwe_ids = {c["id"] for c in cwes}
        assert "CWE-89" in cwe_ids

    def test_multiple_categories_deduplicate(self):
        cwes = cwes_for_threat_categories(
            [StrideCategory.SPOOFING, StrideCategory.SPOOFING]
        )
        ids = [c["id"] for c in cwes]
        assert len(ids) == len(set(ids))

    def test_mitre_mapping(self):
        techniques = mitre_for_threat_categories([StrideCategory.SPOOFING])
        ids = {t["id"] for t in techniques}
        assert "T1078" in ids

    def test_linddun_cross_reference(self):
        linddun = linddun_for_stride([StrideCategory.INFORMATION_DISCLOSURE])
        from threatlens.models import LinddunCategory

        assert LinddunCategory.DISCLOSURE in linddun

    def test_all_stride_categories_have_cwes(self):
        for cat in StrideCategory:
            cwes = cwes_for_threat_categories([cat])
            assert len(cwes) > 0, f"No CWEs for {cat.value}"


class TestCorrelation:
    def test_correlate_single_threat(self):
        threats = analyze_stride("User login with password and session tokens")
        assert len(threats) > 0
        corr = correlate_threat(threats[0])
        assert corr.threat_id == threats[0].id
        assert len(corr.stride) > 0
        assert corr.dread is not None
        assert corr.dread.overall > 0
        assert len(corr.cwe_ids) > 0

    def test_correlate_all_sorted_by_severity(self):
        threats = analyze_stride(
            "Authentication API with admin database and public file uploads"
        )
        correlations = correlate_all(threats)
        assert len(correlations) == len(threats)
        if len(correlations) > 1:
            for i in range(len(correlations) - 1):
                score_a = correlations[i].dread.overall if correlations[i].dread else 0
                score_b = (
                    correlations[i + 1].dread.overall
                    if correlations[i + 1].dread
                    else 0
                )
                assert score_a >= score_b

    def test_framework_coverage_summary(self):
        threats = analyze_stride(
            "REST API with JWT authentication and PostgreSQL database"
        )
        correlations = correlate_all(threats)
        coverage = framework_coverage_summary(correlations)
        assert "stride" in coverage
        assert "linddun" in coverage
        assert "cwe" in coverage
        assert "dread_severity" in coverage
