"""Core data models for ThreatLens multi-framework threat analysis."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, computed_field

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class StrideCategory(str, Enum):
    """STRIDE threat classification categories."""

    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class LinddunCategory(str, Enum):
    """LINDDUN privacy threat categories."""

    LINKABILITY = "linkability"
    IDENTIFIABILITY = "identifiability"
    NON_REPUDIATION = "non_repudiation"
    DETECTABILITY = "detectability"
    DISCLOSURE = "disclosure"
    UNAWARENESS = "unawareness"
    NON_COMPLIANCE = "non_compliance"


class PastaStage(str, Enum):
    """PASTA process stages."""

    BUSINESS_OBJECTIVES = "1_business_objectives"
    TECHNICAL_SCOPE = "2_technical_scope"
    DECOMPOSITION = "3_decomposition"
    THREAT_ANALYSIS = "4_threat_analysis"
    VULNERABILITY_ANALYSIS = "5_vulnerability_analysis"
    ATTACK_MODELING = "6_attack_modeling"
    RISK_IMPACT = "7_risk_impact"


class Severity(str, Enum):
    """Risk severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class GateType(str, Enum):
    """Attack tree gate types."""

    AND = "AND"
    OR = "OR"
    LEAF = "LEAF"


# ---------------------------------------------------------------------------
# Scoring Models
# ---------------------------------------------------------------------------


class DreadScore(BaseModel):
    """DREAD quantitative risk scoring. Each dimension is scored 1-10."""

    damage: float = Field(ge=1, le=10)
    reproducibility: float = Field(ge=1, le=10)
    exploitability: float = Field(ge=1, le=10)
    affected_users: float = Field(ge=1, le=10)
    discoverability: float = Field(ge=1, le=10)

    @computed_field
    @property
    def overall(self) -> float:
        total = (
            self.damage
            + self.reproducibility
            + self.exploitability
            + self.affected_users
            + self.discoverability
        )
        return round(total / 5, 1)

    @computed_field
    @property
    def rating(self) -> Severity:
        s = self.overall
        if s >= 8:
            return Severity.CRITICAL
        if s >= 6:
            return Severity.HIGH
        if s >= 4:
            return Severity.MEDIUM
        if s >= 2:
            return Severity.LOW
        return Severity.INFO


# ---------------------------------------------------------------------------
# Threat & Analysis Models
# ---------------------------------------------------------------------------


class Threat(BaseModel):
    """A single identified security threat."""

    id: str
    title: str
    description: str
    stride_categories: list[StrideCategory]
    dread_score: DreadScore | None = None
    privacy_categories: list[LinddunCategory] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM


class AttackNode(BaseModel):
    """A node in an attack tree."""

    id: str
    label: str
    gate: GateType = GateType.LEAF
    children: list[AttackNode] = Field(default_factory=list)
    likelihood: float | None = Field(None, ge=0, le=1)
    impact: float | None = Field(None, ge=1, le=10)


class AttackTree(BaseModel):
    """Complete attack tree for a target asset."""

    target: str
    description: str
    root: AttackNode


class PrivacyImpact(BaseModel):
    """Single LINDDUN privacy impact finding."""

    category: LinddunCategory
    description: str
    severity: Severity
    affected_data_types: list[str]
    recommendations: list[str]


class PastaStageResult(BaseModel):
    """Output from one PASTA stage."""

    stage: PastaStage
    title: str
    findings: list[str]
    artifacts: dict[str, str] = Field(default_factory=dict)


class FrameworkCorrelation(BaseModel):
    """Cross-framework mapping for a single threat."""

    threat_id: str
    threat_title: str
    stride: list[StrideCategory]
    dread: DreadScore | None = None
    linddun: list[LinddunCategory]
    cwe_ids: list[str]
    mitre_techniques: list[str] = Field(default_factory=list)


class ThreatLandscape(BaseModel):
    """Complete multi-framework threat landscape."""

    system_name: str
    description: str
    threats: list[Threat]
    risk_summary: dict[str, int]
    framework_coverage: dict[str, list[str]]
