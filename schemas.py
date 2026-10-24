"""
ElderShield v2 — formal state schemas.

These are the contracts for the three persistent/state objects. `GET /schemas`
serves them as JSON Schema; `test_e2e.py` validates live server output against
them so the docs can't drift from the code.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Stage = Literal["contact", "off_platform_chat", "urgency_lure", "financial_request"]
Decision = Literal["ALLOW", "CHALLENGE", "INTERCEPT"]
SignalCategory = Literal["urgency", "impersonation", "secrecy", "payment_pressure", "voice_session"]


class Anomaly(BaseModel):
    type: Literal["hidden_llm_injection", "hidden_text", "inline_llm_injection"]
    severity: Literal["critical", "high", "medium"]
    detail: str
    excerpt_hash: Optional[str] = Field(None, description="SHA-256 prefix of the hidden text; raw text is never kept")


# --------------------------------------------------------------------------- #
# CrossTabCausalGraph
# --------------------------------------------------------------------------- #

class TriggerNode(BaseModel):
    """An inbound coercion signal (Tab A). Persisted to SQLite, hot for 30 min."""
    id: str = Field(pattern=r"^trg_[0-9a-f]{10}$")
    tab_id: str
    entity_hash: str = Field(description="salted SHA-256 of the sender, 24 hex chars", pattern=r"^[0-9a-f]{24}$")
    ts: float
    ts_iso: str
    age_s: float
    signals: dict[SignalCategory, list[str]]
    severity: int = Field(ge=0, le=100)
    coached_phrases: list[str] = Field(description="cover stories the sender told the victim to recite")
    anomalies: list[Anomaly]


class CorrelationEdge(BaseModel):
    """Trigger -> Action edge, written every time an outbound action is evaluated."""
    trigger_id: str = Field(description="empty string on the long-con (cold) path")
    action_id: str = Field(pattern=r"^act_[0-9a-f]{10}$")
    causality_score: int = Field(ge=0, le=100)
    latency_s: float
    decision: Decision
    reason: str


class CrossTabCausalGraphState(BaseModel):
    window_minutes: int
    updated_at: str
    triggers: list[TriggerNode]
    correlations: list[CorrelationEdge]


# --------------------------------------------------------------------------- #
# EntityTrajectoryStore (one row per sender)
# --------------------------------------------------------------------------- #

class StageEvent(BaseModel):
    stage: Stage
    ts: str


class EntityTrajectory(BaseModel):
    entity_hash: str = Field(pattern=r"^[0-9a-f]{24}$")
    first_seen: float
    last_seen: float
    first_seen_iso: str
    last_seen_iso: str
    escalation_stage: Stage = Field(description="monotonic: never regresses")
    stage_history: list[StageEvent]
    channels: list[str]
    interaction_count: int = Field(ge=1)
    risk_score: int = Field(ge=0, le=100)


# --------------------------------------------------------------------------- #
# ProofOfCoercionReceipt
# --------------------------------------------------------------------------- #

class InterceptedAction(BaseModel):
    type: str
    origin: str
    amount_blocked: Optional[float]
    action_id: str


class TriggerVectorHash(BaseModel):
    category: SignalCategory
    vector_hash: str = Field(pattern=r"^[0-9a-f]{16}$")


class TrajectoryDigest(BaseModel):
    stage: Optional[Stage]
    stage_count: int
    first_seen: Optional[str]
    risk_score: Optional[int]


class ReceiptPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")   # nothing un-reviewed can leak into a receipt
    schema_: Literal["eldershield.proof_of_coercion.v2"] = Field(alias="schema")
    receipt_id: str = Field(pattern=r"^poc_[0-9a-f]{12}$")
    issued_at: str
    intercepted_action: InterceptedAction
    causality_score: int = Field(ge=0, le=100)
    trigger_vector_hashes: list[TriggerVectorHash]
    entity_trajectory_digest: Optional[TrajectoryDigest]
    redacted_summary: str


class ProofOfCoercionReceipt(BaseModel):
    payload: ReceiptPayload
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature_ed25519: str = Field(description="base64 Ed25519 over canonical JSON (sorted keys, compact)")
    device_pubkey_ed25519: str = Field(description="base64 raw 32-byte public key")


# --------------------------------------------------------------------------- #
# ElderShield v3 — Agentic Case Files, Watchlist & Disclosure Schemas
# --------------------------------------------------------------------------- #

class ObservationFeatures(BaseModel):
    signals: list[str] = Field(default_factory=list)
    coached_phrases: list[str] = Field(default_factory=list)
    payment_identifiers_hashed: list[str] = Field(default_factory=list)
    domains_mentioned: list[str] = Field(default_factory=list)
    channel_move_requested: bool = False
    isolation_language: bool = False


class Observation(BaseModel):
    """An immutable, append-only event in a contact's timeline."""
    obs_id: str = Field(pattern=r"^obs_[0-9a-f]{6,}$")
    case_id: str = Field(pattern=r"^case_[0-9a-f]{6,}$")
    entity_hash: str = Field(pattern=r"^[0-9a-f]{24}$")
    ts: str
    channel: str
    kind: str
    features: ObservationFeatures
    redacted_snippet: str
    anomalies: list[Anomaly] = Field(default_factory=list)


CaseStatus = Literal["watching", "concerned", "active_hold", "resolved_benign", "resolved_scam", "dismissed_by_user"]


class CaseFile(BaseModel):
    """A per-contact or contact-cluster investigative case file."""
    case_id: str = Field(pattern=r"^case_[0-9a-f]{6,}$")
    entity_hashes: list[str]
    opened_at: str
    last_event_at: str
    status: CaseStatus = "watching"
    scam_pattern: Optional[str] = None
    stage: str = "contact"
    concern_level: int = Field(ge=0, le=4, description="0 quiet, 1 note, 2 reality check, 3 hold-ready, 4 hold")
    hypothesis: str = ""
    evidence_for: list[str] = Field(default_factory=list)
    evidence_against: list[str] = Field(default_factory=list)
    missing_info: list[str] = Field(default_factory=list)
    next_review_at: Optional[str] = None
    investigator_runs: int = 0


WatchKind = Literal[
    "payee_identifier", "destination_domain", "amount_range",
    "memo_phrase", "withdrawal_fee_request", "gift_card_checkout", "remote_access_install"
]
WatchAction = Literal["note", "reality_check", "hold_and_explain"]


class WatchItem(BaseModel):
    """Concrete item the sub-millisecond fast path checks at submit time."""
    watch_id: str = Field(pattern=r"^w_[0-9a-f]{4,}$")
    case_id: str
    kind: WatchKind
    value_hash: str
    applies_to_sinks: list[str]
    action: WatchAction
    reason_for_user: str
    created_by: str = "investigator"
    expires_at: str


class TimelineEvent(BaseModel):
    day: int
    ref: str
    channel: str
    signals: list[str]
    snippet: Optional[str] = None
    domain: Optional[str] = None
    amount: Optional[str] = None


class PendingActionSummary(BaseModel):
    sink: str
    amount: Optional[str] = None
    destination: Optional[str] = None


class InvestigatorRequest(BaseModel):
    """The strictly de-identified case summary sent to the cloud model."""
    task: str = "assess_case"
    case_ref: str
    user_baseline: dict[str, Any]
    timeline: list[TimelineEvent]
    pending_action: Optional[PendingActionSummary] = None
    current_watch_items: int = 0


class ProposedWatchItem(BaseModel):
    kind: WatchKind
    ref: str
    action: WatchAction


class InvestigatorResponse(BaseModel):
    """Strict JSON schema output from Claude investigator."""
    scam_pattern: str
    stage: str
    concern_level: int = Field(ge=0, le=4)
    hypothesis: str = Field(max_length=400)
    benign_explanations_considered: list[str]
    what_would_change_my_mind: list[str]
    evidence_refs: list[str]
    proposed_watch_items: list[ProposedWatchItem] = Field(default_factory=list)
    next_review_in_hours: int = 24
    user_message_draft: str = Field(max_length=350)


class DisclosureLog(BaseModel):
    """Tamper-evident log of every outbound request that left the device."""
    disclosure_id: str = Field(pattern=r"^disc_[0-9a-f]{6,}$")
    ts: str
    case_id: str
    bytes_sent: int
    exact_request_json: str
    model: str
    latency_ms: float

