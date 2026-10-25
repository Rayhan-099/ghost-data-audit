"""Domain models for Ghost Data Still Exists forensic audit engine."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class DeletionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class StepPhase(str, Enum):
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"


# Operation ordering according to challenge specification
FINDING_OPERATIONS = [
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
]

REMEDIATION_OPERATIONS = [
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
]

VERIFICATION_OPERATIONS = [
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]

PHASE_ORDER = {
    StepPhase.FINDING: 1,
    StepPhase.REMEDIATION: 2,
    StepPhase.VERIFICATION: 3,
}

OPERATION_ORDER = {}
for i, op in enumerate(FINDING_OPERATIONS, start=1):
    OPERATION_ORDER[(StepPhase.FINDING, op)] = i
for i, op in enumerate(REMEDIATION_OPERATIONS, start=1):
    OPERATION_ORDER[(StepPhase.REMEDIATION, op)] = i
for i, op in enumerate(VERIFICATION_OPERATIONS, start=1):
    OPERATION_ORDER[(StepPhase.VERIFICATION, op)] = i


@dataclass
class AuditStep:
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_no": self.step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


@dataclass
class DeletionRequest:
    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str


@dataclass
class IdentityProfile:
    user_id: str
    primary_email: str
    name: Optional[str] = None
    phone: Optional[str] = None
    email_hash: Optional[str] = None
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    names: Set[str] = field(default_factory=set)
    email_hashes: Set[str] = field(default_factory=set)


@dataclass
class ResourceObservation:
    resource_id: str
    system_id: str
    category: str
    state: str  # e.g. PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, BLOCKED
    observed_at: str
    file_id: str
    origin: str
    identifiers: Set[str] = field(default_factory=set)
    raw_record: Dict[str, Any] = field(default_factory=dict)
