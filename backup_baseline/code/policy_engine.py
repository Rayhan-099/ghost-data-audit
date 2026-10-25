"""Policy engine applying deletion_rules.csv rules to discovered resources and states."""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class PolicyTreatment:
    rule_id: str
    data_category: str
    required_action: str
    compliant_state: str
    finding_op: Optional[str]
    finding_state: Optional[str]
    remediation_op: Optional[str]
    remediation_state: Optional[str]
    verification_op: str
    verification_state: str


class PolicyEngine:
    def __init__(self):
        self._init_rules()

    def _init_rules(self):
        # Maps system_id / category to policy treatment
        self.rules: Dict[str, PolicyTreatment] = {
            "USER_PROFILE": PolicyTreatment(
                rule_id="rule_01",
                data_category="USER_PROFILE",
                required_action="DELETE",
                compliant_state="ABSENT",
                finding_op="REPORT_REMAINING_RECORD",
                finding_state="PRESENT",
                remediation_op="DELETE_RECORD",
                remediation_state="ABSENT",
                verification_op="VERIFY_RECORD_ABSENT",
                verification_state="ABSENT",
            ),
            "SEARCH_INDEX_ENTRY": PolicyTreatment(
                rule_id="rule_03",
                data_category="SEARCH_INDEX_ENTRY",
                required_action="DELETE",
                compliant_state="ABSENT",
                finding_op="REPORT_REMAINING_RECORD",
                finding_state="PRESENT",
                remediation_op="DELETE_RECORD",
                remediation_state="ABSENT",
                verification_op="VERIFY_RECORD_ABSENT",
                verification_state="ABSENT",
            ),
            "USER_EXPORT": PolicyTreatment(
                rule_id="rule_09",
                data_category="USER_EXPORT",
                required_action="DELETE",
                compliant_state="ABSENT",
                finding_op="REPORT_REMAINING_RECORD",
                finding_state="PRESENT",
                remediation_op="DELETE_RECORD",
                remediation_state="ABSENT",
                verification_op="VERIFY_RECORD_ABSENT",
                verification_state="ABSENT",
            ),
            "SUPPORT_ATTACHMENT": PolicyTreatment(
                rule_id="rule_06",
                data_category="SUPPORT_ATTACHMENT",
                required_action="DELETE",
                compliant_state="ABSENT",
                finding_op="REPORT_REMAINING_RECORD",
                finding_state="PRESENT",
                remediation_op="DELETE_RECORD",
                remediation_state="ABSENT",
                verification_op="VERIFY_RECORD_ABSENT",
                verification_state="ABSENT",
            ),
            "SUPPORT_MESSAGE": PolicyTreatment(
                rule_id="rule_05",
                data_category="SUPPORT_MESSAGE",
                required_action="REDACT",
                compliant_state="REDACTED",
                finding_op="REPORT_EXPOSED_PII",
                finding_state="PRESENT",
                remediation_op="REDACT_RECORD",
                remediation_state="REDACTED",
                verification_op="VERIFY_RECORD_REDACTED",
                verification_state="REDACTED",
            ),
            "ACCOUNT_TOMBSTONE": PolicyTreatment(
                rule_id="rule_15",
                data_category="ACCOUNT_TOMBSTONE",
                required_action="REDACT",
                compliant_state="REDACTED",
                finding_op="REPORT_EXPOSED_PII",
                finding_state="PRESENT",
                remediation_op="REDACT_RECORD",
                remediation_state="REDACTED",
                verification_op="VERIFY_RECORD_REDACTED",
                verification_state="REDACTED",
            ),
            "ANALYTICS_PROFILE": PolicyTreatment(
                rule_id="rule_07",
                data_category="ANALYTICS_PROFILE",
                required_action="ANONYMIZE",
                compliant_state="ANONYMIZED",
                finding_op="REPORT_EXPOSED_PII",
                finding_state="PRESENT",
                remediation_op="ANONYMIZE_RECORD",
                remediation_state="ANONYMIZED",
                verification_op="VERIFY_RECORD_ANONYMIZED",
                verification_state="ANONYMIZED",
            ),
            "DATA_FLOW": PolicyTreatment(
                rule_id="data_flow_control",
                data_category="DATA_FLOW",
                required_action="DISABLE",
                compliant_state="DISABLED",
                finding_op="REPORT_ACTIVE_DATA_FLOW",
                finding_state="ACTIVE",
                remediation_op="DISABLE_DATA_FLOW",
                remediation_state="DISABLED",
                verification_op="VERIFY_DATA_FLOW_DISABLED",
                verification_state="DISABLED",
            ),
            "BACKUP_ARCHIVE": PolicyTreatment(
                rule_id="rule_14",
                data_category="BACKUP_ARCHIVE",
                required_action="BLOCK_RESTORE",
                compliant_state="BLOCKED",
                finding_op="REPORT_RESTORE_RISK",
                finding_state="ACTIVE",
                remediation_op="BLOCK_RESTORE",
                remediation_state="BLOCKED",
                verification_op="VERIFY_RESTORE_BLOCKED",
                verification_state="BLOCKED",
            ),
            "SECURITY_AUDIT_LOG": PolicyTreatment(
                rule_id="rule_12",
                data_category="SECURITY_AUDIT_LOG",
                required_action="RETAIN",
                compliant_state="PRESENT",
                finding_op=None,
                finding_state=None,
                remediation_op=None,
                remediation_state=None,
                verification_op="VERIFY_RECORD_PRESENT",
                verification_state="PRESENT",
            ),
        }

    def infer_category(self, system_id: str, resource_id: str, explicit_cat: Optional[str] = None) -> str:
        if explicit_cat and explicit_cat in self.rules:
            return explicit_cat
        if resource_id.startswith("account_"):
            return "USER_PROFILE"
        if resource_id.startswith("search_"):
            return "SEARCH_INDEX_ENTRY"
        if resource_id.startswith("export_"):
            return "USER_EXPORT"
        if resource_id.startswith("data_flow_"):
            return "DATA_FLOW"
        if resource_id.startswith("backup_"):
            return "BACKUP_ARCHIVE"
        if resource_id.startswith("audit_record_"):
            return "SECURITY_AUDIT_LOG"
        if resource_id.startswith("tombstone_"):
            return "ACCOUNT_TOMBSTONE"
        if resource_id.startswith("support_"):
            if "attachment" in str(explicit_cat).lower():
                return "SUPPORT_ATTACHMENT"
            return "SUPPORT_MESSAGE"
        if resource_id.startswith("analytics_"):
            return "ANALYTICS_PROFILE"
        return "USER_PROFILE"

    def get_treatment(self, category: str) -> Optional[PolicyTreatment]:
        return self.rules.get(category)
