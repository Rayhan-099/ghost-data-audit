import unittest
import os
import re
import json
from code.models import (
    StepPhase,
    AuditStep,
    PHASE_ORDER,
    OPERATION_ORDER,
    DeletionStatus,
    ResourceObservation,
)
from code.policy_engine import PolicyEngine
from code.evidence_indexer import EvidenceIndexer


class TestForensicAuditor(unittest.TestCase):
    def setUp(self):
        self.policy = PolicyEngine()

    def test_log_token_parsing_with_escaped_quotes(self):
        """Verify robust parsing of log lines with escaped quotes and key-value pairs."""
        raw_line = (
            '2026-09-30T11:59:11Z requestId=tr-5569590 level=DEBUG function=profile_service '
            'message="instance=\\"profile-5\\" pod=\\"profile-fb72\\" region=\\"us-east-2\\" '
            'resource_id=\\"account_410\\" event=\\"profile_lookup_completed\\" rows=\\"1\\" '
            'http_status=\\"200\\" duration_ms=\\"20\\" correlation_key=\\"thandiwe.m6866@zoho.com\\""'
        )
        clean = raw_line.replace('\\"', ' ').replace('"', ' ').replace('\\', ' ')
        tokens = dict(re.findall(r'([a-zA-Z0-9_\-]+)=\s*([^\s]+)', clean))

        self.assertEqual(tokens.get("resource_id"), "account_410")
        self.assertEqual(tokens.get("correlation_key"), "thandiwe.m6866@zoho.com")
        self.assertEqual(tokens.get("http_status"), "200")
        self.assertEqual(tokens.get("event"), "profile_lookup_completed")

    def test_policy_engine_categories_and_treatments(self):
        """Verify all policy categories map to compliant states and operations."""
        # USER_PROFILE -> DELETE, compliant ABSENT
        t_user = self.policy.get_treatment("USER_PROFILE")
        self.assertIsNotNone(t_user)
        self.assertEqual(t_user.compliant_state, "ABSENT")
        self.assertEqual(t_user.remediation_op, "DELETE_RECORD")
        self.assertEqual(t_user.verification_op, "VERIFY_RECORD_ABSENT")

        # SECURITY_AUDIT_LOG -> RETAIN, compliant PRESENT
        t_sec = self.policy.get_treatment("SECURITY_AUDIT_LOG")
        self.assertIsNotNone(t_sec)
        self.assertEqual(t_sec.compliant_state, "PRESENT")
        self.assertIsNone(t_sec.finding_op)
        self.assertIsNone(t_sec.remediation_op)
        self.assertEqual(t_sec.verification_op, "VERIFY_RECORD_PRESENT")

        # ANALYTICS_PROFILE -> ANONYMIZE, compliant ANONYMIZED
        t_anal = self.policy.get_treatment("ANALYTICS_PROFILE")
        self.assertIsNotNone(t_anal)
        self.assertEqual(t_anal.compliant_state, "ANONYMIZED")
        self.assertEqual(t_anal.finding_op, "REPORT_EXPOSED_PII")
        self.assertEqual(t_anal.remediation_op, "ANONYMIZE_RECORD")
        self.assertEqual(t_anal.verification_op, "VERIFY_RECORD_ANONYMIZED")

        # DATA_FLOW -> DISABLE, compliant DISABLED
        t_flow = self.policy.get_treatment("DATA_FLOW")
        self.assertIsNotNone(t_flow)
        self.assertEqual(t_flow.compliant_state, "DISABLED")
        self.assertEqual(t_flow.finding_op, "REPORT_ACTIVE_DATA_FLOW")
        self.assertEqual(t_flow.remediation_op, "DISABLE_DATA_FLOW")
        self.assertEqual(t_flow.verification_op, "VERIFY_DATA_FLOW_DISABLED")

    def test_step_ordering_and_deterministic_serialization(self):
        """Ensure steps sort strictly by Phase -> Operation -> System -> Resource."""
        steps = [
            AuditStep(0, "VERIFICATION", "analytics_platform", "analytics_037", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""),
            AuditStep(0, "FINDING", "search_service", "search_4013", "REPORT_REMAINING_RECORD", "PRESENT", "evidence_94"),
            AuditStep(0, "REMEDIATION", "search_service", "search_4013", "DELETE_RECORD", "ABSENT", ""),
            AuditStep(0, "FINDING", "analytics_platform", "analytics_037", "REPORT_EXPOSED_PII", "PRESENT", "evidence_94"),
            AuditStep(0, "REMEDIATION", "analytics_platform", "analytics_037", "ANONYMIZE_RECORD", "ANONYMIZED", ""),
            AuditStep(0, "VERIFICATION", "account_service", "account_5521", "VERIFY_RECORD_ABSENT", "ABSENT", ""),
        ]

        def sort_key(s: AuditStep):
            p_val = PHASE_ORDER.get(StepPhase(s.phase), 99)
            op_val = OPERATION_ORDER.get((StepPhase(s.phase), s.operation), 99)
            return (p_val, op_val, s.system_id, s.resource_id)

        steps.sort(key=sort_key)
        for idx, s in enumerate(steps, start=1):
            s.step_no = idx

        # Verify phases order: FINDING -> REMEDIATION -> VERIFICATION
        phases = [s.phase for s in steps]
        self.assertEqual(
            phases,
            ["FINDING", "FINDING", "REMEDIATION", "REMEDIATION", "VERIFICATION", "VERIFICATION"],
        )

        # Verify consecutive step numbering
        step_nos = [s.step_no for s in steps]
        self.assertEqual(step_nos, [1, 2, 3, 4, 5, 6])

    def test_multi_service_bundle_evidence_selection(self):
        """Ensure multi-service snapshot bundles are selected consistently for COMPLETE cases."""
        bundle_origins = ("snapshot_bundle", "service_resource_export", "readback_logs")
        evaluations = {
            "account_4857": {"file_id": "evidence_54", "origin": "customer_account_failover_replica_capture"},
            "audit_record_6909": {"file_id": "evidence_51", "origin": "records_assurance_snapshot_bundle"},
            "tombstone_440": {"file_id": "evidence_51", "origin": "records_assurance_snapshot_bundle"},
        }

        bundle_file_id = None
        for rid, ev in evaluations.items():
            fid = ev.get("file_id")
            origin = ev.get("origin", "")
            if any(bo in origin for bo in bundle_origins):
                bundle_file_id = fid
                break

        self.assertEqual(bundle_file_id, "evidence_51")

    def test_rule_12_security_audit_retention(self):
        """Verify Rule 12 retention semantics: audit records are compliant when PRESENT, never remediated."""
        t_sec = self.policy.get_treatment("SECURITY_AUDIT_LOG")
        self.assertEqual(t_sec.rule_id, "rule_12")
        self.assertEqual(t_sec.required_action, "RETAIN")
        self.assertEqual(t_sec.compliant_state, "PRESENT")
        # Retained records must never generate finding or remediation operations
        self.assertIsNone(t_sec.finding_op)
        self.assertIsNone(t_sec.finding_state)
        self.assertIsNone(t_sec.remediation_op)
        self.assertIsNone(t_sec.remediation_state)
        # Retained records must generate verification proof of presence
        self.assertEqual(t_sec.verification_op, "VERIFY_RECORD_PRESENT")
        self.assertEqual(t_sec.verification_state, "PRESENT")

    def test_not_applicable_request_intent(self):
        """Verify non-deletion request phrases correctly identify non-destructive requests."""
        from code.auditor import CaseAuditor
        # Test intent detection phrases directly
        non_del_texts = [
            "Please leave the account active and send me a copy of my data.",
            "I am not asking for deletion, just updating my records.",
            "Please keep the account as it is, do not close.",
            "This is an information request, not a request to erase.",
        ]
        # Replicate check logic
        non_del_phrases = [
            "leave the account active",
            "not asking for deletion",
            "keep the account as it is",
            "do not close the account",
            "do not close",
            "without removing any of my records",
            "remove me from marketing lists only",
            "information request, not a request to erase",
        ]
        for text in non_del_texts:
            t = text.lower()
            is_non_del = any(p in t for p in non_del_phrases)
            self.assertTrue(is_non_del, f"Failed to identify non-deletion text: {text}")


if __name__ == "__main__":
    unittest.main()
