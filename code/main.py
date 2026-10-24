"""Production runner for Ghost Data Still Exists forensic audit engine.
Processes all 518 cases from dataset/deletion_requests.csv and outputs output.csv.
"""

import csv
import json
import os
import sys
from typing import List, Tuple

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from code.identity_resolver import IdentityResolver
from code.evidence_indexer import EvidenceIndexer
from code.policy_engine import PolicyEngine
from code.auditor import CaseAuditor
from code.models import DeletionRequest, DeletionStatus, AuditStep


def run_audit(
    dataset_dir: str = "dataset",
    output_file: str = "output.csv",
    requests_file: str = "deletion_requests.csv",
) -> None:
    print(f"Initializing forensic audit engine with data from: {dataset_dir}")
    resolver = IdentityResolver(
        os.path.join(dataset_dir, "user_identities.csv"),
        os.path.join(dataset_dir, "user_audit_log.csv"),
    )
    indexer = EvidenceIndexer(dataset_dir)
    policy = PolicyEngine()
    auditor = CaseAuditor(resolver, indexer, policy)

    req_path = os.path.join(dataset_dir, requests_file)
    if not os.path.exists(req_path):
        raise FileNotFoundError(f"Missing deletion requests file: {req_path}")

    requests: List[DeletionRequest] = []
    with open(req_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            requests.append(
                DeletionRequest(
                    case_id=row["case_id"].strip(),
                    email=row["email"].strip(),
                    requested_at=row["requested_at"].strip(),
                    reported_status=row["reported_status"].strip(),
                    reported_at=row["reported_at"].strip(),
                    audit_at=row["audit_at"].strip(),
                    request_text=row["request_text"].strip(),
                )
            )

    # Sort requests by case_id (numeric sort on case_XX)
    def case_sort_key(r: DeletionRequest) -> int:
        part = r.case_id.replace("case_", "")
        return int(part) if part.isdigit() else 999999

    requests.sort(key=case_sort_key)
    print(f"Loaded {len(requests)} deletion requests to audit.")

    results: List[Tuple[str, str, str]] = []
    status_counts = {
        DeletionStatus.COMPLETE.value: 0,
        DeletionStatus.INCOMPLETE.value: 0,
        DeletionStatus.NOT_APPLICABLE.value: 0,
    }

    for req in requests:
        status, steps = auditor.audit_case(req)
        status_counts[status.value] += 1
        steps_dicts = [s.to_dict() for s in steps]
        steps_json = json.dumps(steps_dicts, separators=(",", ":"))
        results.append((req.case_id, status.value, steps_json))

    # Write output.csv at root
    with open(output_file, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for row in results:
            writer.writerow(row)

    print(f"Successfully generated {output_file} with {len(results)} rows.")
    print("Status distribution:")
    for st, count in status_counts.items():
        print(f"  {st}: {count} ({count / len(results) * 100:.1f}%)")


if __name__ == "__main__":
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else "dataset"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "output.csv"
    req_file = sys.argv[3] if len(sys.argv) > 3 else "deletion_requests.csv"
    run_audit(dataset_path, out_path, req_file)
