"""Standalone evaluation pipeline for Ghost Data Still Exists.
Computes case-level status accuracy, step-level precision/recall,
field-level concordance, and sequence correctness.
"""

import csv
import json
import os
import sys
from typing import Any, Dict, List, Set, Tuple


def evaluate_predictions(
    predicted_file: str,
    ground_truth_file: str,
) -> Dict[str, Any]:
    print(f"Evaluating predictions: {predicted_file}")
    print(f"Against ground truth:   {ground_truth_file}")

    pred_rows: Dict[str, Tuple[str, List[Dict[str, Any]]]] = {}
    with open(predicted_file, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = row["case_id"].strip()
            st = row["deletion_status"].strip()
            steps = json.loads(row["steps_json"])
            pred_rows[cid] = (st, steps)

    gt_rows: Dict[str, Tuple[str, List[Dict[str, Any]]]] = {}
    with open(ground_truth_file, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = row["case_id"].strip()
            st = row["deletion_status"].strip()
            steps = json.loads(row["steps_json"])
            gt_rows[cid] = (st, steps)

    common_cases = sorted(list(set(pred_rows.keys()) & set(gt_rows.keys())))
    if not common_cases:
        print("Warning: No overlapping cases found between predicted and ground truth!")
        return {}

    total_cases = len(common_cases)
    status_matches = 0
    exact_step_matches = 0
    total_gt_steps = 0
    total_pred_steps = 0
    matched_steps = 0
    field_matches = {
        "step_no": 0,
        "phase": 0,
        "system_id": 0,
        "resource_id": 0,
        "operation": 0,
        "state": 0,
        "evidence_id": 0,
    }
    field_comparisons = 0

    case_details = []

    for cid in common_cases:
        p_st, p_steps = pred_rows[cid]
        g_st, g_steps = gt_rows[cid]

        st_match = (p_st == g_st)
        if st_match:
            status_matches += 1

        exact_steps = (p_steps == g_steps)
        if exact_steps:
            exact_step_matches += 1

        total_gt_steps += len(g_steps)
        total_pred_steps += len(p_steps)

        # Step matching by (phase, resource_id, operation)
        gt_keys = {(s["phase"], s["resource_id"], s["operation"]): s for s in g_steps}
        for s in p_steps:
            k = (s["phase"], s["resource_id"], s["operation"])
            if k in gt_keys:
                matched_steps += 1
                gt_s = gt_keys[k]
                for fld in field_matches.keys():
                    field_comparisons += 1
                    if s.get(fld) == gt_s.get(fld):
                        field_matches[fld] += 1

        case_details.append({
            "case_id": cid,
            "status_match": st_match,
            "pred_status": p_st,
            "gt_status": g_st,
            "exact_steps": exact_steps,
            "pred_step_count": len(p_steps),
            "gt_step_count": len(g_steps),
        })

    status_acc = status_matches / total_cases if total_cases > 0 else 0.0
    exact_step_acc = exact_step_matches / total_cases if total_cases > 0 else 0.0
    step_precision = matched_steps / total_pred_steps if total_pred_steps > 0 else 0.0
    step_recall = matched_steps / total_gt_steps if total_gt_steps > 0 else 0.0
    step_f1 = (
        (2 * step_precision * step_recall) / (step_precision + step_recall)
        if (step_precision + step_recall) > 0
        else 0.0
    )

    summary = {
        "total_cases_evaluated": total_cases,
        "status_accuracy": status_acc,
        "status_matches": status_matches,
        "exact_step_matches": exact_step_matches,
        "exact_step_accuracy": exact_step_acc,
        "total_gt_steps": total_gt_steps,
        "total_pred_steps": total_pred_steps,
        "matched_steps": matched_steps,
        "step_precision": step_precision,
        "step_recall": step_recall,
        "step_f1": step_f1,
        "field_concordance": {
            k: (v / (matched_steps if matched_steps > 0 else 1))
            for k, v in field_matches.items()
        },
        "case_details": case_details,
    }

    print("\n" + "=" * 50)
    print("         FORENSIC AUDIT EVALUATION SUMMARY")
    print("=" * 50)
    print(f"Total Cases Evaluated:    {total_cases}")
    print(f"Case Status Accuracy:     {status_acc * 100:.2f}% ({status_matches}/{total_cases})")
    print(f"Exact Steps Accuracy:     {exact_step_acc * 100:.2f}% ({exact_step_matches}/{total_cases})")
    print(f"Step Precision:           {step_precision * 100:.2f}%")
    print(f"Step Recall:              {step_recall * 100:.2f}%")
    print(f"Step F1 Score:            {step_f1 * 100:.2f}%")
    print("\nField-Level Concordance (for matched steps):")
    for fld, score in summary["field_concordance"].items():
        print(f"  {fld:15s}: {score * 100:.2f}%")
    print("=" * 50)

    return summary


if __name__ == "__main__":
    p_file = sys.argv[1] if len(sys.argv) > 1 else "output.csv"
    g_file = sys.argv[2] if len(sys.argv) > 2 else "dataset/sample_output.csv"
    evaluate_predictions(p_file, g_file)
