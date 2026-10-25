"""Entrypoint for running evaluation on benchmark samples."""
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from code.main import run_audit
from code.evaluation.evaluator import evaluate_predictions


def main() -> None:
    dataset_dir = "dataset"
    sample_reqs = "sample_deletion_requests.csv"
    sample_gt = os.path.join(dataset_dir, "sample_output.csv")
    pred_output = os.path.join("code", "evaluation", "sample_predictions.csv")

    print("Running audit on benchmark sample requests...")
    run_audit(dataset_dir=dataset_dir, output_file=pred_output, requests_file=sample_reqs)

    print("\nEvaluating against benchmark ground truth...")
    metrics = evaluate_predictions(pred_output, sample_gt)
    print("\nEvaluation completed successfully.")


if __name__ == "__main__":
    main()
