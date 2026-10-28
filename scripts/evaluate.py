"""Evaluation script calculating SOC detection metrics (Accuracy, Precision, Recall, F1, FPR, Confusion Matrix)."""

from __future__ import annotations

import glob
from pathlib import Path
import sys
from typing import Dict, List, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mailguard.cli import MailGuardAnalyzer
from mailguard.models import Verdict


def evaluate_corpus() -> Dict[str, Any]:
    console = Console()
    base_dir = Path(__file__).resolve().parent.parent
    samples_dir = base_dir / "samples"

    analyzer = MailGuardAnalyzer(offline=True)

    categories = ["legit", "suspicious", "spoofed"]
    expected_mapping = {
        "legit": Verdict.LEGITIMATE,
        "suspicious": Verdict.SUSPICIOUS,
        "spoofed": Verdict.SPOOFED,
    }

    # Confusion matrix for 3 classes: [actual][predicted]
    labels = [Verdict.LEGITIMATE, Verdict.SUSPICIOUS, Verdict.SPOOFED]
    matrix: Dict[Verdict, Dict[Verdict, int]] = {
        act: {pred: 0 for pred in labels} for act in labels
    }

    total_samples = 0
    correct_samples = 0
    misclassified: List[Tuple[str, str, str]] = []

    # Binary metrics tracking (Negative = LEGITIMATE, Positive = SUSPICIOUS or SPOOFED)
    tp = 0  # True Positive: actual suspicious/spoofed predicted as suspicious/spoofed
    fp = 0  # False Positive: actual legitimate predicted as suspicious/spoofed
    tn = 0  # True Negative: actual legitimate predicted as legitimate
    fn = 0  # False Negative: actual suspicious/spoofed predicted as legitimate

    file_results = []

    for cat in categories:
        target_dir = samples_dir / cat
        eml_files = sorted(list(target_dir.glob("*.eml")))
        expected_verdict = expected_mapping[cat]

        for eml in eml_files:
            total_samples += 1
            res = analyzer.analyze_file(eml)
            predicted_verdict = res.verdict

            matrix[expected_verdict][predicted_verdict] += 1
            is_correct = (expected_verdict == predicted_verdict)
            if is_correct:
                correct_samples += 1
            else:
                misclassified.append((eml.name, expected_verdict.value, predicted_verdict.value))

            # Binary classification mapping
            is_actual_threat = (expected_verdict in (Verdict.SUSPICIOUS, Verdict.SPOOFED))
            is_pred_threat = (predicted_verdict in (Verdict.SUSPICIOUS, Verdict.SPOOFED))

            if is_actual_threat and is_pred_threat:
                tp += 1
            elif not is_actual_threat and is_pred_threat:
                fp += 1
            elif not is_actual_threat and not is_pred_threat:
                tn += 1
            elif is_actual_threat and not is_pred_threat:
                fn += 1

            file_results.append({
                "file": eml.name,
                "category": cat,
                "score": res.risk_score,
                "verdict": predicted_verdict.value,
                "status": "PASS" if is_correct else "MISCLASSIFIED",
            })

    # Metric computations
    accuracy = (correct_samples / total_samples) if total_samples > 0 else 0.0
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # Display Results via Rich
    console.print(Panel(
        f"[bold cyan]MailGuard Synthetic Sample Evaluation Results[/bold cyan]\n"
        f"Total Samples Analyzed: [bold white]{total_samples}[/bold white] | "
        f"Correct: [bold green]{correct_samples}[/bold green] | "
        f"Accuracy: [bold green]{accuracy * 100:.1f}%[/bold green]",
        expand=False,
    ))

    # Binary Metrics Table
    metrics_table = Table(title="SOC Binary Detection Performance (Threat vs Benign)", expand=True)
    metrics_table.add_column("Metric", style="bold cyan")
    metrics_table.add_column("Formula / Definition", style="dim")
    metrics_table.add_column("Value", style="bold green", justify="right")

    metrics_table.add_row("Accuracy", "(TP + TN) / Total", f"{accuracy * 100:.1f}%")
    metrics_table.add_row("Precision", "TP / (TP + FP)", f"{precision * 100:.1f}%")
    metrics_table.add_row("Recall (Sensitivity)", "TP / (TP + FN)", f"{recall * 100:.1f}%")
    metrics_table.add_row("F1-Score", "2 * (P * R) / (P + R)", f"{f1:.4f}")
    metrics_table.add_row("False Positive Rate (FPR)", "FP / (FP + TN)", f"{fpr * 100:.1f}%")
    console.print(metrics_table)

    # 3x3 Multi-Class Confusion Matrix Table
    cm_table = Table(title="Multi-Class Confusion Matrix (Ground Truth vs Predicted)", expand=True)
    cm_table.add_column("Ground Truth \\ Predicted", style="bold magenta")
    cm_table.add_column("Pred LEGITIMATE", justify="center")
    cm_table.add_column("Pred SUSPICIOUS", justify="center")
    cm_table.add_column("Pred SPOOFED", justify="center")

    for act in labels:
        cm_table.add_row(
            f"Actual {act.value}",
            str(matrix[act][Verdict.LEGITIMATE]),
            str(matrix[act][Verdict.SUSPICIOUS]),
            str(matrix[act][Verdict.SPOOFED]),
        )
    console.print(cm_table)

    # Misclassifications Report
    if misclassified:
        err_table = Table(title="Misclassified Samples", expand=True)
        err_table.add_column("Filename", style="bold red")
        err_table.add_column("Expected", style="yellow")
        err_table.add_column("Predicted", style="red")
        for fn_name, exp_v, pred_v in misclassified:
            err_table.add_row(fn_name, exp_v, pred_v)
        console.print(err_table)
    else:
        console.print("[bold green]Zero misclassifications on synthetic ground truth corpus![/bold green]\n")

    return {
        "total_samples": total_samples,
        "correct_samples": correct_samples,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "confusion_matrix": {act.value: {p.value: matrix[act][p] for p in labels} for act in labels},
        "misclassified": misclassified,
    }


if __name__ == "__main__":
    evaluate_corpus()
