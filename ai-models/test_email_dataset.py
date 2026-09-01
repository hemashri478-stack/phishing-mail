#!/usr/bin/env python3
"""
Evaluation Script for EmailAnalyzer against ai-models/email_dataset.csv
Calculates Overall Accuracy, Confusion Matrix (TP, TN, FP, FN), Per-Category Accuracy,
and exports full prediction details to ai-models/email_test_results.csv.
"""

import os
import sys
import ast
import pandas as pd

# Ensure backend directory is importable
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
backend_dir = os.path.join(project_root, "backend")

sys.path.insert(0, project_root)
sys.path.insert(0, backend_dir)

# Ensure UTF-8 output on Windows terminal
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from backend.email_analyzer import EmailAnalyzer

DATASET_PATH = os.path.join(current_dir, "email_dataset.csv")
RESULTS_PATH = os.path.join(current_dir, "email_test_results.csv")


def run_evaluation():
    print(f"📂 Loading dataset from: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    print(f"📊 Total Samples Loaded: {len(df)}")

    results = []
    mistakes = []

    tp = 0  # True Positive: True Phish (1) predicted as Phish (1)
    tn = 0  # True Negative: True Non-Phish (0) predicted as Non-Phish (0)
    fp = 0  # False Positive: True Non-Phish (0) predicted as Phish (1)
    fn = 0  # False Negative: True Phish (1) predicted as Non-Phish (0)

    category_stats = {}

    for _, row in df.iterrows():
        row_id = row.get("id")
        category = str(row.get("category", "UNKNOWN")).strip()
        true_is_phishing = int(row.get("is_phishing", 0))

        # Parse attachments safely
        att_raw = row.get("attachments", "[]")
        if pd.isna(att_raw) or not str(att_raw).strip():
            attachments = []
        elif isinstance(att_raw, list):
            attachments = att_raw
        else:
            try:
                attachments = ast.literal_eval(str(att_raw))
            except Exception:
                attachments = []

        # Prepare input dictionary expected by EmailAnalyzer
        email_input = {
            "from": "" if pd.isna(row.get("from")) else str(row.get("from")),
            "reply_to": "" if pd.isna(row.get("reply_to")) else str(row.get("reply_to")),
            "subject": "" if pd.isna(row.get("subject")) else str(row.get("subject")),
            "body": "" if pd.isna(row.get("body")) else str(row.get("body")),
            "body_html": "" if pd.isna(row.get("body_html")) else str(row.get("body_html")),
            "attachments": attachments
        }

        # Run detection
        analysis = EmailAnalyzer.analyze_email(email_input)

        risk_score = analysis.get("risk_score", 0)
        risk_level = analysis.get("risk_level", "Safe")
        pred_bool = analysis.get("is_phishing", False)
        predicted_is_phishing = 1 if pred_bool else 0

        threat_categories = analysis.get("threat_categories", [])
        if not threat_categories and analysis.get("threat_type") and analysis.get("threat_type") != "Clean":
            threat_categories = [analysis.get("threat_type")]
        detected_threats_str = "; ".join(threat_categories) if threat_categories else "Clean"

        is_correct = (predicted_is_phishing == true_is_phishing)

        # Confusion matrix accounting
        if true_is_phishing == 1 and predicted_is_phishing == 1:
            tp += 1
        elif true_is_phishing == 0 and predicted_is_phishing == 0:
            tn += 1
        elif true_is_phishing == 0 and predicted_is_phishing == 1:
            fp += 1
        elif true_is_phishing == 1 and predicted_is_phishing == 0:
            fn += 1

        # Per-category accounting
        if category not in category_stats:
            category_stats[category] = {"total": 0, "correct": 0, "predicted_phish": 0, "predicted_safe": 0}
        category_stats[category]["total"] += 1
        if is_correct:
            category_stats[category]["correct"] += 1
        if predicted_is_phishing == 1:
            category_stats[category]["predicted_phish"] += 1
        else:
            category_stats[category]["predicted_safe"] += 1

        # Record mistake if incorrect
        if not is_correct:
            mistakes.append({
                "id": row_id,
                "category": category,
                "from": email_input["from"][:40],
                "subject": email_input["subject"][:40],
                "true_is_phishing": true_is_phishing,
                "predicted_is_phishing": predicted_is_phishing,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "detected_threats": detected_threats_str
            })

        results.append({
            "id": row_id,
            "category": category,
            "true_is_phishing": true_is_phishing,
            "predicted_is_phishing": predicted_is_phishing,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "detected_threats": detected_threats_str,
            "correct": 1 if is_correct else 0
        })

    # Export results to CSV
    results_df = pd.DataFrame(results)
    results_df.to_csv(RESULTS_PATH, index=False, encoding="utf-8")
    print(f"💾 Detailed results exported to: {RESULTS_PATH}")

    total_samples = len(df)
    correct_count = tp + tn
    incorrect_count = fp + fn
    accuracy_pct = (correct_count / total_samples) * 100.0 if total_samples > 0 else 0.0

    print("\n" + "=" * 70)
    print("🎯 EMAIL ANALYZER EVALUATION SUMMARY REPORT")
    print("=" * 70)
    print(f"Total Samples Evaluated:    {total_samples}")
    print(f"Correct Predictions:        {correct_count}")
    print(f"Incorrect Predictions:      {incorrect_count}")
    print(f"Overall Accuracy:           {accuracy_pct:.2f}%")

    print("\n" + "-" * 70)
    print("📊 CONFUSION MATRIX")
    print("-" * 70)
    print(f"True Positives (TP)  [Phishing correctly caught]:     {tp:>3} / 45")
    print(f"True Negatives (TN)  [Non-phish correctly passed]:    {tn:>3} / 105")
    print(f"False Positives (FP) [Non-phish wrongly flagged]:     {fp:>3}")
    print(f"False Negatives (FN) [Phishing missed by detector]:   {fn:>3}")

    precision = (tp / (tp + fp)) * 100.0 if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    print(f"\nPrecision:                  {precision:.2f}%")
    print(f"Recall (Detection Rate):    {recall:.2f}%")
    print(f"F1-Score:                   {f1:.2f}%")

    print("\n" + "-" * 70)
    print("📋 PER-CATEGORY ACCURACY BREAKDOWN")
    print("-" * 70)
    print(f"{'Category':<15} {'Total':<8} {'Correct':<10} {'Accuracy (%)':<15} {'Ground Truth'}")
    print("-" * 70)
    for cat in ["LEGITIMATE", "SPAM", "PHISHING", "SUSPICIOUS"]:
        if cat in category_stats:
            stats = category_stats[cat]
            cat_acc = (stats["correct"] / stats["total"]) * 100.0 if stats["total"] > 0 else 0.0
            gt_label = "is_phishing = 1" if cat == "PHISHING" else "is_phishing = 0"
            print(f"{cat:<15} {stats['total']:<8} {stats['correct']:<10} {cat_acc:>6.2f}%         {gt_label}")

    print("\n" + "-" * 70)
    print(f"⚠️ MISTAKES / MISCLASSIFICATIONS ({len(mistakes)} Total)")
    print("-" * 70)
    if mistakes:
        print(f"Showing up to 10 misclassified emails:")
        for idx, m in enumerate(mistakes[:10], 1):
            print(f"\n[{idx}] Email ID #{m['id']} | Category: {m['category']}")
            print(f"    From:             {m['from']}")
            print(f"    Subject:          {m['subject']}")
            print(f"    True / Predicted: {m['true_is_phishing']} (Ground Truth) vs {m['predicted_is_phishing']} (Predicted)")
            print(f"    Risk Score:       {m['risk_score']}/100 ({m['risk_level']})")
            print(f"    Detected Threats: {m['detected_threats']}")
    else:
        print("🎉 PERFECT DETECTION: Zero misclassifications found!")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    run_evaluation()
