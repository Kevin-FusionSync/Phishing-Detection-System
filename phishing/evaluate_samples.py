import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from .scorer import PhishingDetector

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description="Run the detector on the simulated phishing/legitimate test cases.")
    parser.add_argument("--samples", default=str(ROOT / "samples" / "simulated_emails.json"))
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--out", default=str(ROOT / "reports" / "simulated_results.csv"))
    args = parser.parse_args()

    with open(args.samples, encoding="utf-8") as fh:
        cases = json.load(fh)

    detector = PhishingDetector()
    if not detector.has_model:
        print("Warning: no trained model found, results use rule-based checks only.")

    rows = []
    for case in cases:
        result = detector.analyze(
            text=case.get("body", ""),
            url=case.get("url", ""),
            sender=case.get("sender", ""),
            subject=case.get("subject", ""),
        )
        predicted = "phishing" if result.risk_score >= args.threshold else "legitimate"
        rows.append({
            "id": case["id"],
            "expected": case["expected"],
            "predicted": predicted,
            "risk_level": result.risk_level,
            "risk_score": round(result.risk_score, 3),
            "ml_probability": None if result.ml_probability is None else round(result.ml_probability, 3),
            "rule_score": round(result.rule_score, 3),
            "indicators": "; ".join(f.name for f in result.indicators),
        })

    df = pd.DataFrame(rows)
    y_true = (df["expected"] == "phishing").astype(int)
    y_pred = (df["predicted"] == "phishing").astype(int)

    pd.set_option("display.width", 200)
    print(df[["id", "expected", "predicted", "risk_level", "risk_score", "ml_probability", "rule_score"]].to_string(index=False))
    print()
    print(f"Accuracy : {accuracy_score(y_true, y_pred):.3f}")
    print(f"Precision: {precision_score(y_true, y_pred, zero_division=0):.3f}")
    print(f"Recall   : {recall_score(y_true, y_pred, zero_division=0):.3f}")
    print(f"F1-score : {f1_score(y_true, y_pred, zero_division=0):.3f}")
    print("Confusion matrix [[TN, FP], [FN, TP]]:", confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist())

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print(f"Saved results to {out}")


if __name__ == "__main__":
    main()
