import argparse
import json
import time
from pathlib import Path

import joblib
import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from .preprocess import load_dataset

ROOT = Path(__file__).resolve().parent.parent
C_VALUES = [0.1, 0.5, 1.0, 2.0, 5.0, 10.0]


def make_vectorizer(max_features):
    return TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
        sublinear_tf=True,
        max_features=max_features,
    )


def make_classifier(c, seed):
    return LogisticRegression(C=c, max_iter=2000, class_weight="balanced", solver="liblinear", random_state=seed)


def split(data, seed):
    train, rest = train_test_split(data, test_size=0.30, stratify=data["label"], random_state=seed)
    val, test = train_test_split(rest, test_size=0.50, stratify=rest["label"], random_state=seed)
    return train, val, test


def tune(train, val, max_features, seed):
    vectorizer = make_vectorizer(max_features)
    x_train = vectorizer.fit_transform(train["clean"])
    x_val = vectorizer.transform(val["clean"])
    scores = {}
    for c in C_VALUES:
        clf = make_classifier(c, seed).fit(x_train, train["label"])
        scores[c] = f1_score(val["label"], clf.predict(x_val))
        print(f"  C={c:<5} validation F1={scores[c]:.4f}")
    best = max(scores, key=scores.get)
    return best, scores


def evaluate(model, test):
    y_true = test["label"]
    y_pred = model.predict(test["clean"])
    y_prob = model.predict_proba(test["clean"])[:, list(model.classes_).index(1)]
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred),
        "recall": recall_score(y_true, y_pred),
        "f1": f1_score(y_true, y_pred),
        "roc_auc": roc_auc_score(y_true, y_prob),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "report": classification_report(y_true, y_pred, target_names=["Legitimate", "Phishing"], output_dict=True),
    }


def top_features(model, k=25):
    names = model.named_steps["tfidf"].get_feature_names_out()
    coef = model.named_steps["clf"].coef_[0]
    order = coef.argsort()
    return {
        "phishing": [[str(names[i]), round(float(coef[i]), 4)] for i in order[::-1][:k]],
        "legitimate": [[str(names[i]), round(float(coef[i]), 4)] for i in order[:k]],
    }


def save_confusion_matrix(matrix, path):
    fig, ax = plt.subplots(figsize=(5, 4))
    ConfusionMatrixDisplay(confusion_matrix=np.array(matrix), display_labels=["Legitimate", "Phishing"]).plot(
        ax=ax, cmap="Blues", values_format="d", colorbar=False
    )
    ax.set_title("Confusion Matrix (test set)")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Train the TF-IDF + Logistic Regression phishing classifier.")
    parser.add_argument("--data", required=True, help="Path to a labelled CSV dataset")
    parser.add_argument("--models-dir", default=str(ROOT / "models"))
    parser.add_argument("--reports-dir", default=str(ROOT / "reports"))
    parser.add_argument("--max-features", type=int, default=200000)
    parser.add_argument("--sample", type=int, default=0, help="Use a random subset of N rows for quick experiments")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    models_dir = Path(args.models_dir)
    reports_dir = Path(args.reports_dir)
    models_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading {args.data}")
    data = load_dataset(args.data)
    if args.sample and args.sample < len(data):
        data = data.sample(n=args.sample, random_state=args.seed).reset_index(drop=True)
    counts = data["label"].value_counts().to_dict()
    print(f"{len(data)} rows after cleaning (phishing={counts.get(1, 0)}, legitimate={counts.get(0, 0)})")

    train, val, test = split(data, args.seed)
    print(f"Split -> train={len(train)}, validation={len(val)}, test={len(test)}")

    print("Tuning regularisation strength on the validation set")
    best_c, val_scores = tune(train, val, args.max_features, args.seed)
    print(f"Best C = {best_c}")

    train_full = pd.concat([train, val])
    model = Pipeline([
        ("tfidf", make_vectorizer(args.max_features)),
        ("clf", make_classifier(best_c, args.seed)),
    ])
    model.fit(train_full["clean"], train_full["label"])

    metrics = evaluate(model, test)
    train_acc = accuracy_score(train_full["label"], model.predict(train_full["clean"]))
    start = time.perf_counter()
    model.predict_proba(test["clean"])
    ms_per_email = (time.perf_counter() - start) * 1000 / len(test)
    print(f"Test accuracy={metrics['accuracy']:.4f} precision={metrics['precision']:.4f} "
          f"recall={metrics['recall']:.4f} f1={metrics['f1']:.4f} roc_auc={metrics['roc_auc']:.4f}")
    print("Confusion matrix [[TN, FP], [FN, TP]]:", metrics["confusion_matrix"])
    print(f"Fit check: train accuracy={train_acc:.4f} test accuracy={metrics['accuracy']:.4f} "
          f"gap={train_acc - metrics['accuracy']:.4f}")
    print(f"Prediction speed: {ms_per_email:.3f} ms per email")

    joblib.dump(model, models_dir / "phishing_model.joblib")
    save_confusion_matrix(metrics["confusion_matrix"], reports_dir / "confusion_matrix.png")

    summary = {
        "dataset": str(args.data),
        "rows": len(data),
        "class_counts": {"phishing": int(counts.get(1, 0)), "legitimate": int(counts.get(0, 0))},
        "split": {"train": len(train), "validation": len(val), "test": len(test)},
        "best_c": best_c,
        "validation_f1": {str(k): round(v, 4) for k, v in val_scores.items()},
        "train_accuracy": train_acc,
        "ms_per_email": round(ms_per_email, 4),
        "test": metrics,
        "top_features": top_features(model),
    }
    with open(reports_dir / "metrics.json", "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"Model saved to {models_dir / 'phishing_model.joblib'}")
    print(f"Reports saved to {reports_dir}")


if __name__ == "__main__":
    main()
