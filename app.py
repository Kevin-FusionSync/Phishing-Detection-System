import json
from pathlib import Path

import pandas as pd
import streamlit as st

from phishing.scorer import HIGH_CUTOFF, LOW_CUTOFF, PhishingDetector

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"

st.set_page_config(page_title="Phishing Detection & Awareness", page_icon="🛡️", layout="wide")


@st.cache_resource
def get_detector():
    return PhishingDetector()


def show_level(level, score):
    message = f"**{level} risk** — score {score:.0%}"
    if level == "High":
        st.error(message)
    elif level == "Medium":
        st.warning(message)
    else:
        st.success(message)


def show_result(result):
    show_level(result.risk_level, result.risk_score)

    c1, c2, c3 = st.columns(3)
    c1.metric("Combined risk", f"{result.risk_score:.0%}")
    c2.metric("ML phishing probability", "n/a" if result.ml_probability is None else f"{result.ml_probability:.0%}")
    c3.metric("Rule-based score", f"{result.rule_score:.0%}")
    st.progress(min(max(result.risk_score, 0.0), 1.0))

    st.subheader("Why this result?")
    for line in result.explanation:
        st.write("• " + line)

    if result.indicators:
        st.subheader("Detected indicators")
        st.dataframe(
            pd.DataFrame([f.to_dict() for f in result.indicators]).rename(columns=str.title),
            width="stretch",
            hide_index=True,
        )

    if result.urls:
        st.subheader("Links found")
        st.dataframe(
            pd.DataFrame([
                {"URL": u.url, "Domain": u.domain, "Score": f"{u.score:.0%}", "Issues": ", ".join(f.name for f in u.findings) or "None"}
                for u in result.urls
            ]),
            width="stretch",
            hide_index=True,
        )

    if result.top_terms:
        with st.expander("Words that influenced the classifier"):
            st.bar_chart(pd.DataFrame(result.top_terms, columns=["term", "weight"]).set_index("term"))

    left, right = st.columns(2)
    with left:
        st.subheader("Recommended actions")
        for action in result.actions:
            st.write("✔ " + action)
    with right:
        if result.tips:
            st.subheader("Awareness tips")
            for tip in result.tips:
                st.info(tip)


def analyze_page():
    st.title("🛡️ Phishing Risk Analyzer")
    st.caption("Paste a suspicious email to estimate its phishing risk.")

    detector = get_detector()
    if not detector.has_model:
        st.warning("No trained model found in models/. Results will use rule-based checks only. "
                   "Run `python -m phishing.train --data data/<dataset>.csv` first.")

    with st.form("analyze"):
        sender = st.text_input("Sender (optional)", placeholder="PayPal Support <support@paypa1-secure.com>")
        subject = st.text_input("Subject (optional)")
        body = st.text_area("Email body", height=250, placeholder="Paste the full email text here. Raw headers and HTML are fine.")
        submitted = st.form_submit_button("Analyze", type="primary")

    if not submitted:
        return
    if not (body.strip() or subject.strip()):
        st.error("Please enter an email to analyze.")
        return

    result = detector.analyze(text=body, sender=sender, subject=subject)
    show_result(result)


def performance_page():
    st.title("📊 Model Performance")
    metrics_file = REPORTS / "metrics.json"
    if not metrics_file.exists():
        st.info("No evaluation results yet. Train the model to generate reports/metrics.json.")
        return

    data = json.loads(metrics_file.read_text(encoding="utf-8"))
    test = data["test"]

    st.caption(f"Dataset: {data['dataset']} — {data['rows']:,} emails "
               f"({data['class_counts']['phishing']:,} phishing / {data['class_counts']['legitimate']:,} legitimate)")
    st.caption(f"Split: train {data['split']['train']:,} · validation {data['split']['validation']:,} · "
               f"test {data['split']['test']:,} · best C = {data['best_c']}")

    cols = st.columns(5)
    for col, key, label in zip(cols, ["accuracy", "precision", "recall", "f1", "roc_auc"],
                               ["Accuracy", "Precision", "Recall", "F1-score", "ROC AUC"]):
        col.metric(label, f"{test[key]:.3f}")

    left, right = st.columns(2)
    with left:
        st.subheader("Confusion matrix")
        image = REPORTS / "confusion_matrix.png"
        if image.exists():
            st.image(str(image))
        else:
            st.write(pd.DataFrame(test["confusion_matrix"], index=["Actual legit", "Actual phishing"],
                                  columns=["Pred legit", "Pred phishing"]))
    with right:
        st.subheader("Classification report")
        report = pd.DataFrame(test["report"]).T.round(3)
        st.dataframe(report, width="stretch")
        st.subheader("Validation F1 by C")
        st.line_chart(pd.Series({float(k): v for k, v in data["validation_f1"].items()}, name="F1"))

    st.subheader("Most informative terms")
    t1, t2 = st.columns(2)
    t1.write("**Phishing**")
    t1.dataframe(pd.DataFrame(data["top_features"]["phishing"], columns=["term", "weight"]), hide_index=True)
    t2.write("**Legitimate**")
    t2.dataframe(pd.DataFrame(data["top_features"]["legitimate"], columns=["term", "weight"]), hide_index=True)

    st.caption(f"Risk levels: Low < {LOW_CUTOFF:.0%} ≤ Medium < {HIGH_CUTOFF:.0%} ≤ High")


PAGES = {
    "Analyze": analyze_page,
    "Model Performance": performance_page,
}

choice = st.sidebar.radio("Navigation", list(PAGES))
st.sidebar.divider()
st.sidebar.caption("AI-based Phishing Detection and Cybersecurity Awareness System")
PAGES[choice]()
