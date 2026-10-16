import re

import pandas as pd

TEXT_COLUMNS = ["text_combined", "email text", "text", "email", "message", "content", "body"]
LABEL_COLUMNS = ["label", "email type", "class", "target", "is_phishing", "category"]
PHISHING_LABELS = {"1", "phishing", "phishing email", "spam", "malicious", "fraud", "scam", "true", "yes"}
LEGIT_LABELS = {"0", "safe", "safe email", "legitimate", "legit", "ham", "benign", "false", "no"}

URL_RE = re.compile(r"(https?://\S+|www\.\S+)", re.I)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
HTML_RE = re.compile(r"<[^>]+>")
NUMBER_RE = re.compile(r"\d+")
NON_ALPHA_RE = re.compile(r"[^a-z\s]")
SPACE_RE = re.compile(r"\s+")


def clean_text(text):
    if text is None:
        return ""
    text = str(text).lower()
    text = HTML_RE.sub(" ", text)
    text = URL_RE.sub(" urltoken ", text)
    text = EMAIL_RE.sub(" emailtoken ", text)
    text = NUMBER_RE.sub(" numtoken ", text)
    text = NON_ALPHA_RE.sub(" ", text)
    return SPACE_RE.sub(" ", text).strip()


def _find_column(columns, candidates):
    lookup = {str(c).strip().lower(): c for c in columns}
    for name in candidates:
        if name in lookup:
            return lookup[name]
    return None


def to_label(value):
    v = str(value).strip().lower()
    if v in PHISHING_LABELS:
        return 1
    if v in LEGIT_LABELS:
        return 0
    try:
        return 1 if float(v) >= 1 else 0
    except ValueError:
        return None


def load_dataset(path):
    df = pd.read_csv(path, encoding_errors="ignore", low_memory=False)
    label_col = _find_column(df.columns, LABEL_COLUMNS)
    text_col = _find_column(df.columns, TEXT_COLUMNS)
    subject_col = _find_column(df.columns, ["subject"])

    if label_col is None or text_col is None:
        raise ValueError(f"Could not find text/label columns in {path}. Columns: {list(df.columns)}")

    text = df[text_col].fillna("").astype(str)
    if subject_col is not None and text_col != subject_col and str(text_col).lower() == "body":
        text = df[subject_col].fillna("").astype(str) + " " + text

    data = pd.DataFrame({"text": text, "label": df[label_col].map(to_label)})
    data = data.dropna(subset=["label"])
    data["label"] = data["label"].astype(int)
    data["clean"] = data["text"].map(clean_text)
    data = data[data["clean"].str.len() > 0]
    data = data.drop_duplicates(subset="clean").reset_index(drop=True)
    return data
