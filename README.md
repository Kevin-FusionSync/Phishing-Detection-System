# AI-Based Phishing Detection and Cybersecurity Awareness System

A web-based prototype that analyses a submitted email, estimates its phishing risk and explains the result.

## Features

- Streamlit web interface for submitting email text (with optional sender/subject)
- Phishing indicator extraction: suspicious URLs, urgency, sender/domain mismatch, Reply-To mismatch, brand impersonation, look-alike domains, link-text mismatch, risky attachments, requests for sensitive information
- TF-IDF + Logistic Regression text classifier trained on a labelled public dataset
- Combined risk score (ML probability + rule score) with Low / Medium / High levels and a written explanation
- Recommended actions and tips based on the detected warning signs
- Evaluation with accuracy, precision, recall, F1-score, ROC AUC and a confusion matrix

## Project structure

```
app.py                      Streamlit application
phishing/
  preprocess.py             dataset loading and text cleaning
  url_rules.py              rules for links found in emails
  indicators.py             email indicator extraction
  scorer.py                 ML + rule risk scoring
  awareness.py              recommended actions and tips
  train.py                  model training and evaluation
tests/test_rules.py
data/                       place the dataset CSV here
models/                     trained model is saved here
reports/                    metrics.json, confusion_matrix.png
```

## Dataset

Recommended: **Phishing Email Dataset** by Naser Abdullah Alam (Kaggle)
https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset

Download `phishing_email.csv` (about 82,000 emails combined from Enron, Ling, CEAS, Nazario, Nigerian Fraud and SpamAssassin, columns `text_combined` and `label`) and put it in `data/`.

The loader also accepts other common formats, for example the Kaggle "Phishing Emails" dataset (`Email Text` / `Email Type`) or any of the individual source files with `subject`, `body` and `label` columns.

## Setup

Requires Python 3.11 or newer. The pinned versions in `requirements.txt` were tested with Python 3.13.

macOS / Linux:

```
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

On macOS the system `python3` may be too old; install a newer one with `brew install python@3.13` and create the venv with `python3.13 -m venv .venv`.

Windows:

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Train and evaluate

```
python -m phishing.train --data data/phishing_email.csv
python -m unittest discover -s tests -v
```

Use `--sample 20000` with the train command for a faster first run. The full dataset takes about 1–2 minutes.

Training creates `models/phishing_model.joblib`. Retrain after changing the scikit-learn version, because saved models are not guaranteed to load across versions. Without a trained model the app still runs, using rule-based checks only.

## Run the app

```
streamlit run app.py
```

The app opens at http://localhost:8501.
