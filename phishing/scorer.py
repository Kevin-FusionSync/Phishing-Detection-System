from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

from .awareness import recommended_actions, tips_for
from .common import noisy_or
from .indicators import extract_indicators
from .preprocess import clean_text

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "models" / "phishing_model.joblib"

ML_WEIGHT = 0.9
LOW_CUTOFF = 0.35
HIGH_CUTOFF = 0.65


def risk_level(score):
    if score >= HIGH_CUTOFF:
        return "High"
    if score >= LOW_CUTOFF:
        return "Medium"
    return "Low"


@dataclass
class AnalysisResult:
    risk_score: float
    risk_level: str
    ml_probability: Optional[float]
    rule_score: float
    indicators: list
    urls: list
    top_terms: list
    explanation: list
    actions: list
    tips: list = field(default_factory=list)

    def to_dict(self):
        return {
            "risk_score": round(self.risk_score, 4),
            "risk_level": self.risk_level,
            "ml_probability": None if self.ml_probability is None else round(self.ml_probability, 4),
            "rule_score": round(self.rule_score, 4),
            "indicators": [f.to_dict() for f in self.indicators],
            "urls": [u.to_dict() for u in self.urls],
            "top_terms": self.top_terms,
            "explanation": self.explanation,
            "actions": self.actions,
            "tips": self.tips,
        }


class PhishingDetector:
    def __init__(self, model_path=MODEL_PATH):
        self.model_path = Path(model_path)
        self.model = joblib.load(self.model_path) if self.model_path.exists() else None

    @property
    def has_model(self):
        return self.model is not None

    def _phishing_index(self):
        classes = list(self.model.named_steps["clf"].classes_)
        return classes.index(1)

    def predict_proba(self, text):
        cleaned = clean_text(text)
        if self.model is None or not cleaned:
            return None, []
        prob = float(self.model.predict_proba([cleaned])[0][self._phishing_index()])
        return prob, self._top_terms(cleaned)

    def _top_terms(self, cleaned, k=8):
        vectorizer = self.model.named_steps["tfidf"]
        clf = self.model.named_steps["clf"]
        row = vectorizer.transform([cleaned]).tocsr()
        if row.nnz == 0:
            return []
        coef = clf.coef_[0] if self._phishing_index() == 1 else -clf.coef_[0]
        contributions = row.data * coef[row.indices]
        names = vectorizer.get_feature_names_out()
        order = np.argsort(contributions)[::-1]
        return [
            (str(names[row.indices[i]]), round(float(contributions[i]), 4))
            for i in order[:k]
            if contributions[i] > 0
        ]

    def analyze(self, text="", url="", sender="", subject=""):
        body = "\n".join(part for part in (subject, text) if part and part.strip())
        findings, url_reports = extract_indicators(body, sender=sender, url=url)

        strongest = {}
        for f in findings:
            if f.name not in strongest or f.weight > strongest[f.name].weight:
                strongest[f.name] = f
        unique = sorted(strongest.values(), key=lambda f: f.weight, reverse=True)
        rule_score = noisy_or(f.weight for f in unique)

        ml_prob, terms = self.predict_proba(body) if body else (None, [])
        if ml_prob is None:
            score = rule_score
        else:
            score = noisy_or([ML_WEIGHT * ml_prob, rule_score])

        level = risk_level(score)
        return AnalysisResult(
            risk_score=score,
            risk_level=level,
            ml_probability=ml_prob,
            rule_score=rule_score,
            indicators=unique,
            urls=url_reports,
            top_terms=terms,
            explanation=self._explain(level, score, ml_prob, unique, terms, bool(body)),
            actions=recommended_actions(level),
            tips=tips_for(unique),
        )

    def _explain(self, level, score, ml_prob, findings, terms, has_text):
        lines = [f"Overall risk is {level} ({score:.0%})."]
        if ml_prob is not None:
            lines.append(f"The text classifier estimates a {ml_prob:.0%} probability that this content is phishing.")
        elif has_text and self.model is None:
            lines.append("The text classifier is not trained yet, so only rule-based checks were used.")
        else:
            lines.append("Only a link was submitted, so the result is based on URL rules.")
        if findings:
            names = ", ".join(f.name.lower() for f in findings[:3])
            lines.append(f"{len(findings)} warning sign(s) were found. The strongest: {names}.")
        else:
            lines.append("No rule-based warning signs were detected.")
        if terms:
            lines.append("Words that pushed the classifier toward phishing: " + ", ".join(t for t, _ in terms[:6]) + ".")
        return lines
