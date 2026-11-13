"""Decision logic of the original application (legacy/PhishingApp_v1.py), extracted
verbatim so it can be measured without Streamlit. Used only by ml/evaluate.py.

The pickles were produced with scikit-learn 1.7.2; loading them under a newer
version emits a warning but the linear model's arithmetic is unchanged.
"""
import pickle
import re
import warnings
from pathlib import Path

HERE = Path(__file__).parent
NEUTRAL_TOKENS = ["url", "com", "org", "www", "http", "https", "_email_"]
SAFE_DOMAINS = ["linkedin.com", "github.com", "python.org"]


def clean_text(text):
    text = str(text).lower()
    text = re.sub(r'http\S+|www\S+', ' _url_ ', text)
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', ' _email_ ', text)
    text = re.sub(r'\d+', '', text)
    text = re.sub(r'[^a-zA-Z\s_]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


class Baseline:
    def __init__(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with open(HERE / "model.pkl", "rb") as fh:
                self.model = pickle.load(fh)  # noqa: S301 - the project's own legacy artefact
            with open(HERE / "vectorizer.pkl", "rb") as fh:
                self.vectorizer = pickle.load(fh)  # noqa: S301
        self.feature_names = self.vectorizer.get_feature_names_out()
        self.coef = self.model.coef_[0]

    def classify(self, text: str) -> str:
        """Returns 'Phishing', 'Suspicious' or 'Legitimate' exactly as the original UI did."""
        vec = self.vectorizer.transform([clean_text(text)])
        prob = self.model.predict_proba(vec)[0][1]
        scores = [(self.feature_names[i], self.coef[i]) for i in vec.nonzero()[1]]
        scores = sorted(scores, key=lambda x: abs(x[1]), reverse=True)[:20]
        scores = [(w, s) for w, s in scores if not any(nt in w for nt in NEUTRAL_TOKENS)]
        has_indicator = any(s > 0 for _, s in scores)
        if any(d in text.lower() for d in SAFE_DOMAINS):
            return "Legitimate"
        if prob > 0.85 and has_indicator:
            return "Phishing"
        if prob > 0.6 and has_indicator:
            return "Suspicious"
        return "Legitimate"
