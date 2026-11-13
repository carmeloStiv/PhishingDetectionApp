"""Loading and running the trained models. A missing or incompatible model
degrades to "ML unavailable" instead of failing the analysis."""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

from .features import FEATURE_NAMES, extract_features
from .urltools import ParsedURL

log = logging.getLogger(__name__)
MODEL_DIR = Path(__file__).parent / "models"


@lru_cache(maxsize=1)
def _url_model():
    try:
        import joblib
        import sklearn

        meta = json.loads((MODEL_DIR / "url_model_meta.json").read_text())
        if meta["features"] != FEATURE_NAMES:
            raise RuntimeError("feature list does not match the trained model")
        if meta["sklearn_version"].split(".")[:2] != sklearn.__version__.split(".")[:2]:
            raise RuntimeError(
                f"model was trained with scikit-learn {meta['sklearn_version']}, "
                f"running {sklearn.__version__}; retrain with `python -m ml.train_url_model`"
            )
        return joblib.load(MODEL_DIR / "url_model.joblib"), meta
    except Exception as exc:  # noqa: BLE001
        log.warning("URL model unavailable: %s", exc)
        return None, {"error": str(exc)}


def url_model_score(p: ParsedURL) -> float | None:
    """Model score in [0, 1] (higher = more phishing-like), or None if unavailable."""
    model, _ = _url_model()
    if model is None:
        return None
    return float(model.predict_proba([extract_features(p)])[0][1])


def url_model_info() -> dict:
    return _url_model()[1]
