"""Train the URL lexical model (gradient-boosted trees on hand-built features).

Trains on the train split only. The validation split is used for model
selection and for choosing the score bands used by the engine; the test split
is never touched here (see ml/evaluate.py).
"""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score

from ml.common import load_split
from phishdetect.features import FEATURE_NAMES, extract_features
from phishdetect.urltools import parse_url

MODEL_DIR = Path(__file__).parent.parent / "phishdetect" / "models"


def featurise(rows):
    X = np.array([extract_features(parse_url(r["url"])) for r in rows])
    y = np.array([int(r["label"]) for r in rows])
    return X, y


def main() -> None:
    train, val = load_split("url_train"), load_split("url_val")
    t = time.time()
    Xtr, ytr = featurise(train)
    Xv, yv = featurise(val)
    print(f"features extracted in {time.time() - t:.0f}s")
    model = HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.08, max_leaf_nodes=31, l2_regularization=1.0, random_state=0
    )
    model.fit(Xtr, ytr)
    p = model.predict_proba(Xv)[:, 1]
    src = np.array([r["source"] for r in val])
    bands = {}
    for th in (0.5, 0.75, 0.9, 0.97):
        flagged = p >= th
        bands[str(th)] = {
            "recall": round(float(flagged[yv == 1].mean()), 4),
            "false_positive_rate": round(float(flagged[yv == 0].mean()), 4),
            "fpr_legit_pages_with_paths": round(float(flagged[src == "pdd_legit"].mean()), 4),
        }
    meta = {
        "model": "HistGradientBoostingClassifier",
        "sklearn_version": sklearn.__version__,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "features": FEATURE_NAMES,
        "n_train": len(train),
        "n_val": len(val),
        "val_roc_auc": round(float(roc_auc_score(yv, p)), 4),
        "val_bands": bands,
    }
    joblib.dump(model, MODEL_DIR / "url_model.joblib", compress=3)
    (MODEL_DIR / "url_model_meta.json").write_text(json.dumps(meta, indent=1))
    print(json.dumps(meta["val_bands"], indent=1), "AUC", meta["val_roc_auc"])


if __name__ == "__main__":
    main()
