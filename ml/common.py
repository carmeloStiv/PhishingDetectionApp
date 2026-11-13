"""Shared helpers for training and evaluation scripts."""
import csv
import gzip
from pathlib import Path

SPLITS = Path(__file__).parent / "splits"


def load_split(name: str) -> list[dict]:
    with gzip.open(SPLITS / f"{name}.csv.gz", "rt", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def binary_metrics(y_true, y_pred) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
    tn = sum(1 for t, p in zip(y_true, y_pred) if not t and not p)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {
        "n": tp + fp + fn + tn, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "accuracy": round((tp + tn) / max(tp + fp + fn + tn, 1), 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
        "false_negative_rate": round(fn / (fn + tp), 4) if fn + tp else None,
    }
