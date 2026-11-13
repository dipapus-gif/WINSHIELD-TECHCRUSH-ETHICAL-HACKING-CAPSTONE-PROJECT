#!/usr/bin/env python3
"""Train the optional WinShield ransomware classifier and write model.json.

The C# app (Services/ThreatClassifier.cs) loads a logistic-regression model from
%LOCALAPPDATA%\\WinShield\\model.json. This script produces that file using only the
Python standard library.

Features (per detection window, in this order) are the counts the detection engine
already tracks. The model sees log(1 + count) of each one:

    modified, renamed, extChanged, suspiciousExt, highEntropy, deleted, dirs, notes, honeypot

Training data
-------------
By default the script generates SYNTHETIC labelled windows: benign activity profiles
(editing documents, builds, git checkouts, backups, archive extraction) against
ransomware-like profiles (mass in-place rewrites with high entropy, mass rename to a
new extension, ransom-note drops). That is enough to demo and test the pipeline, but
a model trained only on synthetic data reflects the assumptions in this file, not
your machine. For a real deployment, export labelled windows to CSV and pass --csv:

    modified,renamed,extChanged,suspiciousExt,highEntropy,deleted,dirs,notes,honeypot,label
    4,0,0,0,0,0,1,0,0,0
    180,170,170,160,150,0,9,6,1,1

(label 1 = ransomware-like, 0 = benign). The rule engine stays in charge either way:
the model can add an alert but can never cancel one raised by a rule or a decoy file.

Usage
-----
    python train_model.py                       # synthetic data, writes the default model.json
    python train_model.py --csv windows.csv     # train on your own labelled windows
    python train_model.py --out model.json --seed 7 --samples 4000
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
import sys
from pathlib import Path

FEATURES = [
    "modified", "renamed", "extChanged", "suspiciousExt",
    "highEntropy", "deleted", "dirs", "notes", "honeypot",
]


def default_out_path() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    base = Path(local) if local else Path.home() / ".local" / "share"
    return base / "WinShield" / "model.json"


# --------------------------------------------------------------------------- data

def _ri(rng: random.Random, lo: int, hi: int) -> int:
    return rng.randint(lo, hi)


def synthetic_window(rng: random.Random, malicious: bool) -> dict[str, int]:
    """One synthetic detection window. Counts only; no file content is involved."""
    w = {name: 0 for name in FEATURES}

    if not malicious:
        kind = rng.choice(["editing", "build", "git", "backup", "extract", "idle", "sync"])
        if kind == "editing":
            w["modified"] = _ri(rng, 1, 15); w["dirs"] = _ri(rng, 1, 3)
            w["renamed"] = _ri(rng, 0, 2)
        elif kind == "build":
            w["modified"] = _ri(rng, 40, 400); w["dirs"] = _ri(rng, 4, 30)
            w["deleted"] = _ri(rng, 10, 150); w["renamed"] = _ri(rng, 0, 10)
        elif kind == "git":
            w["modified"] = _ri(rng, 60, 300); w["dirs"] = _ri(rng, 5, 40)
            w["deleted"] = _ri(rng, 5, 120)
        elif kind == "backup":
            w["modified"] = _ri(rng, 30, 300); w["renamed"] = _ri(rng, 10, 80)
            w["extChanged"] = _ri(rng, 0, 15); w["dirs"] = _ri(rng, 3, 20)
        elif kind == "extract":
            w["modified"] = _ri(rng, 100, 500); w["dirs"] = _ri(rng, 6, 40)
            w["highEntropy"] = _ri(rng, 0, 12)
        elif kind == "sync":
            w["modified"] = _ri(rng, 10, 120); w["renamed"] = _ri(rng, 5, 60)
            w["dirs"] = _ri(rng, 2, 12); w["extChanged"] = _ri(rng, 0, 6)
        else:
            w["modified"] = _ri(rng, 0, 4)
        # Rare benign oddities: one note-like file, a lone odd extension.
        if rng.random() < 0.04:
            w["notes"] = 1
        if rng.random() < 0.03:
            w["suspiciousExt"] = 1
        return w

    kind = rng.choice(["inplace", "rename", "mixed", "slow", "notes_first"])
    if kind == "inplace":      # rewrites content, keeps names
        w["modified"] = _ri(rng, 60, 400); w["highEntropy"] = _ri(rng, 40, 300)
        w["dirs"] = _ri(rng, 4, 30); w["notes"] = _ri(rng, 0, 6)
    elif kind == "rename":     # rewrite + new extension
        n = _ri(rng, 50, 350)
        w["modified"] = n; w["renamed"] = int(n * rng.uniform(0.7, 1.0))
        w["extChanged"] = int(n * rng.uniform(0.7, 1.0)); w["suspiciousExt"] = int(n * rng.uniform(0.3, 1.0))
        w["highEntropy"] = int(n * rng.uniform(0.5, 1.0)); w["dirs"] = _ri(rng, 3, 25)
        w["notes"] = _ri(rng, 1, 8)
    elif kind == "mixed":
        w["modified"] = _ri(rng, 40, 250); w["renamed"] = _ri(rng, 20, 200)
        w["extChanged"] = _ri(rng, 20, 200); w["highEntropy"] = _ri(rng, 20, 200)
        w["deleted"] = _ri(rng, 10, 100); w["dirs"] = _ri(rng, 4, 20); w["notes"] = _ri(rng, 0, 5)
    elif kind == "slow":       # low and slow, still clearly one-directional
        w["modified"] = _ri(rng, 25, 80); w["extChanged"] = _ri(rng, 15, 70)
        w["highEntropy"] = _ri(rng, 15, 70); w["suspiciousExt"] = _ri(rng, 5, 50)
        w["dirs"] = _ri(rng, 3, 10); w["notes"] = _ri(rng, 0, 3)
    else:                      # notes dropped across folders before much encryption
        w["notes"] = _ri(rng, 3, 15); w["dirs"] = _ri(rng, 3, 15)
        w["modified"] = _ri(rng, 10, 80); w["highEntropy"] = _ri(rng, 5, 60)
        w["suspiciousExt"] = _ri(rng, 0, 40)
    if rng.random() < 0.35:
        w["honeypot"] = 1
    return w


def make_synthetic(samples: int, seed: int) -> list[tuple[dict[str, int], int]]:
    rng = random.Random(seed)
    data = []
    for i in range(samples):
        malicious = i % 2 == 1
        data.append((synthetic_window(rng, malicious), 1 if malicious else 0))
    rng.shuffle(data)
    return data


def load_csv(path: Path) -> list[tuple[dict[str, int], int]]:
    rows = []
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        missing = [c for c in FEATURES + ["label"] if c not in (reader.fieldnames or [])]
        if missing:
            raise SystemExit(f"CSV is missing columns: {', '.join(missing)}")
        for line_no, row in enumerate(reader, start=2):
            try:
                label = int(row["label"])
                if label not in (0, 1):
                    raise ValueError("label must be 0 or 1")
                window = {name: max(0, int(float(row[name]))) for name in FEATURES}
            except (ValueError, TypeError) as exc:
                raise SystemExit(f"{path}:{line_no}: {exc}")
            rows.append((window, label))
    if not rows:
        raise SystemExit("CSV has no data rows")
    if len({label for _, label in rows}) < 2:
        raise SystemExit("CSV needs both benign (0) and ransomware-like (1) examples")
    return rows


# ------------------------------------------------------------------------- model

def vectorise(window: dict[str, int]) -> list[float]:
    # The C# classifier uses Math.Log(1 + x), so train on exactly the same transform.
    return [math.log1p(max(0, window[name])) for name in FEATURES]


def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def train(rows, epochs: int, lr: float, l2: float):
    xs = [vectorise(w) for w, _ in rows]
    ys = [label for _, label in rows]
    n, d = len(xs), len(FEATURES)
    weights = [0.0] * d
    bias = 0.0

    # Class weights keep a rare positive class from being ignored when training on real data.
    pos = sum(ys); neg = n - pos
    w_pos = n / (2.0 * pos); w_neg = n / (2.0 * neg)

    for _ in range(epochs):
        grad_w = [0.0] * d
        grad_b = 0.0
        for x, y in zip(xs, ys):
            p = sigmoid(bias + sum(wi * xi for wi, xi in zip(weights, x)))
            err = (p - y) * (w_pos if y else w_neg)
            for j in range(d):
                grad_w[j] += err * x[j]
            grad_b += err
        for j in range(d):
            weights[j] -= lr * (grad_w[j] / n + l2 * weights[j])
        bias -= lr * grad_b / n
    return bias, weights


def score(bias: float, weights: list[float], window: dict[str, int]) -> float:
    z = bias + sum(w * x for w, x in zip(weights, vectorise(window)))
    return 100.0 * sigmoid(z)


def evaluate(bias, weights, rows) -> dict[str, float]:
    tp = fp = tn = fn = 0
    for window, label in rows:
        pred = 1 if score(bias, weights, window) >= 50.0 else 0
        if pred and label: tp += 1
        elif pred and not label: fp += 1
        elif not pred and not label: tn += 1
        else: fn += 1
    total = tp + fp + tn + fn
    return {
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "n": total,
    }


# --------------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Train the optional WinShield ransomware classifier.")
    ap.add_argument("--csv", type=Path, help="labelled windows (columns: the 9 features + label)")
    ap.add_argument("--out", type=Path, default=default_out_path(), help="where to write model.json")
    ap.add_argument("--samples", type=int, default=3000, help="synthetic windows to generate (no --csv)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--epochs", type=int, default=600)
    ap.add_argument("--lr", type=float, default=0.3)
    ap.add_argument("--l2", type=float, default=0.001)
    args = ap.parse_args(argv)

    if args.csv:
        rows = load_csv(args.csv)
        source = f"{len(rows)} windows from {args.csv.name}"
    else:
        if args.samples < 200:
            raise SystemExit("--samples must be at least 200")
        rows = make_synthetic(args.samples, args.seed)
        source = f"{len(rows)} SYNTHETIC windows (seed {args.seed})"
        print("Note: training on synthetic data. Use --csv with real labelled windows for deployment.\n")

    rng = random.Random(args.seed)
    rng.shuffle(rows)
    cut = int(len(rows) * 0.8)
    train_rows, test_rows = rows[:cut], rows[cut:]

    bias, weights = train(train_rows, args.epochs, args.lr, args.l2)
    train_m = evaluate(bias, weights, train_rows)
    test_m = evaluate(bias, weights, test_rows)

    print(f"Trained on {len(train_rows)} windows, tested on {len(test_rows)} held-out windows")
    print(f"  held-out accuracy      {test_m['accuracy']:.3f}")
    print(f"  held-out precision     {test_m['precision']:.3f}")
    print(f"  held-out recall        {test_m['recall']:.3f}")
    print(f"  held-out false alarms  {test_m['false_positive_rate']:.3f}")
    print(f"  (training accuracy     {train_m['accuracy']:.3f})\n")

    examples = {
        "editing a few documents": {"modified": 6, "dirs": 1},
        "a large build": {"modified": 250, "deleted": 60, "dirs": 20},
        "mass rewrite + rename + notes": {"modified": 200, "renamed": 190, "extChanged": 190,
                                           "suspiciousExt": 150, "highEntropy": 170, "dirs": 10, "notes": 4},
    }
    for label, window in examples.items():
        full = {name: window.get(name, 0) for name in FEATURES}
        print(f"  score for {label:<32} {score(bias, weights, full):5.1f}/100")

    model = {
        "bias": bias,
        "weights": dict(zip(FEATURES, weights)),
        "trained_on": source,
        "held_out": {k: round(v, 4) if isinstance(v, float) else v for k, v in test_m.items()},
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(model, indent=2), encoding="utf-8")
    print(f"\nModel written to {args.out}")
    print("Restart WinShield (or reload the model in Settings) to use it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
