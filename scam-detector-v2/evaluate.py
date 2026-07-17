#!/usr/bin/env python3
"""
evaluate.py
-----------
Corpus-driven evaluation for the scam detector.

Loads a labelled CSV (label,message) and reports precision, recall, F1 and a
confusion matrix -- the metrics that actually tell you whether the detector is
trustworthy on real data. Grow the corpus by pasting real messages into
samples.csv; no code change needed.

Why these metrics (and not just "accuracy"):
  * A single accuracy % hides HOW you fail. 90% accuracy with every failure
    being a flagged real bank text is a useless detector.
  * Precision = of the messages I flagged, how many were truly scams.
                Low precision -> annoying false alarms on legit messages.
  * Recall    = of the real scams, how many did I catch.
                Low recall -> dangerous misses.
  * F1        = harmonic mean; a single number that punishes lopsided results.

For a scam detector, watch PRECISION hardest: flagging real M-Pesa/bank
messages destroys user trust faster than missing the occasional scam.

Usage:
    python3 evaluate.py                     # uses samples.csv
    python3 evaluate.py -c my_corpus.csv    # custom corpus
    python3 evaluate.py -v                  # list every misclassified case
    python3 evaluate.py --errors-only       # only show the mistakes

CSV format:
    label,message
    scam,"URGENT: send your PIN ..."
    legit,"Your order has shipped ..."

Author: Peter (AH200 / Cybersec-toolkit)
"""

import argparse
import csv
import sys

from scam_detector import analyse

# We treat "scam" as the positive class.
POSITIVE = "scam"
NEGATIVE = "legit"


def load_corpus(path):
    """Read a label,message CSV. Returns list of (label, message)."""
    rows = []
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None or "label" not in reader.fieldnames \
                    or "message" not in reader.fieldnames:
                print(f"[!] {path} must have header: label,message", file=sys.stderr)
                sys.exit(2)
            for i, row in enumerate(reader, start=2):  # line 2 = first data row
                label = (row.get("label") or "").strip().lower()
                message = (row.get("message") or "").strip()
                if not message:
                    continue
                if label not in (POSITIVE, NEGATIVE):
                    print(f"[!] line {i}: unknown label {label!r} "
                          f"(expected {POSITIVE}/{NEGATIVE}) -- skipped",
                          file=sys.stderr)
                    continue
                rows.append((label, message))
    except OSError as e:
        print(f"[!] Could not read corpus: {e}", file=sys.stderr)
        sys.exit(2)
    if not rows:
        print(f"[!] No usable rows in {path}", file=sys.stderr)
        sys.exit(2)
    return rows


def evaluate(corpus, verbose=False, errors_only=False):
    tp = tn = fp = fn = 0
    errors = []
    cases = []

    for label, message in corpus:
        result = analyse(message)
        predicted = POSITIVE if result["risk"] in ("MEDIUM", "HIGH") else NEGATIVE

        if label == POSITIVE and predicted == POSITIVE:
            tp += 1; kind = "TP"
        elif label == NEGATIVE and predicted == NEGATIVE:
            tn += 1; kind = "TN"
        elif label == NEGATIVE and predicted == POSITIVE:
            fp += 1; kind = "FP"; errors.append(("FALSE ALARM", message, result))
        else:  # scam predicted legit
            fn += 1; kind = "MISS"; errors.append(("MISSED SCAM", message, result))

        cases.append((kind, label, predicted, result, message))

    # ---- metrics (guard against divide-by-zero) ----
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    accuracy = (tp + tn) / len(corpus)

    # ---- output ----
    if verbose and not errors_only:
        for kind, label, predicted, result, message in cases:
            flag = "   " if kind in ("TP", "TN") else ">> "
            print(f"{flag}[{kind:4}] score={result['score']:>2} "
                  f"true={label:5} pred={predicted:5} :: "
                  f"{message[:50].replace(chr(10), ' ')}...")
        print()

    print("Confusion matrix")
    print("                 predicted")
    print("                 scam   legit")
    print(f"  actual scam  |  {tp:<4}   {fn:<4}")
    print(f"  actual legit |  {fp:<4}   {tn:<4}")
    print()
    print(f"  Corpus size : {len(corpus)}")
    print(f"  Accuracy    : {accuracy:.1%}")
    print(f"  Precision   : {precision:.1%}   (of flagged, how many were real scams)")
    print(f"  Recall      : {recall:.1%}   (of real scams, how many caught)")
    print(f"  F1 score    : {f1:.1%}")

    if errors_only or (errors and not verbose):
        print("\nMisclassified cases (fix these):")
        if not errors:
            print("  none")
        for tag, message, result in errors:
            print(f"  [{tag}] score={result['score']} :: {message[:70]}...")
            for reason in result["explanation"]:
                print(f"        - {reason}")

    return {"precision": precision, "recall": recall, "f1": f1,
            "fp": fp, "fn": fn}


def main():
    ap = argparse.ArgumentParser(description="Evaluate the scam detector on a labelled corpus.")
    ap.add_argument("-c", "--corpus", default="samples.csv",
                    help="Path to label,message CSV (default: samples.csv)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="List every case, not just the summary")
    ap.add_argument("--errors-only", action="store_true",
                    help="Show only misclassified cases")
    args = ap.parse_args()

    corpus = load_corpus(args.corpus)
    evaluate(corpus, verbose=args.verbose, errors_only=args.errors_only)


if __name__ == "__main__":
    main()
