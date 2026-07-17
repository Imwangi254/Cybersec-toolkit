#!/usr/bin/env python3
"""
test_samples.py
---------------
Test harness for the scam detector.

Runs a labelled set of messages through analyse() and reports accuracy,
false positives (legit flagged as scam) and false negatives (scam missed).

The legitimate samples matter most: a detector that flags real M-Pesa and
bank messages is useless in practice. False positives are the true metric.

Run:
    python3 test_samples.py          # summary
    python3 test_samples.py -v       # show every case

Author: Peter (AH200 / Cybersec-toolkit)
"""

import argparse
from scam_detector import analyse

# label: "scam" messages SHOULD score MEDIUM or HIGH.
#        "legit" messages SHOULD score LOW.
SAMPLES = [
    # ---- SCAMS ----
    ("scam", "URGENT: Your M-Pesa account will be suspended within 24 hours. "
             "Confirm your PIN to reactivate. Safaricom customer care."),
    ("scam", "Congratulations! You have won KES 500,000 in the Safaricom promo. "
             "Send the OTP sent to your phone to claim your prize now."),
    ("scam", "Dear customer, your bank account is blocked. Reply with your "
             "password immediately to avoid deactivation."),
    ("scam", "Hello, money was sent to you by mistake. Please send your PIN so "
             "we can reverse the wrong transaction. Act now."),
    ("scam", "KRA final notice: verify your account within 2 hours or face "
             "penalties. Click http://bit.ly/kra-verify and enter your code."),
    ("scam", "Your SIM will be blocked. To upgrade from 4G to 5G, share the "
             "verification code we just sent you. Official telecom notice."),
    ("scam", "You have a pending refund. Provide your OTP to receive KES 12,000 "
             "immediately. Forward to everyone so they also benefit."),

    # ---- LEGITIMATE (must NOT be flagged) ----
    ("legit", "TIB4H5J7K9 Confirmed. You have received Ksh1,000.00 from JOHN "
              "DOE 0712345678 on 17/7/26 at 1:04 PM. New M-PESA balance is "
              "Ksh3,450.00."),
    ("legit", "Hi, are we still meeting for lunch at 1pm today? Let me know."),
    ("legit", "Your Equity Bank statement for June is ready. Log in to the app "
              "to view it. Do not share your PIN or password with anyone."),
    ("legit", "Reminder: your electricity token purchase was successful. "
              "Units: 45.2. Thank you for using KPLC."),
    ("legit", "The meeting has been moved to Thursday. Please update your "
              "calendar and share the new agenda with the team."),
    ("legit", "Congratulations on passing your exam! So proud of you. Let's "
              "celebrate this weekend."),
    ("legit", "Your order #4821 has shipped and will arrive within 3 days. "
              "Track it using the link in your account."),
]


def run(verbose=False):
    tp = tn = fp = fn = 0
    failures = []

    for label, msg in SAMPLES:
        result = analyse(msg)
        flagged = result["risk"] in ("MEDIUM", "HIGH")

        if label == "scam" and flagged:
            tp += 1; outcome = "OK  (scam caught)"
        elif label == "scam" and not flagged:
            fn += 1; outcome = "MISS (scam not caught)"; failures.append((label, msg, result))
        elif label == "legit" and not flagged:
            tn += 1; outcome = "OK  (legit passed)"
        else:  # legit and flagged
            fp += 1; outcome = "FALSE ALARM (legit flagged)"; failures.append((label, msg, result))

        if verbose:
            preview = msg[:55].replace("\n", " ")
            print(f"[{result['risk']:6}] score={result['score']:>2}  "
                  f"{outcome:28} :: {preview}...")

    total = len(SAMPLES)
    correct = tp + tn
    print("\n" + "-" * 55)
    print(f"Total samples     : {total}")
    print(f"Correct           : {correct}/{total} "
          f"({100*correct/total:.0f}%)")
    print(f"Scams caught      : {tp} (missed {fn})")
    print(f"Legit passed      : {tn} (false alarms {fp})")
    print("-" * 55)

    if failures:
        print("\nCases to review (tune weights/patterns for these):")
        for label, msg, result in failures:
            print(f"  [{label}] score={result['score']} :: {msg[:60]}...")
    else:
        print("\nAll samples classified correctly.")

    return fp, fn


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    run(verbose=args.verbose)
