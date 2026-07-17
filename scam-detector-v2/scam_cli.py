#!/usr/bin/env python3
"""
scam_cli.py
-----------
Command-line front-end for the scam detector.

Examples:
    # analyse a message directly
    python3 scam_cli.py -m "You won a prize! Click http://bit.ly/x to claim"

    # analyse a message from a file
    python3 scam_cli.py -f message.txt

    # analyse from a pipe / stdin
    echo "Send your OTP to confirm" | python3 scam_cli.py

    # JSON output (for chaining into other tools)
    python3 scam_cli.py -m "..." --json

Author: Peter (AH200 / Cybersec-toolkit)
"""

import argparse
import json
import sys

from scam_detector import analyse, format_report


def main():
    parser = argparse.ArgumentParser(
        description="Detect social-engineering scam messages (Kenya-tuned)."
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("-m", "--message", help="Message text to analyse")
    src.add_argument("-f", "--file", help="Path to a file containing the message")
    parser.add_argument("--json", action="store_true",
                        help="Output raw JSON instead of a formatted report")
    args = parser.parse_args()

    # Resolve the message source: -m, -f, or stdin.
    if args.message:
        message = args.message
    elif args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                message = fh.read()
        except OSError as e:
            print(f"[!] Could not read file: {e}", file=sys.stderr)
            sys.exit(2)
    elif not sys.stdin.isatty():
        message = sys.stdin.read()
    else:
        parser.error("Provide a message with -m, -f, or via stdin.")

    result = analyse(message)

    if args.json:
        print(json.dumps({"message": message, **result}, indent=2))
    else:
        print(format_report(message, result))

    # Exit code doubles as a signal for scripts: 0 low, 1 medium, 2 high.
    sys.exit({"LOW": 0, "MEDIUM": 1, "HIGH": 2}[result["risk"]])


if __name__ == "__main__":
    main()
