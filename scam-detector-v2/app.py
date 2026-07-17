#!/usr/bin/env python3
"""
app.py
------
Flask web front-end for the scam detector.

Wraps the existing engine (scam_detector.analyse) in a single-page web app so
a non-technical person can paste a suspicious SMS and get an explained verdict.
Adds NO detection logic of its own -- it's a distribution layer over the same
analyse() every other interface uses.

Run:
    pip install flask       # if not already installed
    python3 app.py
    # open http://127.0.0.1:5000

Author: Peter (AH200 / Cybersec-toolkit)
"""

from flask import Flask, request, jsonify, render_template
from scam_detector import analyse

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    """Analyse a message. Accepts JSON {message, sender} -> verdict JSON."""
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    sender = (data.get("sender") or "").strip()

    if not message:
        return jsonify({"error": "Please paste a message to check."}), 400

    result = analyse(message, sender=sender or None)

    # Split explanation into the layer it belongs to for nicer display.
    return jsonify({
        "risk": result["risk"],
        "score": result["score"],
        "verdict": result["verdict"],
        "signals": result.get("signals", {}),
        "reasons": result["explanation"],
    })


# Simple JSON health check, handy if you later deploy behind a proxy.
@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # host=127.0.0.1 keeps it local by default. Change to 0.0.0.0 only if you
    # intend to expose it on your network -- and add rate limiting first.
    app.run(host="127.0.0.1", port=5000, debug=False)
