# Scam Detector - Web App

A Flask web interface for the scam message detector. A user opens a web page,
pastes a suspicious SMS, and gets an instant colour-coded verdict - no terminal.

## Architecture
- engine.py: the detection logic (unchanged from the CLI tool).
- app.py: the Flask web layer that serves a form and displays the verdict.

## Setup and run
    pip install flask --break-system-packages
    python3 app.py
Then open http://127.0.0.1:5000 in a browser (leave the server running).

## Roadmap to WhatsApp
1. CLI tool (done)  2. Web app (this)  3. Host on a server  4. WhatsApp bot

## Note
Flask dev server is for local testing only. Brand names referenced only
to help users identify impersonation.
