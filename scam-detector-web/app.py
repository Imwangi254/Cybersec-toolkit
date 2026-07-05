from flask import Flask, request
from engine import check_message

app = Flask(__name__)

PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>Scam Message Detector</title>
  <style>
    body {{ font-family: sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; }}
    h1 {{ color: #1a5276; }}
    textarea {{ width: 100%; height: 120px; padding: 10px; font-size: 16px; }}
    button {{ background: #1a5276; color: white; border: none; padding: 12px 24px;
             font-size: 16px; cursor: pointer; border-radius: 4px; margin-top: 10px; }}
    .verdict {{ padding: 15px; border-radius: 4px; margin-top: 20px; font-weight: bold; }}
    .high {{ background: #f8d7da; color: #721c24; }}
    .suspicious {{ background: #fff3cd; color: #856404; }}
    .low {{ background: #d4edda; color: #155724; }}
    .finding {{ margin: 5px 0; }}
    .note {{ color: #666; font-size: 14px; margin-top: 20px; }}
  </style>
</head>
<body>
  <h1>Scam Message Detector</h1>
  <p>Paste a suspicious SMS or message below to check if it's likely a scam.</p>
  <form method="post">
    <textarea name="message" placeholder="Paste the message here...">{message}</textarea>
    <br>
    <button type="submit">Check Message</button>
  </form>
  {result}
  <p class="note">This tool helps spot common scams but cannot catch every one.
  Never share your PIN. When unsure, call the person or company on a number you know.</p>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    message = ""
    if request.method == "POST":
        message = request.form.get("message", "")
        if message.strip():
            score, findings = check_message(message)
            findings_html = ""
            for f in findings:
                findings_html += f'<div class="finding">{f}</div>'
            if not findings:
                findings_html = '<div class="finding">No obvious scam signals detected.</div>'
            if score >= 5:
                verdict_class = "high"
                verdict = f"HIGH RISK - very likely a scam (score {score})"
            elif score >= 2:
                verdict_class = "suspicious"
                verdict = f"SUSPICIOUS - be careful (score {score})"
            else:
                verdict_class = "low"
                verdict = f"LOW RISK - but stay alert (score {score})"
            result = f'<div class="verdict {verdict_class}">{verdict}</div>{findings_html}'

    return PAGE.format(message=message, result=result)

if __name__ == "__main__":
    print("Starting Scam Detector web app...")
    print("Open your browser (inside Kali) to: http://127.0.0.1:5000")
    app.run(debug=True, host="127.0.0.1", port=5000)
