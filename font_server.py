"""
font_server.py — Font Finder backend (secure proxy), Gemini edition.

The Font Finder tab in index.html builds a detailed forensic-typography
prompt client-side (trait checklist, reference font list, detail level,
etc.). This server takes that image + prompt, sends it to Google's
Gemini API (which has a genuinely free tier — no credit card required)
using a server-side key, and returns Gemini's parsed JSON straight
through. The API key never touches the browser.

Uses the current `google-genai` SDK (the older `google-generativeai`
package is deprecated and no longer receives updates).

Endpoints:
  GET  /status              -> health check ({ok, configured, model})
  POST /find-font             -> { image: <dataURL or base64>, mime?: str,
                                    prompt: str }
                                  returns the model's parsed JSON array
                                  (array of font-match objects), unmodified.

Required env var:
  GOOGLE_API_KEY  — your own free Gemini API key from
                     https://aistudio.google.com/apikey
                     (never expose this in frontend JS; it must only
                     live server-side).

Run locally:
  pip install -r requirements.txt
  export GOOGLE_API_KEY=AIza...
  python font_server.py

Deploy on Render:
  Build Command: pip install -r requirements.txt
  Start Command: gunicorn font_server:app --bind 0.0.0.0:$PORT
  Environment Variable: GOOGLE_API_KEY = <your key>
"""

import os
import re
import json
import base64
import logging

from flask import Flask, request, jsonify
from flask_cors import CORS
from google import genai
from google.genai import types

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("font_server")

app = Flask(__name__)

# Lock this down to your actual deployed frontend origin once you know it,
# e.g. CORS(app, origins=["https://mockup-engine-2.onrender.com"])
CORS(app)

GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')
MODEL = "gemini-2.0-flash"
MAX_PROMPT_CHARS = 20000  # generous ceiling; the real prompt is a few KB

client = genai.Client(
    api_key=GOOGLE_API_KEY,
    http_options=types.HttpOptions(timeout=30000),  # 30s — fail fast instead of hanging
) if GOOGLE_API_KEY else None

DATA_URL_RE = re.compile(r"^data:(?P<mime>[\w/+.-]+);base64,(?P<data>.*)$", re.DOTALL)


def parse_image_field(image_field: str, mime_hint: str | None):
    """Accepts either a full data: URL or raw base64 and returns (mime, b64data)."""
    m = DATA_URL_RE.match(image_field or "")
    if m:
        return m.group("mime"), m.group("data")
    return (mime_hint or "image/png"), image_field


@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "ok": True,
        "configured": client is not None,
        "model": MODEL,
    })


@app.route("/find-font", methods=["POST"])
def find_font():
    if client is None:
        return jsonify({"error": "Server is missing GOOGLE_API_KEY"}), 500

    payload = request.get_json(silent=True) or {}
    image_field = payload.get("image")
    mime_hint = payload.get("mime")
    prompt = (payload.get("prompt") or "").strip()

    if not image_field:
        return jsonify({"error": "No image provided"}), 400
    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400
    if len(prompt) > MAX_PROMPT_CHARS:
        return jsonify({"error": "Prompt too long"}), 400

    mime, b64data = parse_image_field(image_field, mime_hint)
    if mime not in ("image/png", "image/jpeg", "image/jpg", "image/webp"):
        mime = "image/png"

    try:
        image_bytes = base64.b64decode(b64data)
    except Exception:
        return jsonify({"error": "Image data is not valid base64"}), 400

    try:
        response = client.models.generate_content(
            model=MODEL,
            contents=[
                types.Part.from_bytes(data=image_bytes, mime_type=mime),
                prompt,
            ],
            config=types.GenerateContentConfig(
                temperature=0.4,
                max_output_tokens=2000,
            ),
        )
    except Exception as e:
        log.exception("Gemini API call failed")
        return jsonify({"error": f"Font identification failed: {e}"}), 502

    raw_text = (getattr(response, "text", "") or "").strip()

    # Strip accidental markdown fences if the model adds them anyway
    cleaned = re.sub(r"^```(json)?|```$", "", raw_text, flags=re.MULTILINE).strip()

    try:
        parsed = json.loads(cleaned)
        if not isinstance(parsed, list):
            parsed = [parsed]
    except Exception:
        log.error("Could not parse model output as JSON: %s", raw_text)
        return jsonify({"error": "Could not parse font matches from model output"}), 502

    # Pass through as-is — the frontend already knows how to read this shape
    # (it built the prompt that asked for it) and enriches it locally against
    # its own FONT_REFERENCE_DB.
    return jsonify(parsed)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)