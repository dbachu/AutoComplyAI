# agent.py - OpenAI integration (attempt structured JSON parsing)
import os, json
from openai import OpenAI

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise RuntimeError("Missing OPENAI_API_KEY environment variable")
client = OpenAI(api_key=OPENAI_API_KEY)
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

def build_prompt(detection: dict) -> str:
    base = [
        "You are a security analyst assistant. I will give you the results of an automated phishing detector.",
        "Provide a short human-readable summary (2-4 sentences), key evidence lines, recommended remediation steps, and map the finding to common compliance controls (ISO 27001 / NIST CSF style).",
        "Return JSON with keys: summary (string), evidence (array of strings), remediation (array of strings), compliance (array of objects with keys: standard, control_id, explanation).",
        "",
        "Detector output:",
        json.dumps(detection, indent=2)
    ]
    return "\n".join(base)

def explain_findings(detection: dict) -> dict:
    prompt = build_prompt(detection)
    try:
        resp = client.responses.create(model=DEFAULT_MODEL, input=prompt, temperature=0.0, max_tokens=800)
        text = ""
        try:
            text = resp.output_text
        except Exception:
            parts = []
            for it in getattr(resp, "output", []) or []:
                if isinstance(it, dict):
                    for c in it.get("content", []) or []:
                        if isinstance(c, dict):
                            parts.append(c.get("text") or c.get("content") or "")
                        else:
                            parts.append(str(c))
                else:
                    parts.append(str(it))
            text = "\n".join(parts)
        idx = text.find('{')
        if idx != -1:
            parsed = json.loads(text[idx:])
            return {"model": DEFAULT_MODEL, "response": parsed}
        else:
            return {"model": DEFAULT_MODEL, "response": {"raw": text}}
    except Exception as e:
        return {"model": DEFAULT_MODEL, "error": str(e), "response": {"raw": ""}}
