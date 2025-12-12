# agent.py
# OpenAI integration (Responses API, using max_output_tokens)
import os, json, logging
from typing import Dict, Any
from openai import OpenAI


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MOCK_OPENAI = os.getenv("MOCK_OPENAI", "false").lower() in ("1","true","yes")

def _mock_response_for(detection: dict) -> Dict[str, Any]:
    # Return a sensible, deterministic structured response for demo / offline use.
    evidence = detection.get("evidence", []) if isinstance(detection, dict) else []
    score = detection.get("score", 0.0) if isinstance(detection, dict) else 0.0
    # simple mapping
    summary = (f"Automated detector flagged this item as '{detection.get('verdict')}' "
               f"with score {score}. Key evidence: {', '.join(evidence) or 'none'}.")
    return {
        "model": "mock",
        "response": {
            "summary": summary,
            "evidence": evidence,
            "remediation": [
                "Isolate the link/email and do not click.",
                "Reset affected credentials and enable MFA if not present.",
                "Report the incident to security operations for investigation."
            ],
            "compliance": [
                {"standard": "ISO27001", "control_id": "A.9.2", "explanation": "Ensure account management and MFA are enforced."},
                {"standard": "NIST-CSF", "control_id": "PR.AT-1", "explanation": "User awareness training on phishing & social engineering."}
            ]
        }
    }


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise RuntimeError("Missing OPENAI_API_KEY environment variable")
client = OpenAI(api_key=OPENAI_API_KEY)

# Default model (change if you prefer)
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

def _try_parse_json_from_text(text: str):
    """Find first JSON object in text and parse it, otherwise return None."""
    if not text:
        return None
    start = text.find('{')
    if start == -1:
        return None
    # attempt to parse progressively to handle trailing text
    candidate = text[start:]
    try:
        return json.loads(candidate)
    except Exception:
        # try to find a balanced JSON substring by searching for the last closing brace
        end = candidate.rfind('}')
        if end != -1:
            try:
                return json.loads(candidate[:end+1])
            except Exception:
                return None
    return None

def explain_findings(detection: dict) -> dict:
    """
    Attempts to call OpenAI Responses API. On 429/quota or other failures,
    returns a helpful error message and (optionally) a mock response if MOCK_OPENAI is true.
    """
    if MOCK_OPENAI:
        logger.info("MOCK_OPENAI enabled — returning canned response")
        return _mock_response_for(detection)

    prompt = build_prompt(detection)

    try:
        # Note: use max_output_tokens for Responses API
        resp = client.responses.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            input=prompt,
            temperature=0.0,
            max_output_tokens=800
        )
        # Extract text (works with various SDK shapes)
        text = getattr(resp, "output_text", None) or ""
        if not text:
            parts = []
            for item in getattr(resp, "output", []) or []:
                if isinstance(item, dict):
                    for c in item.get("content", []) or []:
                        if isinstance(c, dict):
                            parts.append(c.get("text") or c.get("content") or "")
                        else:
                            parts.append(str(c))
                else:
                    parts.append(str(item))
            text = "\n".join(parts)

        # Try to parse JSON block
        idx = text.find("{")
        if idx != -1:
            try:
                parsed = json.loads(text[idx:])
                return {"model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"), "response": parsed}
            except Exception:
                # return raw text if parsing fails
                return {"model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"), "response": {"raw": text}}
        else:
            return {"model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"), "response": {"raw": text}}

    except Exception as e:
        # Inspect exception message for 429/quota, rate limit or auth errors
        msg = str(e)
        logger.exception("OpenAI call failed: %s", msg)

        if "429" in msg or "quota" in msg.lower() or "insufficient_quota" in msg.lower():
            err_text = ("OpenAI quota/exceeded or billing issue. "
                        "Please check your account usage/billing at https://platform.openai.com/account/usage")
            # If mock mode allowed, return mock and also inform user
            if MOCK_OPENAI:
                mock = _mock_response_for(detection)
                mock["note"] = "Returned mock response due to OpenAI quota error: " + err_text
                return mock
            return {"model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"), "error": err_text, "response": {"raw": ""}}

        # generic fallback: if other errors, optionally return mock or error
        if MOCK_OPENAI:
            mock = _mock_response_for(detection)
            mock["note"] = "Returned mock response due to OpenAI API error: " + msg
            return mock

        return {"model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"), "error": msg, "response": {"raw": ""}}
    