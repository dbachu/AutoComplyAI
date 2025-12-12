# reportgen.py - generate PDF report with project metadata
import os, json, uuid
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime

OUT_DIR = 'reports'
os.makedirs(OUT_DIR, exist_ok=True)

def _draw_wrapped(c, x, y, text, max_width=480, leading=12):
    words = text.split()
    line = ""
    for w in words:
        if c.stringWidth(line + " " + w) < max_width:
            if line:
                line += " " + w
            else:
                line = w
        else:
            c.drawString(x, y, line)
            y -= leading
            line = w
    if line:
        c.drawString(x, y, line)
        y -= leading
    return y

def make_pdf_report(payload: dict, project_title: str, author_info: str) -> str:
    fname = f"AutoComplyAI_report_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:6]}.pdf"
    out_path = os.path.join(OUT_DIR, fname)
    c = canvas.Canvas(out_path, pagesize=A4)
    width, height = A4
    margin = 50
    y = height - margin

    c.setFont('Helvetica-Bold', 16)
    c.drawString(margin, y, "AutoComplyAI — Phishing Detection Report")
    y -= 18
    c.setFont('Helvetica', 10)
    c.drawString(margin, y, f"Generated: {datetime.utcnow().isoformat()} UTC")
    y -= 16

    c.setFont('Helvetica-Bold', 12)
    c.drawString(margin, y, "Project:")
    y -= 14
    c.setFont('Helvetica', 11)
    for line in project_title.splitlines():
        c.drawString(margin+10, y, line)
        y -= 12
    y -= 6
    c.setFont('Helvetica-Bold', 12)
    c.drawString(margin, y, "Author / Guide:")
    y -= 14
    c.setFont('Helvetica', 11)
    for line in author_info.splitlines():
        c.drawString(margin+10, y, line)
        y -= 12
    y -= 10

    det = payload.get('detection', {})
    c.setFont('Helvetica-Bold', 12)
    c.drawString(margin, y, "Detection Summary")
    y -= 14
    c.setFont('Helvetica', 10)
    summary_lines = [
        f"Type: {det.get('type')}",
        f"Verdict: {det.get('verdict')}",
        f"Score: {det.get('score')}",
        f"Evidence: {', '.join(det.get('evidence', []))}"
    ]
    for line in summary_lines:
        c.drawString(margin+10, y, line)
        y -= 12
        if y < 120:
            c.showPage()
            y = height - margin

    y -= 6
    c.setFont('Helvetica-Bold', 12)
    c.drawString(margin, y, "AI Explanation & Compliance Mapping")
    y -= 14
    c.setFont('Helvetica', 10)
    ai = payload.get('openai', {}).get('response', {})
    try:
        if isinstance(ai, dict):
            if 'summary' in ai:
                c.drawString(margin+10, y, "Summary:")
                y -= 12
                y = _draw_wrapped(c, margin+20, y, ai.get('summary',''), max_width=480, leading=12)
                y -= 6
            if 'evidence' in ai:
                c.drawString(margin+10, y, "Key Evidence:")
                y -= 12
                for ev in ai.get('evidence', []):
                    y = _draw_wrapped(c, margin+20, y, "- " + ev, max_width=480, leading=12)
                    y -= 2
            if 'remediation' in ai:
                y -= 4
                c.drawString(margin+10, y, "Remediation:")
                y -= 12
                for r in ai.get('remediation', []):
                    y = _draw_wrapped(c, margin+20, y, "- " + r, max_width=480, leading=12)
                    y -= 2
            if 'compliance' in ai:
                y -= 4
                c.drawString(margin+10, y, "Compliance Mapping:")
                y -= 12
                for comp in ai.get('compliance', []):
                    text = f"{comp.get('standard')} {comp.get('control_id','')}: {comp.get('explanation','')}"
                    y = _draw_wrapped(c, margin+20, y, "- " + text, max_width=480, leading=12)
                    y -= 2
        else:
            y = _draw_wrapped(c, margin+10, y, str(ai), max_width=480, leading=12)
    except Exception as e:
        c.drawString(margin+10, y, "AI output could not be rendered: " + str(e))
        y -= 12

    c.showPage()
    c.save()
    return out_path
