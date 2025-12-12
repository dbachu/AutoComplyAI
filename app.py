# app.py - AutoComplyAI demo server
import os
from dotenv import load_dotenv
load_dotenv()  # ensure .env is loaded before importing modules that depend on env vars

from flask import Flask, render_template, request, send_file, jsonify, redirect, url_for
from detector import analyze_email, analyze_url
from agent import explain_findings
from reportgen import make_pdf_report

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

PROJECT_TITLE = "AutoComplyAI: Adaptive Phishing Detection with\nBuilt-In Incident Reporting"
AUTHOR_INFO = "Deepika Kothamasu\nPES2PGE24DS012\nProject Guide: Mr. Mahesh Ramegowda"

@app.route('/')
def index():
    return render_template('index.html', project_title=PROJECT_TITLE, author_info=AUTHOR_INFO)

@app.route('/scan', methods=['POST'])
def scan():
    data_type = request.form.get('type') or (request.json and request.json.get('type'))
    content = request.form.get('content') or (request.json and request.json.get('content',''))
    if not content:
        return jsonify({'error': 'No content provided'}), 400

    if data_type == 'url':
        detection = analyze_url(content)
    else:
        detection = analyze_email(content)

    openai_result = explain_findings(detection)
    return jsonify({'detection': detection, 'openai': openai_result})

@app.route('/report', methods=['POST'])
def report():
    payload = request.get_json()
    if not payload or 'detection' not in payload or 'openai' not in payload:
        return jsonify({'error': 'Expected JSON with detection and openai keys.'}), 400
    pdf_path = make_pdf_report(payload, project_title=PROJECT_TITLE, author_info=AUTHOR_INFO)
    return send_file(pdf_path, as_attachment=True, download_name='AutoComplyAI_report.pdf')

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5050))
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
