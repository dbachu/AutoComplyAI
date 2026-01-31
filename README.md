# AutoComplyAI

**AutoComplyAI: Adaptive Phishing Detection with Built-In Incident Reporting**

## Overview

AutoComplyAI is a Flask-based demo that analyzes URLs and email bodies for phishing indicators, explains findings using OpenAI (with mock fallback), and generates PDF incident reports. This repository is prepared for academic submission and demoing, and includes diagrams, a full project report, and CI workflows for testing and deployment.

## Quick links
- Project demo (local): `python app.py`
- Docs / GitHub Pages: site served from `docs/` (deploy via GitHub Pages)
- Full project report: `docs/reports/AutoComplyAI_Full_Project_Report.pdf`
- Presentation: `docs/ppt/AutoComplyAI_Presentation.pptx`

## How to run locally

1. Create venv & install deps:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Copy `.env.example` to `.env` and add your OpenAI API key (or enable mock mode):
```bash
cp .env.example .env
# edit .env and set OPENAI_API_KEY, or set MOCK_OPENAI=true for offline demo
```

3. Run the app:
```bash
    python app.py
```

4. Open http://127.0.0.1:5050

## Repo structure (enhanced)
```
AutoComplyAI/
├─ app.py
├─ detector.py
├─ agent.py
├─ models/
├─ templates/
├─ static/
├─ docs/                # Documentation & GitHub Pages site
│  ├─ diagrams/
│  ├─ reports/
│  └─ ppt/
└─ .github/workflows/   # CI/CD workflows
```

## CI / CD

This repo includes GitHub Actions workflows:
- `ci.yml` — runs unit tests and linters on push/PR.
- `docker-build.yml` — builds a Docker image and publishes (if configured).
- `pages.yml` — deploys `docs/` to GitHub Pages using `peaceiris/actions-gh-pages`.

## Contributing / Citation

If you use this project as a base, please cite the integrated methods and the base paper used for model improvements in your report.

---
Generated assets and workflows are included in this package for easy integration. 


