# AutoComplyAI - Demo (MIT)

**AutoComplyAI: Adaptive Phishing Detection with
Built-In Incident Reporting**

A demoable Flask application that:
- Detects phishing (URL + email body heuristics + optional ML model)
- Uses OpenAI to explain findings and map to compliance items
- Produces a downloadable PDF compliance report from the UI
- Includes scripts to train a simple ML URL model (joblib)
- Includes Dockerfile for easy containerization
- MIT License

## Project Information
Deepika Kothamasu
PES2PGE24DS012
Project Guide: Mr. Mahesh Ramegowda

## Quick start (local)
1. Create venv and install:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. (Optional) Train the sample model:
   ```bash
   python models/train_model.py
   ```
3. Create a `.env` file with your OpenAI API key:
   ```bash
   OPENAI_API_KEY=sk-...
   OPENAI_MODEL=gpt-4o-mini
   PORT=5050
   FLASK_DEBUG=false
   ```
4. Run:
   ```bash
   python app.py
   ```
5. Open http://127.0.0.1:5050

## Docker quick start
```bash
docker build -t autocomplyai:latest .
docker run -e OPENAI_API_KEY="sk-..." -p 5050:5050 autocomplyai:latest
```

## Notes
- Do not send highly sensitive PII to public LLMs in production.
- This demo includes a "Generate PDF" button in the UI that returns a compliant PDF report.
