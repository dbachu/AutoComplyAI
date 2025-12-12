FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
ENV FLASK_ENV=production
EXPOSE 5050
CMD ["gunicorn", "-b", "0.0.0.0:5050", "app:app", "--workers=1"]
