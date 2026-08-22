FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY ips.txt .
COPY templates ./templates
COPY static ./static

EXPOSE 6655

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "6655"]
