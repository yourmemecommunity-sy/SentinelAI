FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Tesseract is the OCR engine (images -> text). Without it, image uploads are BLOCKED (fail closed), never guessed at.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY requirements.txt .
# pip is only needed to build the image: removing it drops every fixable finding of the Trivy scan from the runtime.
RUN pip install --no-cache-dir -r requirements.txt && pip uninstall -y pip
COPY app ./app
RUN useradd --system --uid 10001 sentinel
USER sentinel
EXPOSE 8003
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8003"]
