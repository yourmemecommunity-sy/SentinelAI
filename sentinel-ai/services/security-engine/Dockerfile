# Stage 1: fetch the tier-2 classifier, pinned to a Hugging Face commit and verified by SHA-256 (services/security-engine/fetch_classifier.sh).
FROM python:3.12-slim AS classifier
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY fetch_classifier.sh /fetch_classifier.sh
RUN sh /fetch_classifier.sh /models/injection-classifier

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY requirements.txt .
# pip is only needed to build the image: removing it drops every fixable finding of the Trivy scan from the runtime.
RUN pip install --no-cache-dir -r requirements.txt && pip uninstall -y pip
COPY --from=classifier /models /srv/models
COPY app ./app
RUN useradd --system --uid 10001 sentinel
USER sentinel
EXPOSE 8001
# SECURITY_ENGINE_WORKERS: one process per worker (each loads its own NER model and classifier: memory grows per worker).
# NER and the classifier are CPU-bound, so throughput scales with workers up to the number of cores (measured in
# docs/verification/12-ai-vs-ai.md).
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8001 --workers ${SECURITY_ENGINE_WORKERS:-1}"]
