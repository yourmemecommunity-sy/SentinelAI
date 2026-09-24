FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY requirements.txt .
# pip is only needed to build the image: removing it drops every fixable finding of the Trivy scan from the runtime.
RUN pip install --no-cache-dir -r requirements.txt && pip uninstall -y pip
COPY app ./app
RUN useradd --system --uid 10001 sentinel
USER sentinel
EXPOSE 8004
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8004"]
