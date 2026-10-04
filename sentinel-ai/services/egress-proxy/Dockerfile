FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/* && pip uninstall -y pip
WORKDIR /srv
COPY proxy.py .
RUN useradd --system --uid 10001 sentinel
USER sentinel
EXPOSE 8899
CMD ["python", "proxy.py"]
