#!/usr/bin/env bash
# Starts REAL PostgreSQL and Redis inside WSL for local verification on machines without Docker.
# Development only: the credentials below are throwaway values for a loopback-only dev database.
#   wsl -u root -- bash /mnt/c/.../scripts/development/wsl-infra.sh start|stop|status
set -euo pipefail

PGVER="$(ls /etc/postgresql | head -1)"
PGDIR="/etc/postgresql/${PGVER}/main"
DB_USER="sentinel"
DB_PASS="sentinel_dev_password"
DB_NAME="sentinel"

configure() {
  # WSL2 forwards localhost from Windows, but only for sockets bound beyond loopback inside the VM.
  sed -i "s/^#\?listen_addresses.*/listen_addresses = '*'/" "${PGDIR}/postgresql.conf"
  if ! grep -q "sentinel-dev" "${PGDIR}/pg_hba.conf"; then
    echo "host all all 0.0.0.0/0 scram-sha-256 # sentinel-dev" >> "${PGDIR}/pg_hba.conf"
  fi
  sed -i "s/^bind .*/bind 0.0.0.0/" /etc/redis/redis.conf
  sed -i "s/^protected-mode yes/protected-mode no/" /etc/redis/redis.conf
}

start() {
  configure
  pg_ctlcluster "${PGVER}" main start 2>/dev/null || true
  service redis-server restart >/dev/null 2>&1 || redis-server /etc/redis/redis.conf --daemonize yes
  for _ in $(seq 1 30); do su postgres -c "pg_isready -q" && break; sleep 1; done

  if ! su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'\"" | grep -q 1; then
    su postgres -c "psql -c \"CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}' SUPERUSER\""
  fi
  if ! su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'\"" | grep -q 1; then
    su postgres -c "createdb -O ${DB_USER} ${DB_NAME}"
  fi
  status
}

stop() {
  pg_ctlcluster "${PGVER}" main stop 2>/dev/null || true
  service redis-server stop >/dev/null 2>&1 || true
  echo "stopped"
}

status() {
  echo "PG_VERSION=$(su postgres -c "psql -tAc 'SHOW server_version'" 2>/dev/null | tr -d ' ')"
  echo "PG_READY=$(su postgres -c 'pg_isready -q' && echo yes || echo no)"
  echo "REDIS=$(redis-cli ping 2>/dev/null || echo down)"
  echo "REDIS_VERSION=$(redis-cli info server 2>/dev/null | grep -m1 redis_version | tr -d '\r' | cut -d: -f2)"
}

# ClamAV over TCP so the document scanner can reach clamd the same way it would in production.
clamav() {
  local conf=/etc/clamav/clamd.conf
  grep -q "^TCPSocket" "${conf}" || echo "TCPSocket 3310" >> "${conf}"
  grep -q "^TCPAddr" "${conf}" || echo "TCPAddr 0.0.0.0" >> "${conf}"
  mkdir -p /run/clamav && chown clamav:clamav /run/clamav 2>/dev/null || true
  # clamav-daemon is socket-activated by systemd, which hands clamd only the Unix socket and makes it ignore TCPSocket
  # ("No tcp AF_INET SOCK_STREAM socket received from systemd"). Stop the units and run clamd standalone so TCP is honoured.
  systemctl stop clamav-daemon.socket clamav-daemon.service >/dev/null 2>&1 || true
  service clamav-daemon stop >/dev/null 2>&1 || true
  pkill -x clamd >/dev/null 2>&1 || true
  sleep 2
  rm -f /var/run/clamav/clamd.ctl /run/clamav/clamd.ctl
  setsid clamd --foreground=true >/var/log/clamav/clamd-standalone.log 2>&1 &
  # clamd loads its signature database on start; that takes a while on first run.
  for _ in $(seq 1 90); do
    if clamdscan --version >/dev/null 2>&1; then break; fi
    sleep 2
  done
  echo "CLAMD=$(clamdscan --version 2>&1 | head -1)"
  echo "TESSERACT=$(tesseract --version 2>&1 | head -1)"
}

case "${1:-status}" in
  start) start ;;
  clamav) clamav ;;
  stop) stop ;;
  status) status ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
