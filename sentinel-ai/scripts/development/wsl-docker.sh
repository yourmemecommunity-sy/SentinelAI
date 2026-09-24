#!/usr/bin/env bash
# Docker Engine inside WSL2 Ubuntu - a real container runtime for machines without Docker Desktop.
#   wsl -u root -- bash scripts/development/wsl-docker.sh install|start|status|sync
#
# NOTE: do not combine with Docker Desktop's WSL integration for the same distro. If Docker Desktop is set up later:
#   apt purge docker.io docker-compose-v2 docker-buildx
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
WORK=/root/sentinel-ai          # builds run from the Linux filesystem; /mnt/c is far too slow for image builds

install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq docker.io docker-compose-v2 docker-buildx
  start
}

start() {
  systemctl enable --now docker >/dev/null 2>&1 || service docker start >/dev/null 2>&1 || (dockerd >/var/log/dockerd.log 2>&1 &)
  for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
  status
}

status() {
  echo "DOCKER_CLIENT=$(docker version --format '{{.Client.Version}}' 2>/dev/null || echo none)"
  echo "DOCKER_SERVER=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo down)"
  echo "COMPOSE=$(docker compose version --short 2>/dev/null || echo none)"
  echo "BUILDX=$(docker buildx version 2>/dev/null | cut -d' ' -f2 || echo none)"
  docker info --format 'CPUS={{.NCPU}} MEM_BYTES={{.MemTotal}} STORAGE={{.Driver}} CGROUP={{.CgroupVersion}}' 2>/dev/null || true
}

# Copy the repository onto the Linux filesystem, excluding everything a build must never see or would re-create.
sync() {
  mkdir -p "${WORK}"
  command -v rsync >/dev/null 2>&1 || apt-get install -y -qq rsync >/dev/null 2>&1
  rsync -a --delete \
    --exclude node_modules --exclude .next --exclude dist --exclude .venv --exclude __pycache__ \
    --exclude .pytest_cache --exclude '*.tsbuildinfo' --exclude .env \
    "${REPO}/" "${WORK}/"
  echo "SYNCED to ${WORK}"
}

case "${1:-status}" in
  install) install ;;
  start) start ;;
  status) status ;;
  sync) sync ;;
  *) echo "usage: $0 install|start|status|sync" >&2; exit 2 ;;
esac
