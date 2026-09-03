#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-policybridge:latest}"
PORT="${2:-8080}"

echo "Building container..."
podman build -t "$IMAGE" -f Containerfile .

echo "Starting container..."
CID=$(podman run -d -p "127.0.0.1:${PORT}:8080" -e POLICYBRIDGE_LISTEN_ADDR=0.0.0.0 "$IMAGE")
trap "podman rm -f $CID" EXIT

echo "Waiting for health check..."
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${PORT}/healthz" > /dev/null 2>&1; then
    echo "Health check passed"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "Health check failed"
    podman logs "$CID"
    exit 1
  fi
  sleep 1
done

echo "Testing about endpoint..."
ABOUT=$(curl -sf "http://127.0.0.1:${PORT}/api/v1/about")
echo "$ABOUT" | grep -q "vmware-analyzer" || { echo "About endpoint missing vmware-analyzer"; exit 1; }

echo "Testing session creation..."
SESSION=$(curl -sf -X POST "http://127.0.0.1:${PORT}/api/v1/sessions")
echo "$SESSION" | grep -q '"id"' || { echo "Session creation failed"; exit 1; }

echo "Testing frontend..."
curl -sf "http://127.0.0.1:${PORT}/" | grep -q "PolicyBridge" || { echo "Frontend not served"; exit 1; }

echo "All smoke tests passed"
