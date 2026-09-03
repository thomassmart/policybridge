# Multi-stage build for PolicyBridge
# Build: podman build -t policybridge:latest -f Containerfile .

ARG GO_VERSION=1.24
ARG NODE_VERSION=22
ARG VERSION=0.1.0

# --- Frontend ---
FROM node:${NODE_VERSION}-bookworm AS frontend
WORKDIR /src
COPY web/package.json web/package-lock.json ./web/
RUN cd web && npm ci
COPY web/ ./web/
RUN cd web && npm run build

# --- Backend ---
FROM golang:${GO_VERSION}-bookworm AS builder
ARG VERSION
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/cmd/policybridge/static ./cmd/policybridge/static
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/policybridge/policybridge/internal/version.Version=${VERSION}" \
    -o /policybridge ./cmd/policybridge

# --- Runtime ---
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /policybridge /policybridge

EXPOSE 8080

ENV POLICYBRIDGE_LISTEN_ADDR=0.0.0.0
ENV POLICYBRIDGE_LISTEN_PORT=8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/policybridge", "-healthcheck"]

USER nonroot:nonroot
ENTRYPOINT ["/policybridge"]
