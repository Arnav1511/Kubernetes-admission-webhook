FROM golang:1.26.6-alpine AS builder

WORKDIR /app
RUN apk upgrade --no-cache
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /webhook ./cmd/webhook

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /webhook /webhook
# Numeric UID/GID (distroless 'nonroot'): a kubelet enforcing runAsNonRoot
# cannot verify a non-numeric username and will refuse to start the container.
USER 65532:65532
ENTRYPOINT ["/webhook"]
