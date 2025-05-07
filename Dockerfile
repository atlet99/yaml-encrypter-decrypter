FROM golang:1.24.3-alpine@sha256:ef18ee7117463ac1055f5a370ed18b8750f01589f13ea0b48642f5792b234044 AS builder

RUN apk --no-cache add build-base git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN VERSION_RAW=$(tail -n 1 .release-version 2>/dev/null || echo "dev") && \
    CGO_ENABLED=0 go build -ldflags="-X 'main.Version=${VERSION_RAW}'" -o yed ./cmd/yaml-encrypter-decrypter

# Final stage with scratch image
FROM scratch
COPY --from=builder /app/yed /yed
ENTRYPOINT ["/yed"]
CMD ["--version"]
