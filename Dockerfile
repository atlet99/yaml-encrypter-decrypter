FROM golang:1.24.2-alpine@sha256:7772cb5322baa875edd74705556d08f0eeca7b9c4b5367754ce3f2f00041ccee AS builder

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
