FROM golang:1.24.2-alpine AS builder

RUN apk --no-cache add build-base git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o yed ./cmd/yaml-encrypter-decrypter

# Final stage with scratch image
FROM scratch
COPY --from=builder /app/yed /yed
ENTRYPOINT ["/yed"]
CMD ["--version"]
