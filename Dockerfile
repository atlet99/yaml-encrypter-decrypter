FROM golang:1.23.2-alpine AS builder

RUN apk --no-cache add build-base git

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o yaml-encrypter-decrypter

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/yaml-encrypter-decrypter .

RUN chmod +x yaml-encrypter-decrypter

CMD ["./yaml-encrypter-decrypter", "--version"]