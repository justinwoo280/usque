FROM golang:1.26.10-alpine AS builder

ENV GOTOOLCHAIN=local

WORKDIR /app

COPY go.mod .
COPY go.sum .
COPY connect-ip/go.mod connect-ip/go.sum ./connect-ip/

RUN go mod download

COPY . .

RUN go build -o usque -ldflags="-s -w" .

# scratch won't be enough, because we need a cert store
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/usque /bin/usque

ENTRYPOINT ["/bin/usque"]
