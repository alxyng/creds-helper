FROM golang:1.25.1-alpine3.22 AS builder

WORKDIR /app
COPY cmd cmd
COPY vendor vendor
COPY go.mod go.sum ./
RUN ls -la
RUN go build -o creds-helper cmd/creds-helper/main.go

FROM alpine:3.22

WORKDIR /app
COPY --from=builder /app/creds-helper .
CMD ["./creds-helper"]
