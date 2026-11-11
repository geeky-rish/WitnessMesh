# Build stage
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o witnessmesh ./cmd/witnessmesh

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache sqlite-libs ca-certificates

WORKDIR /app

COPY --from=builder /app/witnessmesh .
COPY --from=builder /app/configs ./configs

# Create data directory
RUN mkdir -p data

EXPOSE 8080 8081 8082 8083 8084

ENTRYPOINT ["./witnessmesh"]
CMD ["-mode", "demo"]