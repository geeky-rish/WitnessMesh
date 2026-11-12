# Stage 1: Build React frontend
FROM node:22-alpine AS web-builder
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ ./
RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache gcc musl-dev sqlite-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o witnessmesh ./cmd/witnessmesh

# Stage 3: Runtime
FROM alpine:3.20
RUN apk add --no-cache sqlite-libs ca-certificates wget curl
WORKDIR /app
COPY --from=builder /app/witnessmesh .
COPY --from=builder /app/configs ./configs
COPY --from=web-builder /web/dist ./web/dist
RUN mkdir -p data
EXPOSE 8080 8081 8082 8083 8084
ENTRYPOINT ["./witnessmesh"]
CMD ["-mode", "demo"]
