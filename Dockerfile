FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /supplyscan-mcp ./cmd/supplyscan-mcp

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /supplyscan-mcp /usr/local/bin/
ENTRYPOINT ["supplyscan-mcp"]