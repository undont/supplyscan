FROM golang:1.26-alpine AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/seanhalberthal/supplyscan/internal/types.Version=${VERSION}" -o /supplyscan ./cmd/supplyscan

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /supplyscan /usr/local/bin/
ENTRYPOINT ["supplyscan"]