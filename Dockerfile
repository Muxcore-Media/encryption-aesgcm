FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod edit -dropreplace=github.com/Muxcore-Media/core \
    -dropreplace=github.com/Muxcore-Media/core/pkg/contracts \
    -dropreplace=github.com/Muxcore-Media/core/sdk/go/module
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /build/module ./cmd/module

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /build/module /
ENV ENCRYPTION_KEY_FILE=/var/lib/encryption-aesgcm/master.key
ENTRYPOINT ["/module"]
