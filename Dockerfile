FROM golang:1.26-alpine AS builder
COPY core/ /build/core/
COPY encryption-aesgcm/ /build/encryption-aesgcm/
WORKDIR /build/encryption-aesgcm
RUN go mod download
RUN CGO_ENABLED=0 go build -o /encryption-aesgcm ./cmd/module
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /encryption-aesgcm /
ENTRYPOINT ["/encryption-aesgcm"]
