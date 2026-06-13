# Encryption AES-GCM

[![CI](https://github.com/Muxcore-Media/encryption-aesgcm/actions/workflows/ci.yml/badge.svg)](https://github.com/Muxcore-Media/encryption-aesgcm/actions)
[![Go Version](https://img.shields.io/badge/Go-1.26-blue)](https://go.dev/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

**AES-256-GCM envelope encryption provider for MuxCore.**

A MuxCore sidecar module that provides at-rest encryption using AES-256-GCM with a static master key. The master key is loaded from the `ENCRYPTION_MASTER_KEY` environment variable (hex-encoded 32 bytes) or auto-generated on first boot and persisted to `ENCRYPTION_KEY_FILE`.

---

## How It Works

```
Module request ──→ encryption-aesgcm (gRPC) ──→ AES-256-GCM
```

### Key operations

- **Encrypt** — Generates a random 12-byte nonce, encrypts plaintext with AES-256-GCM, prepends the nonce to the ciphertext. The output is a self-describing blob: `[12-byte nonce][GCM ciphertext + tag]`.
- **Decrypt** — Extracts the 12-byte nonce from the first N bytes, decrypts the remainder with AES-256-GCM.
- **RotateKey** — Not supported (static key provider). Returns an error.
- **Available** — Returns `true` if the master key has been loaded and the AEAD cipher is ready.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENCRYPTION_MASTER_KEY` | `` | Hex-encoded 32-byte (256-bit) master key. Takes precedence over key file. |
| `ENCRYPTION_KEY_FILE` | `/var/lib/encryption-aesgcm/master.key` | Path to file containing hex-encoded master key. Auto-generated on first boot if neither env var nor file exists. |
| `ENCRYPTION_GRPC_ADDR` | `:9601` | gRPC listen address |

---

## Quick Start

```bash
# Build
make build

# Run with a generated key
./encryption-aesgcm

# Run with a specific key
export ENCRYPTION_MASTER_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
./encryption-aesgcm
```

---

## Deployment

### Docker

```bash
make docker
docker run -d --restart=unless-stopped \
  -e ENCRYPTION_GRPC_ADDR=:9601 \
  -e MUXCORE_GRPC_ADDR=core:9090 \
  ghcr.io/muxcore-media/encryption-aesgcm:latest
```

### docker-compose

```bash
docker compose -f deploy/docker-compose.yml up
```

---

## Development

```bash
make dev      # run in dev mode
make test     # run tests
make lint     # golangci-lint
make fmt      # format code
```

---

## Implementation

- Registers with capability: `"encryption"`
- Implements `contracts.EncryptionProvider`
- Uses stdlib `crypto/aes`, `crypto/cipher` (no external crypto dependencies)
- Exposes gRPC `EncryptionService` for inter-module access

---

## License

GPL-3.0
