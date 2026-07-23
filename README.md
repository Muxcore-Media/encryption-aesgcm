# Encryption AES-GCM

[![CI](https://github.com/Muxcore-Media/encryption-aesgcm/actions/workflows/ci.yml/badge.svg)](https://github.com/Muxcore-Media/encryption-aesgcm/actions)
[![Go Version](https://img.shields.io/badge/Go-1.26-blue)](https://go.dev/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

**AES-256-GCM envelope encryption provider for MuxCore.**

A MuxCore sidecar module that provides at-rest encryption using AES-256-GCM with a versioned on-disk keyring. Keys load from `ENCRYPTION_MASTER_KEY` (hex) or a keyring file at `ENCRYPTION_KEY_FILE` (auto-generated on first boot). `RotateKey` adds a new active key while retaining historical keys for decrypt.

---

## How It Works

```
Module request ──→ encryption-aesgcm (gRPC) ──→ AES-256-GCM
```

### Key operations

- **Encrypt** — AES-256-GCM with the active key. Ciphertext is self-describing: `MXE1` magic + 4-byte big-endian key id + 12-byte nonce + GCM ciphertext/tag.
- **Decrypt** — Reads the versioned prefix and selects the matching key from the ring. Legacy unversioned blobs (`[nonce][ct+tag]`) decrypt with key id `0`.
- **RotateKey** — Generates a new AES-256 key, makes it active, persists the full ring (`0600`). Old keys remain available for Decrypt indefinitely.
- **Available** — Returns `true` when the keyring is loaded and the active key is present.

### Keyring file

JSON (mode `0600`):

```json
{
  "version": 1,
  "active": 1,
  "keys": {
    "0": "<64 hex chars>",
    "1": "<64 hex chars>"
  }
}
```

Legacy single-line hex files (with or without trailing newline) still load as key id `0`. First boot and rotation rewrite the file as a JSON keyring.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENCRYPTION_MASTER_KEY` | `` | Hex-encoded 32-byte (256-bit) key. Bootstraps a single-key ring (id `0`) when no JSON keyring file exists; overrides a legacy hex file. |
| `ENCRYPTION_KEY_FILE` | `/var/lib/encryption-aesgcm/master.key` | Path to JSON keyring (or legacy hex). Auto-generated on first boot if neither env nor file exists. A JSON keyring on disk is preferred over `ENCRYPTION_MASTER_KEY` so rotated keys survive restart. |
| `ENCRYPTION_GRPC_ADDR` | `:9601` | Module EncryptionService gRPC listen address |
| `MUXCORE_GRPC_ADDR` | `` | Core mesh gRPC address (required). Also `--muxcore-mesh-addr`. |
| `MUXCORE_MODULE_ID` | `encryption-aesgcm` | Module ID override. Also `--muxcore-module-id`. |
| `MUXCORE_INSECURE_DISABLE_TLS` | `` | Set to `true` to disable TLS to core (dev only). |

---

## Quick Start

```bash
# Build
make build

# Run with a generated keyring (requires core reachable)
export MUXCORE_GRPC_ADDR=localhost:9090
export MUXCORE_INSECURE_DISABLE_TLS=true
./encryption-aesgcm

# Run with a specific bootstrap key
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
  -e MUXCORE_INSECURE_DISABLE_TLS=true \
  ghcr.io/muxcore-media/encryption-aesgcm:latest
```

### docker-compose

```bash
docker compose -f deploy/docker-compose.yml up
```

---

## Development

```bash
make test     # run tests
make lint     # golangci-lint
make fmt      # format code
make ci       # lint + test + build
```

---

## Implementation

- Registers with capabilities: `"encryption"`, `"encryption.aesgcm"`
- Declares contract `EncryptionProvider` (`MinCoreVersion: 0.4.0`)
- Uses stdlib `crypto/aes`, `crypto/cipher` (no external crypto dependencies)
- Exposes gRPC `EncryptionService` (`Encrypt` / `Decrypt` / `RotateKey` / `Available`)
- Supports key rotation with versioned ciphertext and legacy blob decrypt

---

## License

GPL-3.0
