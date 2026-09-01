# Encryption AES-GCM

[![CI](https://git.zem.systems/muxcore/encryption-aesgcm/actions/workflows/ci.yml/badge.svg)](https://git.zem.systems/muxcore/encryption-aesgcm/actions)
[![Go Version](https://img.shields.io/badge/Go-1.26-blue)](https://go.dev/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

**AES-256-GCM envelope encryption provider for MuxCore.**

A MuxCore sidecar module that provides at-rest encryption using AES-256-GCM with a versioned on-disk keyring. Keys load from a keyring file at `ENCRYPTION_KEY_FILE` (auto-generated on first boot) or bootstrap from `ENCRYPTION_MASTER_KEY` (hex, persisted to disk when no JSON keyring exists). `RotateKey` adds a new active key while retaining historical keys for decrypt.

---

## How It Works

```
Module request ──→ encryption-aesgcm (gRPC) ──→ AES-256-GCM
```

### Key operations

- **Encrypt** — AES-256-GCM with the active key. Ciphertext is self-describing: `MXE1` magic + 4-byte big-endian key id + 12-byte nonce + GCM ciphertext/tag. Plaintext is capped at 16 MiB.
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

### Key precedence and backup

1. **JSON keyring on disk wins** — if `ENCRYPTION_KEY_FILE` contains a JSON keyring, that file is loaded and `ENCRYPTION_MASTER_KEY` is ignored. This keeps rotated keys across restarts.
2. **Env bootstrap** — when no JSON keyring exists, `ENCRYPTION_MASTER_KEY` bootstraps key id `0` and is **persisted** to `ENCRYPTION_KEY_FILE` so restarts do not depend on the env var.
3. **Auto-generate** — when neither a usable file nor env key is present, a new keyring is generated on first boot.

**Back up `ENCRYPTION_KEY_FILE`.** Losing the keyring file loses the ability to decrypt all ciphertext encrypted with those keys. There is no recovery path. For restore, stop the module, replace the JSON file (mode `0600`), and restart.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENCRYPTION_MASTER_KEY` | `` | Hex-encoded 32-byte (256-bit) key. Bootstraps and persists when no JSON keyring exists; ignored when a JSON keyring is on disk. |
| `ENCRYPTION_KEY_FILE` | `/var/lib/encryption-aesgcm/master.key` | Path to JSON keyring (or legacy hex). Auto-generated on first boot if neither env nor file exists. Admin `key_file` updates must point at an **existing** path. |
| `ENCRYPTION_GRPC_ADDR` | `127.0.0.1:9601` | Module EncryptionService gRPC listen address (loopback by default — no auth on Encrypt/Decrypt/RotateKey). |
| `MUXCORE_GRPC_ADDR` | `` | Core mesh gRPC address (required). Also `--muxcore-mesh-addr`. |
| `MUXCORE_MODULE_ID` | `encryption-aesgcm` | Module ID override. Also `--muxcore-module-id`. |
| `MUXCORE_INSECURE_DISABLE_TLS` | `` | Set to `true` to disable TLS to core (dev only). |

Admin settings expose read-only `active_key_id` / `key_count` and a `rotate_key` trigger (any non-empty value).

---

## Quick Start

```bash
# Build
make build

# Run with a generated keyring (requires core reachable)
export MUXCORE_GRPC_ADDR=localhost:9090
export MUXCORE_INSECURE_DISABLE_TLS=true
./encryption-aesgcm

# Run with a specific bootstrap key (persisted to ENCRYPTION_KEY_FILE)
export ENCRYPTION_MASTER_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
./encryption-aesgcm
```

---

## Deployment

### Docker

The distroless image runs as `nonroot`; mount a writable volume for the keyring.

```bash
make docker
docker run -d --restart=unless-stopped \
  -v encryption-aesgcm-keys:/var/lib/encryption-aesgcm \
  -e ENCRYPTION_KEY_FILE=/var/lib/encryption-aesgcm/master.key \
  -e ENCRYPTION_GRPC_ADDR=127.0.0.1:9601 \
  -e MUXCORE_GRPC_ADDR=core:9090 \
  -e MUXCORE_INSECURE_DISABLE_TLS=true \
  ghcr.io/muxcore-media/encryption-aesgcm:latest
```

### docker-compose

```bash
docker compose -f deploy/docker-compose.yml up
```

gRPC listens on loopback inside the container; port `9601` is not published to the host.

### systemd

`deploy/systemd/muxcore-module.service` sets `StateDirectory=encryption-aesgcm` so `/var/lib/encryption-aesgcm` exists under `ProtectSystem=strict`.

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

- Registers with capabilities: `"encryption"`, `"encryption.aesgcm"`, `"settings"`
- Declares contract `EncryptionProvider` (`MinCoreVersion: 0.4.0`)
- Uses stdlib `crypto/aes`, `crypto/cipher` (no external crypto dependencies)
- Exposes gRPC `EncryptionService` (`Encrypt` / `Decrypt` / `RotateKey` / `Available`)
- Supports key rotation with versioned ciphertext and legacy blob decrypt
- gRPC errors use standard codes (`InvalidArgument`, `FailedPrecondition`, `NotFound`)

---

## License

GPL-3.0
