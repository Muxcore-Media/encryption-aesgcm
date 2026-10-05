# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.7] - 2026-10-05

### Changed
- CI runs on GitHub-hosted runners from the umbrella template; retired-origin workflows removed.
- Dependencies resolve from published GitHub tags (no filesystem `replace`); requires core v0.6.0.

### Security

- Require mesh caller identity, module bearer token, or verified mTLS client certificate for `Encrypt` / `Decrypt` / `RotateKey` gRPC RPCs
- Default `ENCRYPTION_GRPC_ADDR` to loopback (`127.0.0.1:9601`) instead of all interfaces

### Added

- `internal/auth.go` unary interceptor and transport-level auth tests (anonymous, public caller, mesh `x-caller-id`, module token, mTLS client CN)
- `ENCRYPTION_MODULE_TOKEN` / `MUXCORE_MODULE_TOKEN` for authenticated callers without mesh metadata

### Changed

- CI and Release workflows run on `self-hosted` (no GitHub-hosted runners; release no longer checks out a sibling `core` tree)
- Dockerfile builds from published `core@v0.5.x` pins (no sibling `COPY core/`)

## [0.2.6] — 2026-08-10

### Changed

- Advertise `settings` capability for admin-ui Settings discovery

## [0.2.5] — 2026-08-10

### Added

- Expose `key_file` via RegisterSettings mesh

## [0.2.4] — 2026-08-10

### Fixed

- Sync Info()/muxcore.json version to **0.2.4**

## [0.2.3] — 2026-08-10

### Added

- `TestEncryptRotateRestartDecrypt`: ciphertext survives rotate + process restart; keyring file mode `0600`
- Versioned JSON keyring with active key id and historical keys
- `RotateKey`: generate new active key, persist ring `0600`, retain old keys for Decrypt
- Versioned ciphertext wire format (`MXE1` + key id + nonce + ct); legacy `[nonce][ct+tag]` still decrypts via key id `0`
- Tests: encrypt→rotate→decrypt old, dual-version decrypt, TrimSpace reload after generate

### Fixed

- Hex key file load now `TrimSpace`s so newline-terminated files reload after generate

### Changed

- Description / version reflect rotation support (no longer a static-key-only provider)

### Previously

- Sidecar module serving core `EncryptionService` gRPC API (`muxcore/encryption/v1`)
- AES-256-GCM encrypt/decrypt; master key from `ENCRYPTION_MASTER_KEY` or `ENCRYPTION_KEY_FILE`
- Production deployment: Dockerfile, docker-compose, systemd unit
- Contract declaration: `EncryptionProvider` with `MinCoreVersion: 0.4.0`
- Module declares capability `"encryption"`
