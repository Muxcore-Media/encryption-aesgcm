# Changelog


## [0.2.6] — 2026-08-10

### Changed

- Advertise `settings` capability for admin-ui Settings discovery

## [0.2.4] — 2026-08-10

### Fixed
- Sync Info()/muxcore.json version to **0.2.4**.

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.3] — 2026-08-10

### Added

- `TestEncryptRotateRestartDecrypt`: ciphertext survives rotate + process restart; keyring file mode `0600`


### Added

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
