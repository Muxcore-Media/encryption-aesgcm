# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Encryption proto definition (`muxcore/encryption/v1/encryption.proto`) with gRPC service spec
- Generated Go code from encryption proto (messages + gRPC stubs)
- Full test suite: module info, encrypt/decrypt round-trip, key generation, lifecycle
- AES-256-GCM encrypt/decrypt with random nonce prepended to ciphertext
- Master key loading: `ENCRYPTION_MASTER_KEY` env var (hex) or auto-generate to `ENCRYPTION_KEY_FILE`
- Key rotation: returns standard "rotation not supported" error
- Production deployment: Dockerfile, docker-compose, systemd unit
- Contract declaration: `EncryptionProvider` with `MinCoreVersion: 0.4.0`
- Module declares capability `"encryption"`
