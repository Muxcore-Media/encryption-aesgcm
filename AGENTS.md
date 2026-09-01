# AGENTS.md — encryption-aesgcm

MuxCore sidecar module (`encryption-aesgcm`). Workspace deploy and SSH: [`../AGENTS.md`](../AGENTS.md). Default ports: [`_mvp/PORTS.md`](../_mvp/PORTS.md).

## Module identity

| Field | Value |
|-------|-------|
| Directory | `encryption-aesgcm` |
| Capabilities | `encryption`, `encryption.aesgcm`, `settings` |
| Contracts | `EncryptionProvider` (`core/pkg/contracts`); gRPC `EncryptionService` |

## Agent rules

- Modules run as gRPC sidecars; capabilities are the security boundary.
- TLS required in production (`MUXCORE_INSECURE_DISABLE_TLS` is dev-only).
- Match existing Go patterns; run `gofmt` and package tests before finishing.
- Cross-module events: prefer `github.com/Muxcore-Media/contracts-media/events` over deprecated `core/pkg/contracts` aliases.
- Do not edit polluted workspace dumps (see `MASTER-ROADMAP.md` Appendix H).
- Default gRPC bind is loopback (`127.0.0.1:9601`); back up `ENCRYPTION_KEY_FILE`.

## Build

```bash
cd encryption-aesgcm
nix-shell -p go --run 'go test ./...'
```
