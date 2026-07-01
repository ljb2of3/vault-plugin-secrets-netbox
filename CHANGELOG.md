# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.1] - 2026-06-30

### Fixed

- Token renewal no longer breaks the issued token on NetBox 3.6.0–4.0.9. On those
  versions, renewing a lease caused NetBox to regenerate the token's key
  server-side, so the token started returning `403 Invalid token` on its next use.
  The plugin now resends the existing key when renewing against an affected
  version, so renewed tokens keep working. NetBox 4.0.10 and newer were never
  affected. ([#42])

## [0.6.0] - 2026-06-29

### Added

- Renewable leases. Issued tokens can now be renewed: each renewal extends the
  NetBox token's expiry in step with the Vault lease (bounded by the role's
  `max_ttl`) instead of being fixed at issue time.

### Changed

- Release checksums are now signed with the Cosign v3 bundle format
  (`*_SHA256SUMS.sigstore.json`); update verification steps accordingly.
- Standardized path help text and corrected "NetBox" capitalization throughout.

## [0.5.1] - 2026-06-25

### Fixed

- The plugin now reports its real version again. A broken build-time version
  injection in 0.5.0 left the reported version empty.

## [0.5.0] - 2026-06-21

### Added

- Support for the reworked NetBox 4.5+ token API alongside 3.7–4.4. The plugin
  detects the server's contract via `/api/status/` and mints the correct token
  type: v1 (legacy 40-character key) or v2 (`nbt_` pepper/secret tokens, on
  servers that support them).

### Changed

- Roles no longer auto-select the token version. `version` now defaults to `1`
  explicitly; set `version=2` to request v2 tokens on a supported server.

### Removed

- `apply-ruleset.sh` helper script.

## [0.4.0] - 2026-06-16

First versioned, release-tooled build.

### Added

- The plugin self-reports its version (visible via `vault plugin list`),
  injected at build time.
- Automated releases via GoReleaser, publishing per-platform binaries, a
  SHA256SUMS checksum file, Cosign signatures, and SBOMs.
- MPL-2.0 license applied across the codebase.

### Security

- Hardened CI: all GitHub Actions are pinned by commit SHA, and `govulncheck`
  runs against every build.

## [0.3.0] - 2026-06-15

### Added

- `creds/<role>` endpoint. Reading it mints a v1 NetBox API token for the role,
  leased by Vault and deleted from NetBox when the lease expires or is revoked.

### Removed

- v2 token support, temporarily, to land a validated v1 mint/revoke flow first
  (v2 returned in 0.5.0).

## [0.2.0] - 2026-06-13

### Added

- Role management at `role/<name>`: create, read, update, delete, and list.
  Each role maps a Vault role to a NetBox username with its own settings, and
  multiple roles may point at the same user.
- Warnings surfaced when NetBox is unreachable or unconfigured while writing a
  role, so misconfiguration is visible before minting.

### Changed

- Renamed the `token_version` role field to `version`.

## [0.1.0] - 2026-06-10

### Added

- Initial release. Plugin scaffolding, the `config/` endpoint for the NetBox
  server URL and admin API token, and the NetBox API client.

[Unreleased]: https://github.com/ljb2of3/vault-plugin-secrets-netbox/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/ljb2of3/vault-plugin-secrets-netbox/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/ljb2of3/vault-plugin-secrets-netbox/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/ljb2of3/vault-plugin-secrets-netbox/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/ljb2of3/vault-plugin-secrets-netbox/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ljb2of3/vault-plugin-secrets-netbox/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ljb2of3/vault-plugin-secrets-netbox/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ljb2of3/vault-plugin-secrets-netbox/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ljb2of3/vault-plugin-secrets-netbox/releases/tag/v0.1.0
[#42]: https://github.com/ljb2of3/vault-plugin-secrets-netbox/issues/42
