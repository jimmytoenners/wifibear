# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-06-13

Maintenance and quality release. No changes to runtime behavior.

### Added
- Unit test suite for the `pkg/wifi` core: PMK derivation against the published
  IEEE 802.11i known-answer vectors, PTK canonical-ordering invariants, MIC
  round-trip verification, EAPOL key-frame parsing, 4-way-handshake message
  classification, and enum string formatting.
- CI now enforces `gofmt` formatting as a gate, and the release workflow runs
  the test suite before building artifacts.

### Changed
- Normalized the Go toolchain requirement to a consistent `go 1.25` across
  `go.mod`, CI, and the release workflow. CI now builds and tests on Go 1.25
  and 1.26 (previously the matrix listed 1.21–1.23 while the module silently
  required a newer toolchain).

### Fixed
- README now states the correct build requirement (Go 1.25+) and the correct
  clone URL (`github.com/jimmytoenners/wifibear`).
- Applied `gofmt` to all previously unformatted source files.

## [0.1.0] - 2026-02-27

Initial release.

### Added
- Single-binary WiFi security auditing tool with native, zero-dependency 802.11
  scanning, monitor-mode control, deauthentication, WPA handshake capture, and a
  parallel PBKDF2-SHA1 dictionary cracker.
- Optional integrations for PMKID (hcxdumptool/hashcat), WPS (reaver/bully), and
  WEP (aircrack-ng suite) attacks.
- Interactive Bubble Tea TUI, JSON results store, and `cracked` / `check` /
  `deps` subcommands.

[0.1.1]: https://github.com/jimmytoenners/wifibear/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jimmytoenners/wifibear/releases/tag/v0.1.0
