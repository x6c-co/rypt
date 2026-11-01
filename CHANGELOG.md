# Changelog

All notable changes to this module are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the module
follows [semantic versioning](https://semver.org).

## Unreleased

### Changed

- **Breaking:** `WithBaseURL` allows plain `http` only for the addresses
  `127.0.0.1` and `::1`, and no longer for the name `localhost`. A name is
  looked up, and the lookup can reach DNS when the hosts file does not list
  `localhost`, or when DNS comes first in the lookup order. The resolver
  then asks for `localhost.<search domain>` first, so whoever controls that
  zone can answer with another machine, which would receive the token in
  clear text. Use `http://127.0.0.1` or `http://[::1]` for a local server,
  or `https://localhost`.

## v0.1.0

The first release, written against version 0.15.0 of the rypt API.

- `Client` with every client-facing operation: direct encryption (`Encrypt`,
  `Decrypt`, `Rewrap`), envelope encryption (`GenerateDataKey`, `Wrap`,
  `Unwrap`), the key lifecycle, the audit log, usage, API tokens,
  containers, firewalls, billing, `Me` and `Health`.
- `Error` with the API's error codes as `ErrorCode` constants, and `IsCode`.
- Retries that depend on whether an operation is safe to repeat.
- `Patch`, `Set` and `Clear` for update fields that can be left as they are,
  replaced or cleared.
