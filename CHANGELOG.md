# Changelog

All notable changes to this module are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the module
follows [semantic versioning](https://semver.org).

## Unreleased

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
