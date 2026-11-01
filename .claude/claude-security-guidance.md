# Security guidance for this repo

<!-- Created by /repo-setup. The security-guidance plugin feeds this file to its
     reviewers. /repo-setup never overwrites this file after creating it. -->

## What this repo is

- Type: library (Go client for the rypt API, encryption as a service in front of Google Cloud KMS)
- Languages: go
- Exposure: imported by other programs; it makes outbound HTTPS calls to https://api.rypt.dev (or a caller-chosen base URL) and listens on nothing

## Trust boundaries

- Untrusted input enters through: API responses (status, headers such as Retry-After, and JSON bodies, including server text copied into errors), and caller arguments to exported functions (ids interpolated into URL paths, base URL, HTTP client, plaintexts and data keys)
- Secrets come from: the caller, who passes an API token or console session token to `NewClient` and plaintexts and data keys as byte slices; the examples and integration tests read `RYPT_TOKEN` and `RYPT_KEY_ID` from the environment; never from the repo

## Rules

- Every query that touches tenant data filters by tenant ID.
- Every external input is validated before use in SQL, shell, file paths, or templates.
- Cryptography uses the standard library or a vetted library; no custom primitives.
- Errors returned to clients never include stack traces, SQL, or secrets.
- The token is sent only to the configured base URL over https (plain http only to the addresses 127.0.0.1 and ::1, never to a name such as localhost), and redirects are never followed.
- Server-supplied text in an error has control and format characters removed and any copy of the token redacted before it is kept.
- Plaintexts, data keys and request/response bodies that carry them stay byte slices, and the client clears its own copies when a call ends.

## Known exceptions

- The tenant-ID rule does not apply here: the library has no data store, and the API enforces tenancy through the token's container.
