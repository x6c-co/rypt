// Package rypt is a client for the rypt API, encryption as a service in
// front of Google Cloud KMS.
//
// rypt offers two modes. Direct mode encrypts and decrypts payloads of up to
// 64 KiB with [Client.Encrypt] and [Client.Decrypt]. Envelope mode protects
// data keys: [Client.GenerateDataKey] returns a new data key together with
// its wrapped form, the caller encrypts its data locally with the data key
// and stores the wrapped form next to it, and [Client.Unwrap] recovers the
// data key later. [Client.Rewrap] moves a ciphertext to a key's current
// primary version after a rotation.
//
// # Authentication
//
// Every call except [Client.Health] sends the token given to [NewClient] as
// a bearer token. The API accepts two kinds:
//
//   - An API token, "ry_" followed by a prefix and a secret, issued from the
//     rypt console. It is the only credential the cryptographic operations
//     accept, and it is confined to one container and to the actions it was
//     given.
//   - A console session token, an Auth0 access token. It is the only
//     credential that may manage API tokens, containers, firewalls and
//     billing, or destroy a key at once.
//
// The key lifecycle, usage and the audit log accept either. Each method's
// documentation says which it needs; a call with the wrong kind fails with
// [CodeAPITokenRequired] or [CodeSessionRequired].
//
// # Errors
//
// A call that fails after reaching the network returns an [*Error]. Its
// [Error.Kind] says whether the API refused the request, could not be
// reached, or answered with a body that does not have the documented shape.
// When the API refused the request, [Error.Code] holds the API's stable
// error code, such as [CodeNotFound] or [CodeKeyPendingDeletion]; use
// [IsCode] to test for one. All text in an Error that came from the server
// has had control characters removed and any copy of the token redacted, so
// it is safe to print and log. Arguments the client can check without the
// network, such as an id that is not a UUID, fail with an error that is not
// an [*Error].
//
// # Retries
//
// A failed request is sent again, up to [DefaultMaxAttempts] times in all
// unless [WithMaxAttempts] says otherwise, when a retry cannot cause harm:
//
//   - Every request is retried after HTTP 503 with the code
//     [CodeUnavailable], which the API sends only for a request it did not
//     carry out, and after a failure to connect.
//   - Reads, and operations that are safe to repeat, are also retried after
//     a connection that failed part-way and after HTTP 502, 503 and 504.
//     These are the five cryptographic operations, the reads, and the
//     updates and deletions the API treats as idempotent. A retried
//     cryptographic operation may be counted as an operation each time.
//
// The rest — creating anything, rotating, restoring or destroying a key,
// deleting a container or firewall, and opening billing sessions — is never
// repeated after the request may have reached the API, because the first
// attempt may have succeeded. HTTP 429 is never retried: neither a monthly
// cap nor the rate limit clears in the time a retry waits. Each method's
// documentation says whether it is retried.
//
// # Secrets
//
// Plaintexts and data keys are passed and returned as byte slices so that
// the caller can zero them with the clear builtin when done. The client
// builds request bodies that carry them by hand, and clears its own copies
// of request and response bodies once a call is over. Go does not guarantee
// that no other copy survives in memory, so this reduces exposure rather
// than preventing it.
//
// The client refuses to follow redirects, so the token and request bodies
// are never sent to another URL, and it talks plain HTTP only to 127.0.0.1
// and ::1. See [WithBaseURL] and [WithHTTPClient].
//
// # API version
//
// This package is written against version 0.15.0 of the rypt OpenAPI
// description, a copy of which is in testdata/openapi.json. The API's own
// documentation is at https://rypt.dev/docs/.
package rypt
