# rypt

[![Go Reference](https://pkg.go.dev/badge/github.com/x6c-co/rypt.svg)](https://pkg.go.dev/github.com/x6c-co/rypt)
[![CI](https://github.com/x6c-co/rypt/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/x6c-co/rypt/actions/workflows/ci.yml)

The Go client for [rypt](https://rypt.dev), encryption as a service in front
of Google Cloud KMS. It covers the whole API: direct encryption, envelope
encryption, the key lifecycle, usage, the audit log, and the console's API
tokens, containers, firewalls and billing. It has no dependencies outside
the standard library.

```sh
go get github.com/x6c-co/rypt
```

## Example

Envelope encryption: rypt generates a data key and wraps it under your rypt
key; you encrypt locally with the data key and store the wrapped form beside
the data.

```go
client, err := rypt.NewClient(os.Getenv("RYPT_TOKEN"))
if err != nil {
	log.Fatal(err)
}

dk, err := client.GenerateDataKey(ctx, keyID, nil)
if err != nil {
	log.Fatal(err)
}
// Encrypt with dk.Plaintext, for example with AES-256-GCM, store
// dk.Wrapped with the ciphertext, and clear(dk.Plaintext).

dek, err := client.Unwrap(ctx, keyID, dk.Wrapped, nil)
// Decrypt with dek, then clear(dek).
```

Small values can be encrypted by the service directly:

```go
ciphertext, err := client.Encrypt(ctx, keyID, []byte("078-05-1120"), aad)
plaintext, err := client.Decrypt(ctx, keyID, ciphertext, aad)
```

Errors from the API carry its error code and request id:

```go
if rypt.IsCode(err, rypt.CodeKeyPendingDeletion) {
	// restore the key with client.RestoreKey
}
```

## Documentation

- [Package documentation](https://pkg.go.dev/github.com/x6c-co/rypt): every
  method, which credential it needs, and whether it is retried.
- [examples/](examples): runnable programs for
  [envelope encryption](examples/envelope/main.go),
  [direct encryption](examples/direct/main.go) and a
  [usage report](examples/usage/main.go).
- [rypt.dev/docs](https://rypt.dev/docs/): the service, its tiers and its
  API.

## Versioning

The module follows [semantic versioning](https://semver.org). Until v1.0.0,
a minor version may change the API; see [CHANGELOG.md](CHANGELOG.md). It
supports the Go version in [go.mod](go.mod) and later.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the branch workflow, the tests and
how releases are made.

## License

MIT. See [LICENSE](LICENSE).
