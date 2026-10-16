//go:build integration

package rypt_test

// The integration tests run against the live rypt API. They read
// RYPT_TOKEN and RYPT_KEY_ID from the environment and skip when either is
// unset; RYPT_API_URL, if set, selects another server. The token needs the
// read, encrypt, decrypt, wrap, unwrap and rewrap actions on the key. A run
// spends about ten operations on the key and changes nothing else. Run
// them with:
//
//	go test -tags integration -count=1 -run Integration ./...

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/x6c-co/rypt"
)

func liveClient(t *testing.T) (*rypt.Client, string) {
	t.Helper()
	token, keyID := os.Getenv("RYPT_TOKEN"), os.Getenv("RYPT_KEY_ID")
	if token == "" || keyID == "" {
		t.Skip("RYPT_TOKEN and RYPT_KEY_ID must be set to run integration tests")
	}
	opts := []rypt.Option{rypt.WithUserAgent("rypt-go-integration-test")}
	if u := os.Getenv("RYPT_API_URL"); u != "" {
		opts = append(opts, rypt.WithBaseURL(u))
	}
	c, err := rypt.NewClient(token, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c, keyID
}

func TestIntegrationHealth(t *testing.T) {
	c, _ := liveClient(t)
	if err := c.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationKeys(t *testing.T) {
	c, keyID := liveClient(t)
	key, err := c.GetKey(t.Context(), keyID)
	if err != nil {
		t.Fatal(err)
	}
	if key.ID != keyID || key.State != rypt.KeyActive || !slices.Contains(key.Versions, key.PrimaryVersion) {
		t.Errorf("unexpected key %+v", key)
	}
	keys, err := c.ListKeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(keys, func(k rypt.Key) bool { return k.ID == keyID }) {
		t.Error("ListKeys does not list the key")
	}
}

func TestIntegrationDirect(t *testing.T) {
	c, keyID := liveClient(t)
	ctx := t.Context()
	pt, aad := []byte("rypt-go integration test"), []byte("aad")

	ct, err := c.Encrypt(ctx, keyID, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := c.Rewrap(ctx, keyID, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	for _, ct := range [][]byte{ct, ct2} {
		got, err := c.Decrypt(ctx, keyID, ct, aad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("Decrypt = %q, want %q", got, pt)
		}
	}
	if _, err := c.Decrypt(ctx, keyID, ct, []byte("other aad")); !rypt.IsCode(err, rypt.CodeInvalidCiphertext) {
		t.Errorf("Decrypt with the wrong aad: %v, want invalid_ciphertext", err)
	}
}

func TestIntegrationEnvelope(t *testing.T) {
	c, keyID := liveClient(t)
	ctx := t.Context()

	dk, err := c.GenerateDataKey(ctx, keyID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(dk.Plaintext) != 32 || len(dk.Wrapped) == 0 {
		t.Fatalf("data key of %d bytes, wrapped %d bytes", len(dk.Plaintext), len(dk.Wrapped))
	}
	got, err := c.Unwrap(ctx, keyID, dk.Wrapped, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dk.Plaintext) {
		t.Error("Unwrap returned a different data key")
	}

	mine := make([]byte, 16)
	rand.Read(mine)
	wrapped, err := c.Wrap(ctx, keyID, mine, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err = c.Unwrap(ctx, keyID, wrapped, []byte("aad")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mine) {
		t.Error("Unwrap returned a different data key")
	}
}

func TestIntegrationErrors(t *testing.T) {
	c, _ := liveClient(t)
	_, err := c.GetKey(t.Context(), "00000000-0000-4000-8000-000000000000")
	if !rypt.IsCode(err, rypt.CodeNotFound) {
		t.Fatalf("GetKey of an unknown key: %v, want not_found", err)
	}
	var e *rypt.Error
	if !errors.As(err, &e) || e.RequestID == "" {
		t.Errorf("no request id in %v", err)
	}

	var opts []rypt.Option
	if u := os.Getenv("RYPT_API_URL"); u != "" {
		opts = append(opts, rypt.WithBaseURL(u))
	}
	bad, err := rypt.NewClient("ry_00000000_00000000000000000000000000000000", opts...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.ListKeys(t.Context()); !rypt.IsCode(err, rypt.CodeUnauthorized) {
		t.Errorf("a wrong token: %v, want unauthorized", err)
	}
}
