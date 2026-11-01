package rypt_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/x6c-co/rypt"
)

// Envelope encryption: a new data key for each record, wrapped by a rypt
// key. The data is encrypted locally, so it can be of any size, and only
// the 32-byte data key goes to the service.
func Example() {
	ctx := context.Background()
	client, err := rypt.NewClient(os.Getenv("RYPT_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	keyID := os.Getenv("RYPT_KEY_ID")
	record := []byte("customer-42") // binds the wrapped key to this record

	// Encrypt.
	dk, err := client.GenerateDataKey(ctx, keyID, record)
	if err != nil {
		log.Fatal(err)
	}
	block, err := aes.NewCipher(dk.Plaintext)
	clear(dk.Plaintext)
	if err != nil {
		log.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		log.Fatal(err)
	}
	sealed := aead.Seal(nonce, nonce, []byte("the secret data"), record)
	// Store dk.Wrapped and sealed together.

	// Decrypt.
	dek, err := client.Unwrap(ctx, keyID, dk.Wrapped, record)
	if err != nil {
		log.Fatal(err)
	}
	block, err = aes.NewCipher(dek)
	clear(dek)
	if err != nil {
		log.Fatal(err)
	}
	aead, err = cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}
	n := aead.NonceSize()
	plaintext, err := aead.Open(nil, sealed[:n], sealed[n:], record)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", plaintext)
}

func ExampleNewClient() {
	client, err := rypt.NewClient(os.Getenv("RYPT_TOKEN"),
		rypt.WithUserAgent("myapp/1.2.3"),
		rypt.WithMaxAttempts(5),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = client
}

func ExampleNewClient_localServer() {
	// Plain http is allowed only to 127.0.0.1 and [::1].
	client, err := rypt.NewClient(os.Getenv("RYPT_TOKEN"), rypt.WithBaseURL("http://127.0.0.1:8080"))
	if err != nil {
		log.Fatal(err)
	}
	_ = client
}

// Direct encryption of a small payload: the service encrypts it, and the
// ciphertext names the key version, so it decrypts after a rotation too.
func ExampleClient_Encrypt() {
	ctx := context.Background()
	client, err := rypt.NewClient(os.Getenv("RYPT_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	keyID := os.Getenv("RYPT_KEY_ID")
	aad := []byte("table=users;column=ssn")

	ciphertext, err := client.Encrypt(ctx, keyID, []byte("078-05-1120"), aad)
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := client.Decrypt(ctx, keyID, ciphertext, aad)
	if err != nil {
		log.Fatal(err)
	}
	defer clear(plaintext)
	fmt.Printf("%s\n", plaintext)
}

// After a rotation, move every ciphertext under the retired version to the
// new primary version before the retired one is destroyed.
func ExampleClient_RotateKey() {
	ctx := context.Background()
	client, err := rypt.NewClient(os.Getenv("RYPT_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	keyID := os.Getenv("RYPT_KEY_ID")
	var stored [][]byte // ciphertexts made by Encrypt or Rewrap

	key, err := client.RotateKey(ctx, keyID)
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range key.RetiringVersions {
		fmt.Printf("version %s is destroyed after %s\n", v.Version, v.DestroyAfter.Format(time.RFC3339))
	}
	for i, ct := range stored {
		if stored[i], err = client.Rewrap(ctx, keyID, ct, nil); err != nil {
			log.Fatal(err)
		}
	}
}

func ExampleIsCode() {
	ctx := context.Background()
	client, err := rypt.NewClient(os.Getenv("RYPT_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	_, err = client.Encrypt(ctx, os.Getenv("RYPT_KEY_ID"), []byte("data"), nil)
	switch {
	case err == nil:
	case rypt.IsCode(err, rypt.CodeKeyPendingDeletion):
		log.Fatal("the key is pending deletion; restore it to use it")
	case rypt.IsCode(err, rypt.CodeOpsCapReached):
		var e *rypt.Error
		errors.As(err, &e)
		log.Fatalf("the key's monthly cap of %d is reached until %s", e.Cap, e.ResetsAt)
	default:
		log.Fatal(err) // includes the API's request id, for support
	}
}

func ExampleError() {
	ctx := context.Background()
	client, err := rypt.NewClient(os.Getenv("RYPT_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	_, err = client.ListKeys(ctx)
	var e *rypt.Error
	if errors.As(err, &e) {
		switch e.Kind {
		case rypt.KindAPI:
			log.Printf("refused with %s (HTTP %d), request %s", e.Code, e.StatusCode, e.RequestID)
		case rypt.KindTransport:
			log.Printf("unreachable after %d attempts: %v", e.Attempts, e.Err)
		case rypt.KindResponse:
			log.Printf("unexpected response: %s", e.Message)
		}
	}
}

// Restrict an API token to one key and two actions, and lift its
// firewall. Fields left out of the params are not changed.
func ExampleClient_UpdateAPIToken() {
	ctx := context.Background()
	// Managing API tokens needs a console session's access token.
	client, err := rypt.NewClient(os.Getenv("RYPT_CONSOLE_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	token, err := client.UpdateAPIToken(ctx, "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d", &rypt.UpdateAPITokenParams{
		KeyIDs:         rypt.Set([]string{"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"}),
		AllowedActions: rypt.Set([]rypt.Action{rypt.ActionWrap, rypt.ActionUnwrap}),
		FirewallID:     rypt.Clear[string](),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token.AllowedActions, token.PermissionChainHead.Hash)
}

func ExampleClient_ListAuditEvents() {
	ctx := context.Background()
	client, err := rypt.NewClient(os.Getenv("RYPT_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	events, err := client.ListAuditEvents(ctx, os.Getenv("RYPT_KEY_ID"), &rypt.AuditEventsParams{
		Since: time.Now().Add(-24 * time.Hour),
		Limit: 1000,
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, ev := range events {
		fmt.Println(ev.Time.Format(time.RFC3339), ev.Op, ev.Result, ev.ErrorCode)
	}
}
