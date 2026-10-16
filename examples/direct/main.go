// Command direct encrypts a short message with the rypt service and
// decrypts it again. Direct encryption suits values of up to 64 KiB, such
// as a column of a database row; for anything larger, see the envelope
// example.
//
// Usage:
//
//	export RYPT_TOKEN=ry_... RYPT_KEY_ID=...
//	go run ./examples/direct "a secret message"
//
// It spends two operations on the key.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/x6c-co/rypt"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) != 2 {
		log.Fatal(`usage: direct "MESSAGE"`)
	}
	client, err := rypt.NewClient(os.Getenv("RYPT_TOKEN"), rypt.WithUserAgent("rypt-example-direct"))
	if err != nil {
		log.Fatal(err)
	}
	keyID := os.Getenv("RYPT_KEY_ID")
	ctx := context.Background()

	// The aad is not secret, but decryption needs the same value: here it
	// says where the ciphertext is stored.
	aad := []byte("table=notes;column=body")

	ciphertext, err := client.Encrypt(ctx, keyID, []byte(os.Args[1]), aad)
	if err != nil {
		fail(err)
	}
	fmt.Println("ciphertext:", base64.StdEncoding.EncodeToString(ciphertext))

	plaintext, err := client.Decrypt(ctx, keyID, ciphertext, aad)
	if err != nil {
		fail(err)
	}
	fmt.Printf("plaintext:  %s\n", plaintext)
	clear(plaintext)
}

// fail explains the most common refusals before exiting.
func fail(err error) {
	switch {
	case rypt.IsCode(err, rypt.CodeActionNotAllowed):
		log.Fatal("this API token was not given the encrypt and decrypt actions: ", err)
	case rypt.IsCode(err, rypt.CodeNotFound):
		log.Fatal("RYPT_KEY_ID names no key this API token can see: ", err)
	case rypt.IsCode(err, rypt.CodeKeyPendingDeletion):
		log.Fatal("the key is pending deletion; restore it to use it: ", err)
	}
	var e *rypt.Error
	if errors.As(err, &e) && e.Kind == rypt.KindTransport {
		log.Fatal("cannot reach rypt; check the network: ", err)
	}
	log.Fatal(err)
}
