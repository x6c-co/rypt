// Command envelope encrypts a file with envelope encryption and decrypts it
// again: a new data key from rypt encrypts the file locally with
// AES-256-GCM, and only the data key's wrapped form is kept, next to the
// ciphertext.
//
// Usage:
//
//	export RYPT_TOKEN=ry_... RYPT_KEY_ID=...
//	go run ./examples/envelope FILE
//
// It writes FILE.sealed and FILE.wrapped, then decrypts them and checks the
// result. It spends two operations on the key.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/x6c-co/rypt"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) != 2 {
		log.Fatal("usage: envelope FILE")
	}
	path := os.Args[1]
	client, err := rypt.NewClient(os.Getenv("RYPT_TOKEN"), rypt.WithUserAgent("rypt-example-envelope"))
	if err != nil {
		log.Fatal(err)
	}
	keyID := os.Getenv("RYPT_KEY_ID")
	ctx := context.Background()

	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	// The file's name binds the wrapped key to it: a wrapped key copied to
	// another file does not unwrap there.
	aad := []byte("file=" + path)

	// Encrypt: one new data key per file.
	dk, err := client.GenerateDataKey(ctx, keyID, aad)
	if err != nil {
		log.Fatal(err)
	}
	sealed, err := seal(dk.Plaintext, data, aad)
	clear(dk.Plaintext)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path+".sealed", sealed, 0o600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path+".wrapped", dk.Wrapped, 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s.sealed and %s.wrapped\n", path, path)

	// Decrypt: recover the data key from its wrapped form.
	wrapped, err := os.ReadFile(path + ".wrapped")
	if err != nil {
		log.Fatal(err)
	}
	dek, err := client.Unwrap(ctx, keyID, wrapped, aad)
	if err != nil {
		log.Fatal(err)
	}
	opened, err := open(dek, sealed, aad)
	clear(dek)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(opened, data) {
		log.Fatal("the decrypted file differs from the original")
	}
	fmt.Println("decrypted and verified")
}

// seal encrypts data with AES-256-GCM under key, and returns the nonce
// followed by the ciphertext.
func seal(key, data, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, data, aad), nil
}

// open reverses seal.
func open(key, sealed, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	n := aead.NonceSize()
	if len(sealed) < n {
		return nil, fmt.Errorf("the sealed file is too short")
	}
	return aead.Open(nil, sealed[:n], sealed[n:], aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
