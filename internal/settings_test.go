package internal

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	encryptionv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/encryption/v1"
)

func TestSettingsKeyFileReload(t *testing.T) {
	dir := t.TempDir()
	key1 := filepath.Join(dir, "a.key")
	key2 := filepath.Join(dir, "b.key")
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	if err := os.WriteFile(key1, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw2 := make([]byte, 32)
	for i := range raw2 {
		raw2[i] = byte(i + 40)
	}
	if err := os.WriteFile(key2, []byte(hex.EncodeToString(raw2)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewModule(Config{KeyFile: key1, GRPCAddr: "127.0.0.1:0"})
	if err := m.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop(t.Context())

	enc, err := m.Encrypt(t.Context(), &encryptionv1.EncryptRequest{Plaintext: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSetting("key_file", key2); err != nil {
		t.Fatal(err)
	}
	if got := m.Settings()[0].Value; got != key2 {
		t.Fatalf("key_file=%q", got)
	}
	// Old ciphertext may not decrypt under the new single-key legacy ring.
	if _, err := m.Decrypt(t.Context(), &encryptionv1.DecryptRequest{Ciphertext: enc.GetCiphertext()}); err == nil {
		t.Fatal("expected decrypt failure after switching legacy key file")
	}
	enc2, err := m.Encrypt(t.Context(), &encryptionv1.EncryptRequest{Plaintext: []byte("world")})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := m.Decrypt(t.Context(), &encryptionv1.DecryptRequest{Ciphertext: enc2.GetCiphertext()})
	if err != nil {
		t.Fatal(err)
	}
	if string(dec.GetPlaintext()) != "world" {
		t.Fatalf("got %q", dec.GetPlaintext())
	}
}
