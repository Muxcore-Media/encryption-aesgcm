package internal

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Muxcore-Media/core/pkg/contracts"
	encryptionv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/encryption/v1"
)

func settingValue(t *testing.T, defs []contracts.SettingDef, key string) string {
	t.Helper()
	for _, d := range defs {
		if d.Key == key {
			return d.Value
		}
	}
	t.Fatalf("setting %q not found", key)
	return ""
}

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
	defer func() { _ = m.Stop(t.Context()) }()

	enc, err := m.Encrypt(t.Context(), &encryptionv1.EncryptRequest{Plaintext: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSetting("key_file", key2); err != nil {
		t.Fatal(err)
	}
	if got := settingValue(t, m.Settings(), "key_file"); got != key2 {
		t.Fatalf("key_file=%q", got)
	}
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

func TestSettingsKeyFileRejectsMissing(t *testing.T) {
	dir := t.TempDir()
	key1 := filepath.Join(dir, "a.key")
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	if err := os.WriteFile(key1, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewModule(Config{KeyFile: key1, GRPCAddr: "127.0.0.1:0"})
	if err := m.Init(t.Context()); err != nil {
		t.Fatal(err)
	}

	enc, err := m.Encrypt(t.Context(), &encryptionv1.EncryptRequest{Plaintext: []byte("keep-me")})
	if err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(dir, "missing.key")
	if err := m.UpdateSetting("key_file", missing); err == nil {
		t.Fatal("expected error for missing key file")
	}
	if got := settingValue(t, m.Settings(), "key_file"); got != key1 {
		t.Fatalf("key_file reverted to %q", got)
	}

	dec, err := m.Decrypt(t.Context(), &encryptionv1.DecryptRequest{Ciphertext: enc.GetCiphertext()})
	if err != nil {
		t.Fatal(err)
	}
	if string(dec.GetPlaintext()) != "keep-me" {
		t.Fatalf("got %q", dec.GetPlaintext())
	}
}

func TestSettingsRotateKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "keyring.json")
	m := NewModule(Config{KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
	if err := m.Init(t.Context()); err != nil {
		t.Fatal(err)
	}

	before := settingValue(t, m.Settings(), "active_key_id")
	if err := m.UpdateSetting("rotate_key", "now"); err != nil {
		t.Fatal(err)
	}
	after := settingValue(t, m.Settings(), "active_key_id")
	if after == before {
		t.Fatalf("active_key_id unchanged: %s", after)
	}
	if got := settingValue(t, m.Settings(), "key_count"); got != "2" {
		t.Fatalf("key_count=%q", got)
	}
}

func TestSettingsReadOnlyKeys(t *testing.T) {
	m := NewModule(Config{KeyFile: filepath.Join(t.TempDir(), "master.key"), GRPCAddr: "127.0.0.1:0"})
	if err := m.UpdateSetting("active_key_id", "99"); err == nil {
		t.Fatal("expected read-only error")
	}
	if err := m.UpdateSetting("key_count", "99"); err == nil {
		t.Fatal("expected read-only error")
	}
}
