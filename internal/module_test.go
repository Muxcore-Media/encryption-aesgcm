package internal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	encryptionv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/encryption/v1"
)

func TestModuleInfo(t *testing.T) {
	m := NewModule(Config{})
	info := m.Info()
	if info.ID == "" {
		t.Error("module ID must not be empty")
	}
	if info.Version == "" {
		t.Error("module version must not be empty")
	}
	if info.MinCoreVersion == "" {
		t.Error("MinCoreVersion must not be empty")
	}
	if len(info.Contracts) == 0 {
		t.Error("Contracts must not be empty")
	}
	if info.Contracts[0].Interface != "EncryptionProvider" {
		t.Errorf("expected EncryptionProvider contract, got %s", info.Contracts[0].Interface)
	}
	if len(info.Capabilities) == 0 {
		t.Error("Capabilities must not be empty")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_MASTER_KEY", hex.EncodeToString(key))

	m := NewModule(Config{KeyFile: filepath.Join(t.TempDir(), "master.key")})
	ctx := context.Background()

	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello encryption-aesgcm")
	resp, err := m.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: plaintext})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Ciphertext) == 0 {
		t.Fatal("ciphertext is empty")
	}
	if string(resp.Ciphertext) == string(plaintext) {
		t.Fatal("ciphertext must not equal plaintext")
	}

	decrypted, err := m.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: resp.Ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted.Plaintext) != string(plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, decrypted.Plaintext)
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_MASTER_KEY", hex.EncodeToString(key))

	m := NewModule(Config{KeyFile: filepath.Join(t.TempDir(), "master.key"), GRPCAddr: ":0"})
	ctx := context.Background()

	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}

	resp, err := m.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: []byte{}})
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := m.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: resp.Ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	if len(decrypted.Plaintext) != 0 {
		t.Fatal("expected empty plaintext")
	}
}

func TestRotateKeyNotSupported(t *testing.T) {
	m := NewModule(Config{KeyFile: filepath.Join(t.TempDir(), "master.key")})
	_, err := m.RotateKey(context.Background(), &encryptionv1.RotateKeyRequest{})
	if err == nil {
		t.Fatal("expected error for rotation")
	}
	if !strings.Contains(err.Error(), "rotation not supported") {
		t.Fatalf("expected rotation not supported error, got: %v", err)
	}
}

func TestAvailable(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_MASTER_KEY", hex.EncodeToString(key))

	m := NewModule(Config{KeyFile: filepath.Join(t.TempDir(), "master.key"), GRPCAddr: ":0"})
	ctx := context.Background()

	resp, err := m.Available(ctx, &encryptionv1.AvailableRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Available {
		t.Fatal("expected not available before init")
	}

	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}

	resp, err = m.Available(ctx, &encryptionv1.AvailableRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Available {
		t.Fatal("expected available after init")
	}
}

func TestLifecycle(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_MASTER_KEY", hex.EncodeToString(key))

	m := NewModule(Config{KeyFile: filepath.Join(t.TempDir(), "master.key"), GRPCAddr: ":0"})
	ctx := context.Background()

	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Health(ctx); err != nil {
		t.Fatal("expected health to pass after start")
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestKeyGeneration(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "subdir", "master.key")

	m := NewModule(Config{KeyFile: keyFile, GRPCAddr: ":0"})
	ctx := context.Background()

	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(key))
	}
}
