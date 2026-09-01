package internal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

	m := NewModule(Config{KeyFile: filepath.Join(t.TempDir(), "master.key"), GRPCAddr: ":0"})
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
	if !isVersionedBlob(resp.Ciphertext) {
		t.Fatal("expected versioned ciphertext blob")
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

func TestEncryptRotateDecryptOld(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "keyring.json")
	m := NewModule(Config{KeyFile: keyFile, GRPCAddr: ":0"})
	ctx := context.Background()

	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("before-rotation")
	oldBlob, err := m.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: plaintext})
	if err != nil {
		t.Fatal(err)
	}
	oldActive := m.active

	if _, err := m.RotateKey(ctx, &encryptionv1.RotateKeyRequest{}); err != nil {
		t.Fatal(err)
	}
	if m.active == oldActive {
		t.Fatal("active key id must change after rotation")
	}

	decrypted, err := m.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: oldBlob.Ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted.Plaintext) != string(plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, decrypted.Plaintext)
	}

	newPlain := []byte("after-rotation")
	newBlob, err := m.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: newPlain})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err = m.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: newBlob.Ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted.Plaintext) != string(newPlain) {
		t.Fatalf("expected %q, got %q", newPlain, decrypted.Plaintext)
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	var ring keyringFile
	if err := json.Unmarshal(data, &ring); err != nil {
		t.Fatal(err)
	}
	if ring.Active != m.active {
		t.Fatalf("persisted active %d != in-memory %d", ring.Active, m.active)
	}
	if len(ring.Keys) < 2 {
		t.Fatalf("expected at least 2 keys after rotation, got %d", len(ring.Keys))
	}
}

func TestLegacyDecryptCompat(t *testing.T) {
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

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("legacy-blob")
	legacy := append(nonce, aead.Seal(nil, nonce, plaintext, nil)...)

	if isVersionedBlob(legacy) {
		t.Fatal("legacy blob must not look versioned")
	}

	decrypted, err := m.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: legacy})
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted.Plaintext) != string(plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, decrypted.Plaintext)
	}

	versioned, err := m.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: []byte("versioned")})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err = m.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: versioned.Ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted.Plaintext) != "versioned" {
		t.Fatalf("got %q", decrypted.Plaintext)
	}
}

func TestTrimSpaceReloadAfterGenerate(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	// Simulate the historical generate path: hex + trailing newline, no TrimSpace would fail.
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(raw)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	m := NewModule(Config{KeyFile: keyFile, GRPCAddr: ":0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Health(ctx); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("trimspace-ok")
	enc, err := m.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: plaintext})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := m.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: enc.Ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	if string(dec.Plaintext) != string(plaintext) {
		t.Fatalf("got %q", dec.Plaintext)
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
	var ring keyringFile
	if err := json.Unmarshal(data, &ring); err != nil {
		t.Fatalf("expected JSON keyring after generate: %v\n%s", err, data)
	}
	if ring.Active != legacyKeyID {
		t.Fatalf("expected active %d, got %d", legacyKeyID, ring.Active)
	}
	hexKey, ok := ring.Keys["0"]
	if !ok {
		t.Fatal("missing key id 0")
	}
	key, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(key))
	}

	fi, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0077 != 0 {
		t.Fatalf("keyring file must not be group/other accessible, mode=%o", fi.Mode().Perm())
	}
}

func TestEncryptRotateRestartDecrypt(t *testing.T) {
	// Real local integration: encrypt → rotate → Stop/Init restart → decrypt
	// old versioned + legacy blobs; new Encrypt uses rotated active key.
	t.Setenv("ENCRYPTION_MASTER_KEY", "")

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "keyring.json")
	ctx := context.Background()

	m1 := NewModule(Config{KeyFile: keyFile, GRPCAddr: ":0"})
	if err := m1.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m1.Start(ctx); err != nil {
		t.Fatal(err)
	}

	oldPlain := []byte("survive-restart")
	oldBlob, err := m1.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: oldPlain})
	if err != nil {
		t.Fatal(err)
	}
	oldActive := m1.active

	// Legacy (unversioned) ciphertext under key id 0 must also survive restart.
	legacyPlain := []byte("legacy-survive")
	m1.mu.RLock()
	legacyEntry := m1.keys[legacyKeyID]
	m1.mu.RUnlock()
	if legacyEntry == nil {
		t.Fatal("expected legacy key id 0 after bootstrap")
	}
	nonce := make([]byte, legacyEntry.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	legacyBlob := append(nonce, legacyEntry.aead.Seal(nil, nonce, legacyPlain, nil)...)

	if _, err := m1.RotateKey(ctx, &encryptionv1.RotateKeyRequest{}); err != nil {
		t.Fatal(err)
	}
	if m1.active == oldActive {
		t.Fatal("active key id must change after rotation")
	}
	rotatedActive := m1.active

	newPlain := []byte("after-rotate-before-restart")
	newBlob, err := m1.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: newPlain})
	if err != nil {
		t.Fatal(err)
	}

	if err := m1.Stop(ctx); err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("keyring must not be group/other accessible, mode=%o", st.Mode().Perm())
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	var ring keyringFile
	if err := json.Unmarshal(data, &ring); err != nil {
		t.Fatal(err)
	}
	if ring.Active != rotatedActive {
		t.Fatalf("persisted active %d != %d", ring.Active, rotatedActive)
	}
	if len(ring.Keys) < 2 {
		t.Fatalf("expected multi-key ring after rotate, got %d", len(ring.Keys))
	}

	// New process: load persisted keyring only (no ENCRYPTION_MASTER_KEY).
	m2 := NewModule(Config{KeyFile: keyFile, GRPCAddr: ":0"})
	if err := m2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m2.Stop(ctx) }()

	if m2.active != rotatedActive {
		t.Fatalf("after restart active=%d, want %d", m2.active, rotatedActive)
	}
	if len(m2.keys) < 2 {
		t.Fatalf("after restart expected >=2 keys, got %d", len(m2.keys))
	}

	for _, tc := range []struct {
		name string
		ct   []byte
		want []byte
	}{
		{"pre-rotate versioned", oldBlob.Ciphertext, oldPlain},
		{"post-rotate versioned", newBlob.Ciphertext, newPlain},
		{"legacy unversioned", legacyBlob, legacyPlain},
	} {
		dec, err := m2.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: tc.ct})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if string(dec.Plaintext) != string(tc.want) {
			t.Fatalf("%s: got %q, want %q", tc.name, dec.Plaintext, tc.want)
		}
	}

	postRestartPlain := []byte("after-restart")
	postBlob, err := m2.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: postRestartPlain})
	if err != nil {
		t.Fatal(err)
	}
	if !isVersionedBlob(postBlob.Ciphertext) {
		t.Fatal("post-restart ciphertext must be versioned")
	}
	dec, err := m2.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: postBlob.Ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	if string(dec.Plaintext) != string(postRestartPlain) {
		t.Fatalf("post-restart round-trip: got %q", dec.Plaintext)
	}
}

func TestEnvKeyPersistRestartDecrypt(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "keyring.json")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_MASTER_KEY", hex.EncodeToString(key))
	t.Setenv("ENCRYPTION_KEY_FILE", keyFile)

	ctx := context.Background()
	m1 := NewModule(Config{KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
	if err := m1.Init(ctx); err != nil {
		t.Fatal(err)
	}

	plain := []byte("env-persisted")
	enc, err := m1.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: plain})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("expected persisted keyring at %s: %v", keyFile, err)
	}

	t.Setenv("ENCRYPTION_MASTER_KEY", "")
	m2 := NewModule(Config{KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
	if err := m2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	dec, err := m2.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: enc.GetCiphertext()})
	if err != nil {
		t.Fatal(err)
	}
	if string(dec.GetPlaintext()) != string(plain) {
		t.Fatalf("got %q", dec.GetPlaintext())
	}
}

func TestDefaultGRPCAddrLoopback(t *testing.T) {
	t.Setenv("ENCRYPTION_GRPC_ADDR", "")
	m := NewModule(Config{})
	if m.grpcAddr != defaultGRPCAddr {
		t.Fatalf("grpcAddr=%q want %q", m.grpcAddr, defaultGRPCAddr)
	}
}

func TestEncryptPlaintextTooLarge(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_MASTER_KEY", hex.EncodeToString(key))

	m := NewModule(Config{KeyFile: filepath.Join(t.TempDir(), "master.key"), GRPCAddr: "127.0.0.1:0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}

	_, err := m.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: make([]byte, maxPlaintextBytes+1)})
	if err == nil {
		t.Fatal("expected error for oversized plaintext")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code=%v want InvalidArgument", status.Code(err))
	}
}

func TestDecryptNegativeCases(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_MASTER_KEY", hex.EncodeToString(key))

	m := NewModule(Config{KeyFile: filepath.Join(t.TempDir(), "master.key"), GRPCAddr: "127.0.0.1:0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}

	t.Run("empty ciphertext", func(t *testing.T) {
		_, err := m.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: nil})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("code=%v", status.Code(err))
		}
	})

	t.Run("short ciphertext", func(t *testing.T) {
		_, err := m.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: []byte{1, 2, 3}})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("code=%v", status.Code(err))
		}
	})

	t.Run("truncated MXE1 header", func(t *testing.T) {
		_, err := m.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: []byte(blobMagic[:3])})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("code=%v", status.Code(err))
		}
	})

	t.Run("unknown key id", func(t *testing.T) {
		blob := append([]byte(blobMagic), 0, 0, 0, 99)
		blob = append(blob, make([]byte, 32)...)
		_, err := m.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: blob})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("code=%v", status.Code(err))
		}
	})
}

func TestInitInvalidMasterKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")

	t.Run("invalid hex", func(t *testing.T) {
		t.Setenv("ENCRYPTION_MASTER_KEY", "not-hex")
		m := NewModule(Config{KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
		if err := m.Init(context.Background()); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		t.Setenv("ENCRYPTION_MASTER_KEY", hex.EncodeToString([]byte("short")))
		m := NewModule(Config{KeyFile: filepath.Join(t.TempDir(), "other.key"), GRPCAddr: "127.0.0.1:0"})
		if err := m.Init(context.Background()); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestInitKeyFileErrors(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")

	t.Run("empty file", func(t *testing.T) {
		if err := os.WriteFile(keyFile, []byte("\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		m := NewModule(Config{KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
		if err := m.Init(context.Background()); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("garbage file", func(t *testing.T) {
		garbage := filepath.Join(dir, "garbage.key")
		if err := os.WriteFile(garbage, []byte("{not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
		m := NewModule(Config{KeyFile: garbage, GRPCAddr: "127.0.0.1:0"})
		if err := m.Init(context.Background()); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestHealthBeforeInit(t *testing.T) {
	m := NewModule(Config{KeyFile: filepath.Join(t.TempDir(), "master.key"), GRPCAddr: "127.0.0.1:0"})
	if err := m.Health(context.Background()); err == nil {
		t.Fatal("expected health error before init")
	}
}

func TestJSONKeyringWinsOverEnv(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "keyring.json")

	fileKey := make([]byte, 32)
	for i := range fileKey {
		fileKey[i] = byte(i + 10)
	}
	envKey := make([]byte, 32)
	for i := range envKey {
		envKey[i] = byte(i + 20)
	}
	t.Setenv("ENCRYPTION_MASTER_KEY", hex.EncodeToString(envKey))

	ring := keyringFile{
		Version: 1,
		Active:  legacyKeyID,
		Keys:    map[string]string{"0": hex.EncodeToString(fileKey)},
	}
	payload, err := json.Marshal(ring)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewModule(Config{KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	plain := []byte("file-key-wins")
	legacy := append(nonce, aead.Seal(nil, nonce, plain, nil)...)

	dec, err := m.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: legacy})
	if err != nil {
		t.Fatal(err)
	}
	if string(dec.GetPlaintext()) != string(plain) {
		t.Fatalf("got %q", dec.GetPlaintext())
	}
}

func TestEncryptNotInitialized(t *testing.T) {
	m := NewModule(Config{KeyFile: filepath.Join(t.TempDir(), "master.key"), GRPCAddr: "127.0.0.1:0"})
	_, err := m.Encrypt(context.Background(), &encryptionv1.EncryptRequest{Plaintext: []byte("x")})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code=%v", status.Code(err))
	}
}
