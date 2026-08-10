package internal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/grpc"

	"github.com/Muxcore-Media/core/pkg/contracts"
	encryptionv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/encryption/v1"
)

const (
	blobMagic      = "MXE1"
	blobHeaderSize = 4 + 4 // magic + key_id
	legacyKeyID    = uint32(0)
	keyBytes       = 32
)

type keyEntry struct {
	id   uint32
	key  []byte
	aead cipher.AEAD
}

type keyringFile struct {
	Version int               `json:"version"`
	Active  uint32            `json:"active"`
	Keys    map[string]string `json:"keys"`
}

type Module struct {
	encryptionv1.UnimplementedEncryptionServiceServer

	mu     sync.RWMutex
	active uint32
	keys   map[uint32]*keyEntry

	id       string
	keyFile  string
	grpcAddr string
	grpcSrv  *grpc.Server
	lis      net.Listener
}

type Config struct {
	ID       string
	KeyFile  string
	GRPCAddr string
}

func NewModule(cfg Config) *Module {
	if cfg.ID == "" {
		cfg.ID = "encryption-aesgcm"
	}
	if cfg.KeyFile == "" {
		cfg.KeyFile = "/var/lib/encryption-aesgcm/master.key"
	}
	if cfg.GRPCAddr == "" {
		cfg.GRPCAddr = ":9601"
	}
	if v := os.Getenv("ENCRYPTION_KEY_FILE"); v != "" {
		cfg.KeyFile = v
	}
	if v := os.Getenv("ENCRYPTION_GRPC_ADDR"); v != "" {
		cfg.GRPCAddr = v
	}
	return &Module{
		id:       cfg.ID,
		keyFile:  cfg.KeyFile,
		grpcAddr: cfg.GRPCAddr,
		keys:     make(map[uint32]*keyEntry),
	}
}

func (m *Module) Info() contracts.ModuleInfo {
	return contracts.ModuleInfo{
		ID:           m.id,
		Name:         "Encryption AES-GCM",
		Version:      "0.2.4",
		Roles:        []string{"infrastructure"},
		Description:  "AES-256-GCM envelope encryption with versioned keyring and key rotation",
		Author:       "MuxCore",
		Capabilities: []string{contracts.CapabilityEncryption, "encryption.aesgcm"},
		Contracts: []contracts.ContractDeclaration{
			{
				Repo:      "github.com/Muxcore-Media/core/pkg/contracts",
				Interface: "EncryptionProvider",
				Version:   "v0.4.0",
			},
		},
		MinCoreVersion: "0.4.0",
		HTTPAddr:       m.grpcAddr,
	}
}

func (m *Module) Init(ctx context.Context) error {
	if err := m.loadOrBootstrapRing(); err != nil {
		return fmt.Errorf("load keyring: %w", err)
	}

	lis, err := net.Listen("tcp", m.grpcAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", m.grpcAddr, err)
	}
	m.lis = lis

	slog.Info("encryption-aesgcm initialized", "addr", m.grpcAddr, "active_key", m.active, "keys", len(m.keys))
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.grpcSrv = grpc.NewServer()
	encryptionv1.RegisterEncryptionServiceServer(m.grpcSrv, m)

	go func() {
		slog.Info("encryption-aesgcm gRPC service started", "addr", m.grpcAddr)
		if err := m.grpcSrv.Serve(m.lis); err != nil {
			slog.Error("encryption-aesgcm gRPC serve error", "error", err)
		}
	}()
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	if m.grpcSrv != nil {
		m.grpcSrv.GracefulStop()
	}
	slog.Info("encryption-aesgcm stopped")
	return nil
}

func (m *Module) Health(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.keys) == 0 {
		return fmt.Errorf("not initialized")
	}
	if _, ok := m.keys[m.active]; !ok {
		return fmt.Errorf("active key %d missing", m.active)
	}
	return nil
}

func (m *Module) Encrypt(ctx context.Context, req *encryptionv1.EncryptRequest) (*encryptionv1.EncryptResponse, error) {
	m.mu.RLock()
	entry := m.keys[m.active]
	activeID := m.active
	m.mu.RUnlock()

	if entry == nil {
		return nil, fmt.Errorf("encryption not initialized")
	}

	nonce := make([]byte, entry.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := entry.aead.Seal(nil, nonce, req.GetPlaintext(), nil)

	out := make([]byte, 0, blobHeaderSize+len(nonce)+len(ciphertext))
	out = append(out, blobMagic...)
	var idBuf [4]byte
	binary.BigEndian.PutUint32(idBuf[:], activeID)
	out = append(out, idBuf[:]...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return &encryptionv1.EncryptResponse{Ciphertext: out}, nil
}

func (m *Module) Decrypt(ctx context.Context, req *encryptionv1.DecryptRequest) (*encryptionv1.DecryptResponse, error) {
	data := req.GetCiphertext()
	if len(data) == 0 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	if isVersionedBlob(data) {
		plaintext, err := m.decryptVersioned(data)
		if err != nil {
			return nil, err
		}
		return &encryptionv1.DecryptResponse{Plaintext: plaintext}, nil
	}

	plaintext, err := m.decryptLegacy(data)
	if err != nil {
		return nil, err
	}
	return &encryptionv1.DecryptResponse{Plaintext: plaintext}, nil
}

func (m *Module) RotateKey(ctx context.Context, req *encryptionv1.RotateKeyRequest) (*encryptionv1.RotateKeyResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.keys) == 0 {
		return nil, fmt.Errorf("encryption not initialized")
	}

	var nextID uint32
	for id := range m.keys {
		if id >= nextID {
			nextID = id + 1
		}
	}

	raw := make([]byte, keyBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	entry, err := newKeyEntry(nextID, raw)
	if err != nil {
		return nil, err
	}

	prevActive := m.active
	m.keys[nextID] = entry
	m.active = nextID

	if err := m.persistRingLocked(); err != nil {
		delete(m.keys, nextID)
		m.active = prevActive
		return nil, fmt.Errorf("persist keyring: %w", err)
	}

	slog.Info("key rotated", "active_key", m.active, "keys", len(m.keys))
	return &encryptionv1.RotateKeyResponse{}, nil
}

func (m *Module) Available(ctx context.Context, req *encryptionv1.AvailableRequest) (*encryptionv1.AvailableResponse, error) {
	m.mu.RLock()
	ok := len(m.keys) > 0 && m.keys[m.active] != nil
	m.mu.RUnlock()

	return &encryptionv1.AvailableResponse{Available: ok}, nil
}

func isVersionedBlob(data []byte) bool {
	return len(data) >= blobHeaderSize && string(data[:4]) == blobMagic
}

func (m *Module) decryptVersioned(data []byte) ([]byte, error) {
	if len(data) < blobHeaderSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	keyID := binary.BigEndian.Uint32(data[4:8])

	m.mu.RLock()
	entry := m.keys[keyID]
	m.mu.RUnlock()
	if entry == nil {
		return nil, fmt.Errorf("unknown key id %d", keyID)
	}

	body := data[blobHeaderSize:]
	nonceSize := entry.aead.NonceSize()
	if len(body) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := body[:nonceSize], body[nonceSize:]
	plaintext, err := entry.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

func (m *Module) decryptLegacy(data []byte) ([]byte, error) {
	m.mu.RLock()
	entry := m.keys[legacyKeyID]
	if entry == nil {
		// fall back to any single key if ring was bootstrapped without id 0
		if len(m.keys) == 1 {
			for _, e := range m.keys {
				entry = e
			}
		}
	}
	m.mu.RUnlock()
	if entry == nil {
		return nil, fmt.Errorf("no legacy key available")
	}

	nonceSize := entry.aead.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := entry.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

func newKeyEntry(id uint32, key []byte) (*keyEntry, error) {
	if len(key) != keyBytes {
		return nil, fmt.Errorf("key must be %d bytes, got %d", keyBytes, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return &keyEntry{id: id, key: key, aead: aead}, nil
}

func (m *Module) loadOrBootstrapRing() error {
	if data, err := os.ReadFile(m.keyFile); err == nil {
		trimmed := strings.TrimSpace(string(data))
		// JSON keyring on disk wins over ENCRYPTION_MASTER_KEY so RotateKey survives restart.
		if trimmed != "" && !isLegacyHexKey(trimmed) {
			return m.loadRingBytes(data)
		}
		if v := os.Getenv("ENCRYPTION_MASTER_KEY"); v != "" {
			return m.loadEnvKey(v)
		}
		return m.loadRingBytes(data)
	}

	if v := os.Getenv("ENCRYPTION_MASTER_KEY"); v != "" {
		return m.loadEnvKey(v)
	}

	key := make([]byte, keyBytes)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate master key: %w", err)
	}
	entry, err := newKeyEntry(legacyKeyID, key)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.keys = map[uint32]*keyEntry{legacyKeyID: entry}
	m.active = legacyKeyID
	err = m.persistRingLocked()
	m.mu.Unlock()
	if err != nil {
		return err
	}

	slog.Info("master key generated and saved", "path", m.keyFile)
	return nil
}

func (m *Module) loadEnvKey(v string) error {
	key, err := hex.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("decode ENCRYPTION_MASTER_KEY: %w", err)
	}
	if len(key) != keyBytes {
		return fmt.Errorf("ENCRYPTION_MASTER_KEY must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}
	entry, err := newKeyEntry(legacyKeyID, key)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.keys = map[uint32]*keyEntry{legacyKeyID: entry}
	m.active = legacyKeyID
	m.mu.Unlock()
	slog.Info("master key loaded from environment variable")
	return nil
}

func (m *Module) loadRingBytes(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return fmt.Errorf("key file %s is empty", m.keyFile)
	}

	// Legacy single-hex key file.
	if isLegacyHexKey(trimmed) {
		key, err := hex.DecodeString(trimmed)
		if err != nil {
			return fmt.Errorf("decode key file %s: %w", m.keyFile, err)
		}
		entry, err := newKeyEntry(legacyKeyID, key)
		if err != nil {
			return err
		}
		m.mu.Lock()
		m.keys = map[uint32]*keyEntry{legacyKeyID: entry}
		m.active = legacyKeyID
		m.mu.Unlock()
		slog.Info("master key loaded from legacy hex file", "path", m.keyFile)
		return nil
	}

	var ring keyringFile
	if err := json.Unmarshal([]byte(trimmed), &ring); err != nil {
		return fmt.Errorf("parse keyring %s: %w", m.keyFile, err)
	}
	if len(ring.Keys) == 0 {
		return fmt.Errorf("keyring %s has no keys", m.keyFile)
	}

	keys := make(map[uint32]*keyEntry, len(ring.Keys))
	for idStr, hexKey := range ring.Keys {
		id64, err := strconv.ParseUint(idStr, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid key id %q in %s: %w", idStr, m.keyFile, err)
		}
		id := uint32(id64)
		raw, err := hex.DecodeString(strings.TrimSpace(hexKey))
		if err != nil {
			return fmt.Errorf("decode key %d in %s: %w", id, m.keyFile, err)
		}
		entry, err := newKeyEntry(id, raw)
		if err != nil {
			return fmt.Errorf("key %d: %w", id, err)
		}
		keys[id] = entry
	}
	if _, ok := keys[ring.Active]; !ok {
		return fmt.Errorf("active key %d missing from %s", ring.Active, m.keyFile)
	}

	m.mu.Lock()
	m.keys = keys
	m.active = ring.Active
	m.mu.Unlock()
	slog.Info("keyring loaded from file", "path", m.keyFile, "active_key", ring.Active, "keys", len(keys))
	return nil
}

func isLegacyHexKey(s string) bool {
	if len(s) != keyBytes*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func (m *Module) persistRingLocked() error {
	dir := filepath.Dir(m.keyFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create key directory %s: %w", dir, err)
	}

	ring := keyringFile{
		Version: 1,
		Active:  m.active,
		Keys:    make(map[string]string, len(m.keys)),
	}
	for id, entry := range m.keys {
		ring.Keys[fmt.Sprintf("%d", id)] = hex.EncodeToString(entry.key)
	}

	payload, err := json.MarshalIndent(ring, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal keyring: %w", err)
	}
	payload = append(payload, '\n')

	tmp := m.keyFile + ".tmp"
	if err := os.WriteFile(tmp, payload, 0600); err != nil {
		return fmt.Errorf("write keyring temp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, m.keyFile); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace keyring %s: %w", m.keyFile, err)
	}
	return nil
}
