package internal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"google.golang.org/grpc"

	"github.com/Muxcore-Media/core/pkg/contracts"
	encryptionv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/encryption/v1"
)

var errRotationNotSupported = errors.New("rotation not supported by AES-GCM static key provider")

type Module struct {
	encryptionv1.UnimplementedEncryptionServiceServer

	mu   sync.RWMutex
	key  []byte
	aead cipher.AEAD

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
	}
}

func (m *Module) Info() contracts.ModuleInfo {
	return contracts.ModuleInfo{
		ID:           m.id,
		Name:         "Encryption AES-GCM",
		Version:      "0.1.0",
		Roles:        []string{"infrastructure"},
		Description:  "AES-256-GCM envelope encryption provider with static master key",
		Author:       "MuxCore",
		Capabilities: []string{contracts.CapabilityEncryption},
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
	key, err := m.loadOrGenerateKey()
	if err != nil {
		return fmt.Errorf("load master key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	m.mu.Lock()
	m.key = key
	m.aead = aead
	m.mu.Unlock()

	lis, err := net.Listen("tcp", m.grpcAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", m.grpcAddr, err)
	}
	m.lis = lis

	slog.Info("encryption-aesgcm initialized", "addr", m.grpcAddr)
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
	ok := m.aead != nil && m.key != nil
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("not initialized")
	}
	return nil
}

func (m *Module) Encrypt(ctx context.Context, req *encryptionv1.EncryptRequest) (*encryptionv1.EncryptResponse, error) {
	m.mu.RLock()
	aead := m.aead
	m.mu.RUnlock()

	if aead == nil {
		return nil, fmt.Errorf("encryption not initialized")
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, req.GetPlaintext(), nil)
	out := append(nonce, ciphertext...)

	return &encryptionv1.EncryptResponse{Ciphertext: out}, nil
}

func (m *Module) Decrypt(ctx context.Context, req *encryptionv1.DecryptRequest) (*encryptionv1.DecryptResponse, error) {
	m.mu.RLock()
	aead := m.aead
	m.mu.RUnlock()

	if aead == nil {
		return nil, fmt.Errorf("encryption not initialized")
	}

	data := req.GetCiphertext()
	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return &encryptionv1.DecryptResponse{Plaintext: plaintext}, nil
}

func (m *Module) RotateKey(ctx context.Context, req *encryptionv1.RotateKeyRequest) (*encryptionv1.RotateKeyResponse, error) {
	return nil, errRotationNotSupported
}

func (m *Module) Available(ctx context.Context, req *encryptionv1.AvailableRequest) (*encryptionv1.AvailableResponse, error) {
	m.mu.RLock()
	ok := m.aead != nil
	m.mu.RUnlock()

	return &encryptionv1.AvailableResponse{Available: ok}, nil
}

func (m *Module) loadOrGenerateKey() ([]byte, error) {
	if v := os.Getenv("ENCRYPTION_MASTER_KEY"); v != "" {
		key, err := hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("decode ENCRYPTION_MASTER_KEY: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("ENCRYPTION_MASTER_KEY must be 32 bytes (64 hex chars), got %d bytes", len(key))
		}
		slog.Info("master key loaded from environment variable")
		return key, nil
	}

	if data, err := os.ReadFile(m.keyFile); err == nil {
		key, err := hex.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("decode key file %s: %w", m.keyFile, err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("key in %s must be 32 bytes (64 hex chars), got %d bytes", m.keyFile, len(key))
		}
		slog.Info("master key loaded from file", "path", m.keyFile)
		return key, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}

	dir := filepath.Dir(m.keyFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create key directory %s: %w", dir, err)
	}

	encoded := hex.EncodeToString(key)
	if err := os.WriteFile(m.keyFile, []byte(encoded+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("write key file %s: %w", m.keyFile, err)
	}

	slog.Info("master key generated and saved", "path", m.keyFile)
	return key, nil
}
