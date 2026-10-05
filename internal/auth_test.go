package internal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	encryptionv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/encryption/v1"
	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const testModuleToken = "test-encryption-module-token"

func startAuthServer(t *testing.T, m *Module, moduleToken string) *bufconn.Listener {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer(grpc.UnaryInterceptor(authUnaryInterceptor(moduleToken)))
	encryptionv1.RegisterEncryptionServiceServer(grpcSrv, m)
	modulesdk.RegisterSettings(grpcSrv, m.id, m)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(func() { grpcSrv.Stop() })
	return lis
}

func testModule(t *testing.T) *Module {
	t.Helper()
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
	return m
}

func rpcContext(md metadata.MD) context.Context {
	return metadata.NewOutgoingContext(context.Background(), md)
}

func expectUnauthenticated(t *testing.T, err error) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status, got %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v: %s", st.Code(), st.Message())
	}
}

func TestAuthorizeEncryptionRPC_RejectsAnonymous(t *testing.T) {
	m := testModule(t)
	lis := startAuthServer(t, m, testModuleToken)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client := encryptionv1.NewEncryptionServiceClient(conn)

	_, err = client.Encrypt(context.Background(), &encryptionv1.EncryptRequest{Plaintext: []byte("secret")})
	expectUnauthenticated(t, err)

	_, err = client.Decrypt(context.Background(), &encryptionv1.DecryptRequest{Ciphertext: []byte("blob")})
	expectUnauthenticated(t, err)

	_, err = client.RotateKey(context.Background(), &encryptionv1.RotateKeyRequest{})
	expectUnauthenticated(t, err)
}

func TestAuthorizeEncryptionRPC_RejectsPublicCaller(t *testing.T) {
	m := testModule(t)
	lis := startAuthServer(t, m, testModuleToken)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client := encryptionv1.NewEncryptionServiceClient(conn)

	_, err = client.Encrypt(rpcContext(metadata.Pairs(callerIDMetadataKey, "_public")),
		&encryptionv1.EncryptRequest{Plaintext: []byte("secret")})
	expectUnauthenticated(t, err)
}

func TestAuthorizeEncryptionRPC_AcceptsMeshCallerID(t *testing.T) {
	m := testModule(t)
	lis := startAuthServer(t, m, testModuleToken)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	client := encryptionv1.NewEncryptionServiceClient(conn)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(callerIDMetadataKey, "database-sqlite"))

	resp, err := client.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: []byte("mesh-auth")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	dec, err := client.Decrypt(ctx, &encryptionv1.DecryptRequest{Ciphertext: resp.Ciphertext})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(dec.Plaintext) != "mesh-auth" {
		t.Fatalf("got %q", dec.Plaintext)
	}
}

func TestAuthorizeEncryptionRPC_AcceptsModuleToken(t *testing.T) {
	m := testModule(t)
	lis := startAuthServer(t, m, testModuleToken)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	client := encryptionv1.NewEncryptionServiceClient(conn)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+testModuleToken))

	_, err = client.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: []byte("token-auth")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
}

func TestAuthorizeEncryptionRPC_RejectsWrongModuleToken(t *testing.T) {
	m := testModule(t)
	lis := startAuthServer(t, m, testModuleToken)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	client := encryptionv1.NewEncryptionServiceClient(conn)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer wrong-token"))

	_, err = client.Encrypt(ctx, &encryptionv1.EncryptRequest{Plaintext: []byte("nope")})
	expectUnauthenticated(t, err)
}

func TestAuthorizeEncryptionRPC_AvailableWithoutAuth(t *testing.T) {
	m := testModule(t)
	lis := startAuthServer(t, m, testModuleToken)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	client := encryptionv1.NewEncryptionServiceClient(conn)
	resp, err := client.Available(context.Background(), &encryptionv1.AvailableRequest{})
	if err != nil {
		t.Fatalf("Available: %v", err)
	}
	if !resp.Available {
		t.Fatal("expected available=true")
	}
}

func TestModuleStart_RejectsUnauthenticatedOverGRPC(t *testing.T) {
	t.Setenv("MUXCORE_INSECURE_DISABLE_TLS", "true")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_MASTER_KEY", hex.EncodeToString(key))

	m := NewModule(Config{
		KeyFile:     filepath.Join(t.TempDir(), "master.key"),
		GRPCAddr:    "127.0.0.1:0",
		ModuleToken: testModuleToken,
	})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Stop(ctx) }()

	conn, err := grpc.NewClient(m.lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	client := encryptionv1.NewEncryptionServiceClient(conn)
	_, err = client.Decrypt(context.Background(), &encryptionv1.DecryptRequest{Ciphertext: []byte("blob")})
	expectUnauthenticated(t, err)
}

func TestAuthorizeEncryptionRPC_AcceptsVerifiedMTLSClient(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	serverCert, serverKey := issueTestCert(t, caCert, caKey, "encryption-aesgcm")
	clientCert, clientKey := issueTestCert(t, caCert, caKey, "muxcored")

	serverCreds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{loadKeyPair(serverCert, serverKey)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool(caCert),
		MinVersion:   tls.VersionTLS12,
	})
	clientCreds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{loadKeyPair(clientCert, clientKey)},
		RootCAs:      certPool(caCert),
		ServerName:   "encryption-aesgcm",
		MinVersion:   tls.VersionTLS12,
	})

	m := testModule(t)
	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer(
		grpc.Creds(serverCreds),
		grpc.UnaryInterceptor(authUnaryInterceptor("")),
	)
	encryptionv1.RegisterEncryptionServiceServer(grpcSrv, m)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(func() { grpcSrv.Stop() })

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(clientCreds),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	client := encryptionv1.NewEncryptionServiceClient(conn)
	resp, err := client.Encrypt(context.Background(), &encryptionv1.EncryptRequest{Plaintext: []byte("mtls")})
	if err != nil {
		t.Fatalf("Encrypt over mTLS: %v", err)
	}
	if len(resp.Ciphertext) == 0 {
		t.Fatal("expected ciphertext")
	}
}

func TestDefaultGRPCAddr(t *testing.T) {
	m := NewModule(Config{})
	if m.grpcAddr != "127.0.0.1:9601" {
		t.Fatalf("grpcAddr=%q, want 127.0.0.1:9601", m.grpcAddr)
	}
}

func generateTestCA(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key
}

func issueTestCert(t *testing.T, caPEM []byte, caKey *ecdsa.PrivateKey, cn string) ([]byte, []byte) {
	t.Helper()
	block, _ := pem.Decode(caPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func certPool(caPEM []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return pool
}

func loadKeyPair(certPEM, keyPEM []byte) tls.Certificate {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return cert
}
