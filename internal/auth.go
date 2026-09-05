package internal

import (
	"context"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const callerIDMetadataKey = "x-caller-id"

const encryptionServicePrefix = "/muxcore.encryption.v1.EncryptionService/"

var protectedEncryptionMethods = map[string]bool{
	encryptionServicePrefix + "Encrypt":   true,
	encryptionServicePrefix + "Decrypt":   true,
	encryptionServicePrefix + "RotateKey": true,
}

func moduleTokenFromEnv() string {
	for _, k := range []string{"ENCRYPTION_MODULE_TOKEN", "MUXCORE_MODULE_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func authUnaryInterceptor(moduleToken string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !protectedEncryptionMethods[info.FullMethod] {
			return handler(ctx, req)
		}
		if err := authorizeEncryptionRPC(ctx, moduleToken); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func authorizeEncryptionRPC(ctx context.Context, moduleToken string) error {
	if id := callerFromVerifiedTLS(ctx); id != "" {
		return nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "mesh identity or module token required")
	}
	if ids := md.Get(callerIDMetadataKey); len(ids) > 0 {
		id := strings.TrimSpace(ids[0])
		if id != "" && id != "_public" {
			return nil
		}
	}
	if moduleToken != "" {
		if vals := md.Get("authorization"); len(vals) > 0 {
			token := bearerToken(vals[0])
			if token != "" && token == moduleToken {
				return nil
			}
		}
	}
	return status.Error(codes.Unauthenticated, "mesh identity or module token required")
}

// callerFromVerifiedTLS returns the client certificate CN when the connection
// used mTLS with a verified peer certificate. This identity cannot be spoofed
// via metadata alone.
func callerFromVerifiedTLS(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 {
		return ""
	}
	cert := ti.State.VerifiedChains[0][0]
	if cert == nil {
		return ""
	}
	return strings.TrimSpace(cert.Subject.CommonName)
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	header = strings.TrimSpace(header)
	if len(header) > len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return header
}
