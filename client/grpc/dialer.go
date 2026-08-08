package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/util/embeddedroots"
)

const (
	// EnvTLSInsecureSkipVerify allows skipping TLS certificate verification.
	// When set to "true", disables certificate expiry and hostname verification.
	// WARNING: This is ONLY for development/testing. Never use in production.
	// Value: "true" or "false" (default: "false")
	EnvTLSInsecureSkipVerify = "NB_TLS_INSECURE_SKIP_VERIFY"
)

// Backoff returns a backoff configuration for gRPC calls
func Backoff(ctx context.Context) backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 10 * time.Second
	b.Clock = backoff.SystemClock
	return backoff.WithContext(b, ctx)
}

// insecureSkipVerifyEnabled checks if TLS certificate verification should be skipped.
func insecureSkipVerifyEnabled() bool {
	val := os.Getenv(EnvTLSInsecureSkipVerify)
	if val == "" {
		return false
	}

	skipVerify, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v, using default (false)", EnvTLSInsecureSkipVerify, err)
		return false
	}

	if skipVerify {
		log.Warnf("⚠️  WARNING: TLS certificate verification is DISABLED via %s. "+
			"This is only for development/testing and leaves the client vulnerable to MITM attacks. "+
			"Never use this in production.", EnvTLSInsecureSkipVerify)
	}

	return skipVerify
}

// CreateConnection creates a gRPC client connection with the appropriate transport options.
// The component parameter specifies the WebSocket proxy component path (e.g., "/management", "/signal").
func CreateConnection(ctx context.Context, addr string, tlsEnabled bool, component string, extraOpts ...grpc.DialOption) (*grpc.ClientConn, error) {
	transportOption := grpc.WithTransportCredentials(insecure.NewCredentials())
	// for js, the outer websocket layer takes care of tls
	if tlsEnabled && runtime.GOOS != "js" {
		certPool, err := x509.SystemCertPool()
		if err != nil || certPool == nil {
			log.Debugf("System cert pool not available; falling back to embedded cert, error: %v", err)
			certPool = embeddedroots.Get()
		}

		tlsConfig := &tls.Config{
			RootCAs: certPool,
		}

		// Allow disabling certificate verification via environment variable.
		// WARNING: This is ONLY for development/testing.
		if insecureSkipVerifyEnabled() {
			tlsConfig.InsecureSkipVerify = true
		}

		transportOption = grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
	}

	connCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	opts := []grpc.DialOption{
		transportOption,
		WithCustomDialer(tlsEnabled, component),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
	}
	opts = append(opts, extraOpts...)

	conn, err := grpc.DialContext(connCtx, addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial context: %w", err)
	}

	return conn, nil
}
