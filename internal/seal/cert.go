package seal

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/bitnami/sealed-secrets/pkg/kubeseal"
)

// DefaultFetchTimeout bounds how long a certificate fetch may take before the
// wizard offers the cached copy instead.
const DefaultFetchTimeout = 10 * time.Second

// Origin records where a sealing certificate came from, so the interface can tell
// the user what they are sealing against.
type Origin string

// Origins a certificate can have.
const (
	OriginController Origin = "controller"
	OriginCache      Origin = "cache"
	OriginFile       Origin = "file"
)

// Certificate is a sealing certificate ready to encrypt with.
type Certificate struct {
	PublicKey *rsa.PublicKey
	// PEM is the certificate as served, kept so it can be cached or written out.
	PEM []byte
	// Origin and Source together describe where this copy came from.
	Origin Origin
	Source string
	// RetrievedAt is when this copy was obtained.
	RetrievedAt time.Time
	// FetchError is set when the controller could not be reached and this copy
	// came from the cache instead. Sealing still works; validation does not.
	FetchError error
}

// Stale reports whether this certificate was served from the cache after the
// controller could not be reached.
func (c Certificate) Stale() bool { return c.FetchError != nil }

// ParseCertificate reads an RSA public key from a PEM certificate. Certificates
// that have expired are rejected, because the controller would refuse them too.
func ParseCertificate(pemBytes []byte, origin Origin, source string) (Certificate, error) {
	publicKey, err := kubeseal.ParseKey(bytes.NewReader(pemBytes))
	if err != nil {
		return Certificate{}, fmt.Errorf("reading certificate from %s: %w", source, err)
	}

	return Certificate{
		PublicKey:   publicKey,
		PEM:         pemBytes,
		Origin:      origin,
		Source:      source,
		RetrievedAt: time.Now(),
	}, nil
}

// LoadCertificate reads a certificate from a local file or URL. It never contacts
// the cluster, which is what allows sealing with no cluster access at all.
func LoadCertificate(ctx context.Context, pathOrURL string) (Certificate, error) {
	if pathOrURL == "" {
		return Certificate{}, errors.New("no certificate path given")
	}

	return readCertificate(ctx, nil, Controller{}, pathOrURL, OriginFile, pathOrURL)
}

// FetchCertificate retrieves the certificate a controller serves.
func FetchCertificate(
	ctx context.Context,
	clientConfig kubeseal.ClientConfig,
	controller Controller,
) (Certificate, error) {
	if clientConfig == nil {
		return Certificate{}, errors.New("no cluster connection to fetch a certificate from")
	}

	return readCertificate(ctx, clientConfig, controller, "", OriginController, controller.String())
}

func readCertificate(
	ctx context.Context,
	clientConfig kubeseal.ClientConfig,
	controller Controller,
	pathOrURL string,
	origin Origin,
	source string,
) (Certificate, error) {
	reader, err := kubeseal.OpenCert(ctx, clientConfig, controller.Namespace, controller.Name, pathOrURL)
	if err != nil {
		return Certificate{}, fmt.Errorf("opening certificate from %s: %w", source, err)
	}
	defer func() { _ = reader.Close() }()

	pemBytes, err := io.ReadAll(reader)
	if err != nil {
		return Certificate{}, fmt.Errorf("reading certificate from %s: %w", source, err)
	}

	return ParseCertificate(pemBytes, origin, source)
}
