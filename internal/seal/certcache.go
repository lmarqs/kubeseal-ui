package seal

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// ErrNotCached reports that no certificate has been stored for a controller.
var ErrNotCached = errors.New("certificate not cached")

// unsafeForFilenames matches everything that should not appear in a cache path.
var unsafeForFilenames = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// Cache stores controller certificates on disk, the way kubectl keeps per-cluster
// data under its cache directory. Certificates are public key material, so this
// is safe to persist; secret values never are.
//
// Entries are keyed by cluster and by controller, because one cluster can run
// several controllers with different key pairs.
type Cache struct {
	dir string
}

// DefaultCacheDir is where certificates are cached when no directory is given.
func DefaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locating user cache directory: %w", err)
	}
	return filepath.Join(base, "ksui", "certs"), nil
}

// NewCache stores certificates under dir.
func NewCache(dir string) *Cache {
	return &Cache{dir: dir}
}

// Load returns the certificate cached for a controller on a cluster, along with
// how long ago it was stored.
func (c *Cache) Load(cluster string, controller Controller) (Certificate, time.Duration, error) {
	path := c.pathFor(cluster, controller)

	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Certificate{}, 0, ErrNotCached
	}
	if err != nil {
		return Certificate{}, 0, fmt.Errorf("reading cached certificate %s: %w", path, err)
	}

	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return Certificate{}, 0, fmt.Errorf("reading cached certificate %s: %w", path, err)
	}

	certificate, err := ParseCertificate(pemBytes, OriginCache, path)
	if err != nil {
		return Certificate{}, 0, err
	}
	certificate.RetrievedAt = info.ModTime()

	return certificate, time.Since(info.ModTime()), nil
}

// Store writes a certificate to the cache, replacing any previous copy. The write
// is atomic so a cancelled run cannot leave a half-written certificate behind.
func (c *Cache) Store(cluster string, controller Controller, certificate Certificate) error {
	path := c.pathFor(cluster, controller)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	temporary, err := os.CreateTemp(filepath.Dir(path), ".cert-*")
	if err != nil {
		return fmt.Errorf("creating cache file: %w", err)
	}
	defer func() { _ = os.Remove(temporary.Name()) }()

	if _, err := temporary.Write(certificate.PEM); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("writing cache file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("writing cache file: %w", err)
	}

	if err := os.Rename(temporary.Name(), path); err != nil {
		return fmt.Errorf("replacing cached certificate %s: %w", path, err)
	}

	return nil
}

// pathFor derives the cache location of one controller's certificate.
func (c *Cache) pathFor(cluster string, controller Controller) string {
	return filepath.Join(
		c.dir,
		sanitize(cluster),
		fmt.Sprintf("%s-%s.pem", sanitize(controller.Namespace), sanitize(controller.Name)),
	)
}

func sanitize(value string) string {
	cleaned := unsafeForFilenames.ReplaceAllString(value, "_")
	if cleaned == "" {
		return "unknown"
	}
	return cleaned
}
