package seal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bitnami/sealed-secrets/pkg/kubeseal"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
)

// DefaultCacheTTL is how long a cached certificate is reused before the
// controller is asked again.
const DefaultCacheTTL = time.Hour

// Resolver decides which certificate to seal with.
//
// A certificate given explicitly wins. Otherwise a cached copy is reused while it
// is still fresh, and the controller is asked when it is not. If the controller
// cannot be reached, an expired cached copy is used rather than failing: the
// controller keeps earlier private keys through rotation, so a slightly old
// certificate still produces a decryptable secret. That fallback is always
// reported so it can be surfaced instead of hidden.
type Resolver struct {
	// CertPath is a certificate file or URL. When set, nothing else is consulted.
	CertPath string
	// Cache may be nil to disable caching entirely.
	Cache *Cache
	// TTL defaults to DefaultCacheTTL.
	TTL time.Duration
	// Cluster identifies the cluster the certificate belongs to, for cache keying.
	Cluster string
	// ClientConfig is how the controller is reached; nil means offline.
	ClientConfig kubeseal.ClientConfig
	// Fetch defaults to FetchCertificate and exists so tests can substitute it.
	Fetch func(context.Context, kubeseal.ClientConfig, kube.Controller) (Certificate, error)
}

// Resolve returns the certificate to seal with.
func (r *Resolver) Resolve(ctx context.Context, controller kube.Controller) (Certificate, error) {
	if r.CertPath != "" {
		return LoadCertificate(ctx, r.CertPath)
	}

	cached, age, cacheErr := r.load(controller)
	if cacheErr == nil && age < r.ttl() {
		return cached, nil
	}

	fetched, fetchErr := r.fetch(ctx, controller)
	if fetchErr == nil {
		r.store(controller, fetched)
		return fetched, nil
	}

	if cacheErr == nil {
		cached.FetchError = fetchErr
		return cached, nil
	}

	return Certificate{}, fetchErr
}

func (r *Resolver) load(controller kube.Controller) (Certificate, time.Duration, error) {
	if r.Cache == nil {
		return Certificate{}, 0, ErrNotCached
	}
	return r.Cache.Load(r.Cluster, controller)
}

// store records a freshly fetched certificate. A cache that cannot be written is
// not worth failing a seal over, so the error is deliberately dropped.
func (r *Resolver) store(controller kube.Controller, certificate Certificate) {
	if r.Cache == nil {
		return
	}
	_ = r.Cache.Store(r.Cluster, controller, certificate)
}

func (r *Resolver) fetch(ctx context.Context, controller kube.Controller) (Certificate, error) {
	fetch := r.Fetch
	if fetch == nil {
		fetch = FetchCertificate
	}
	if r.ClientConfig == nil {
		return Certificate{}, fmt.Errorf(
			"no certificate available for %s: %w", controller, errors.New("no cluster connection"))
	}

	return fetch(ctx, r.ClientConfig, controller)
}

func (r *Resolver) ttl() time.Duration {
	if r.TTL <= 0 {
		return DefaultCacheTTL
	}
	return r.TTL
}
