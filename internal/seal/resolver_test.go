package seal_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bitnami/sealed-secrets/pkg/kubeseal"
	"k8s.io/client-go/rest"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
	"github.com/lmarqs/kubeseal-ui/internal/seal"
)

// fetcherReturning builds a Fetch stub serving the given PEM, counting calls.
func fetcherReturning(t *testing.T, pemBytes []byte, calls *int) func(
	context.Context, kubeseal.ClientConfig, kube.Controller) (seal.Certificate, error) {
	t.Helper()
	return func(context.Context, kubeseal.ClientConfig, kube.Controller) (seal.Certificate, error) {
		*calls++
		return seal.ParseCertificate(pemBytes, seal.OriginController, "controller")
	}
}

// unreachableController stands in for a controller that cannot be contacted.
func unreachableController(err error) func(
	context.Context, kubeseal.ClientConfig, kube.Controller) (seal.Certificate, error) {
	return func(context.Context, kubeseal.ClientConfig, kube.Controller) (seal.Certificate, error) {
		return seal.Certificate{}, err
	}
}

// stubConfig is a non-nil ClientConfig standing in for a reachable cluster; the
// stubbed Fetch never actually uses it.
type stubConfig struct{}

func (stubConfig) ClientConfig() (*rest.Config, error) { return &rest.Config{}, nil }
func (stubConfig) Namespace() (string, bool, error)    { return "default", false, nil }

func TestAnExplicitCertificateFileIsUsedWithoutContactingTheController(t *testing.T) {
	pemBytes, _ := certificatePEM(t)
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}
	calls := 0
	resolver := &seal.Resolver{
		CertPath: path,
		Fetch:    fetcherReturning(t, pemBytes, &calls),
	}

	certificate, err := resolver.Resolve(context.Background(), kube.DefaultController())
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}

	if certificate.Origin != seal.OriginFile {
		t.Errorf("origin = %s, want file", certificate.Origin)
	}
	if calls != 0 {
		t.Errorf("controller was contacted %d times, want 0", calls)
	}
}

func TestTheControllerIsAskedWhenNothingIsCached(t *testing.T) {
	pemBytes, _ := certificatePEM(t)
	calls := 0
	resolver := &seal.Resolver{
		Cache:        seal.NewCache(t.TempDir()),
		Cluster:      "https://prod.example",
		ClientConfig: stubConfig{},
		Fetch:        fetcherReturning(t, pemBytes, &calls),
	}

	certificate, err := resolver.Resolve(context.Background(), kube.DefaultController())
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}

	if certificate.Origin != seal.OriginController {
		t.Errorf("origin = %s, want controller", certificate.Origin)
	}
	if calls != 1 {
		t.Errorf("controller was contacted %d times, want 1", calls)
	}
}

func TestAFetchedCertificateIsCachedForTheNextRun(t *testing.T) {
	pemBytes, _ := certificatePEM(t)
	calls := 0
	cache := seal.NewCache(t.TempDir())
	resolver := &seal.Resolver{
		Cache:        cache,
		Cluster:      "https://prod.example",
		ClientConfig: stubConfig{},
		Fetch:        fetcherReturning(t, pemBytes, &calls),
	}

	if _, err := resolver.Resolve(context.Background(), kube.DefaultController()); err != nil {
		t.Fatalf("first Resolve() returned error: %v", err)
	}
	second, err := resolver.Resolve(context.Background(), kube.DefaultController())
	if err != nil {
		t.Fatalf("second Resolve() returned error: %v", err)
	}

	if calls != 1 {
		t.Errorf("controller was contacted %d times, want 1", calls)
	}
	if second.Origin != seal.OriginCache {
		t.Errorf("origin = %s, want cache", second.Origin)
	}
}

func TestAnExpiredCacheEntryTriggersAFreshFetch(t *testing.T) {
	pemBytes, _ := certificatePEM(t)
	calls := 0
	cache := seal.NewCache(t.TempDir())
	storeCertificate(t, cache, "https://prod.example", kube.DefaultController(), pemBytes)
	resolver := &seal.Resolver{
		Cache:        cache,
		Cluster:      "https://prod.example",
		TTL:          time.Nanosecond,
		ClientConfig: stubConfig{},
		Fetch:        fetcherReturning(t, pemBytes, &calls),
	}

	certificate, err := resolver.Resolve(context.Background(), kube.DefaultController())
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}

	if calls != 1 {
		t.Errorf("controller was contacted %d times, want 1", calls)
	}
	if certificate.Origin != seal.OriginController {
		t.Errorf("origin = %s, want controller", certificate.Origin)
	}
}

func TestAnUnreachableControllerFallsBackToTheCacheAndSaysSo(t *testing.T) {
	pemBytes, _ := certificatePEM(t)
	cache := seal.NewCache(t.TempDir())
	storeCertificate(t, cache, "https://prod.example", kube.DefaultController(), pemBytes)
	unreachable := errors.New("dial tcp: connection refused")
	resolver := &seal.Resolver{
		Cache:        cache,
		Cluster:      "https://prod.example",
		TTL:          time.Nanosecond,
		ClientConfig: stubConfig{},
		Fetch:        unreachableController(unreachable),
	}

	certificate, err := resolver.Resolve(context.Background(), kube.DefaultController())
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}

	if !certificate.Stale() {
		t.Error("certificate does not report that it came from the cache after a failed fetch")
	}
	if !errors.Is(certificate.FetchError, unreachable) {
		t.Errorf("FetchError = %v, want the fetch failure", certificate.FetchError)
	}
	if certificate.PublicKey == nil {
		t.Error("no usable key was returned")
	}
}

func TestAnUnreachableControllerWithNoCacheFails(t *testing.T) {
	unreachable := errors.New("dial tcp: connection refused")
	resolver := &seal.Resolver{
		Cache:        seal.NewCache(t.TempDir()),
		Cluster:      "https://prod.example",
		ClientConfig: stubConfig{},
		Fetch:        unreachableController(unreachable),
	}

	_, err := resolver.Resolve(context.Background(), kube.DefaultController())

	if !errors.Is(err, unreachable) {
		t.Fatalf("error = %v, want the fetch failure", err)
	}
}

func TestResolvingWithoutACacheOrClusterConnectionFails(t *testing.T) {
	resolver := &seal.Resolver{}

	_, err := resolver.Resolve(context.Background(), kube.DefaultController())

	if err == nil {
		t.Fatal("Resolve() succeeded with nothing to resolve from")
	}
}
