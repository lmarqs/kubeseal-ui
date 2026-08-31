package seal_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bitnami/sealed-secrets/pkg/crypto"

	"github.com/lmarqs/kubeseal-ui/internal/seal"
)

// certificatePEM returns a controller-style certificate and its private key.
func certificatePEM(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	privateKey, certificate, err := crypto.GeneratePrivateKeyAndCert(2048, time.Hour, "ksui-test")
	if err != nil {
		t.Fatalf("generating certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), privateKey
}

func expiredCertificatePEM(t *testing.T) []byte {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	certificate, err := crypto.SignKeyWithNotBefore(
		rand.Reader, privateKey, time.Now().Add(-2*time.Hour), time.Hour, "expired")
	if err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
}

func TestParseCertificateExtractsThePublicKey(t *testing.T) {
	pemBytes, privateKey := certificatePEM(t)

	certificate, err := seal.ParseCertificate(pemBytes, seal.OriginFile, "test.pem")
	if err != nil {
		t.Fatalf("ParseCertificate() returned error: %v", err)
	}

	if certificate.PublicKey.N.Cmp(privateKey.N) != 0 {
		t.Error("parsed public key does not match the generated key")
	}
	if certificate.Origin != seal.OriginFile || certificate.Source != "test.pem" {
		t.Errorf("provenance = %s %s, want file test.pem", certificate.Origin, certificate.Source)
	}
}

func TestParseCertificateRejectsAnExpiredCertificate(t *testing.T) {
	_, err := seal.ParseCertificate(expiredCertificatePEM(t), seal.OriginFile, "expired.pem")

	if err == nil {
		t.Fatal("ParseCertificate() accepted an expired certificate")
	}
}

func TestParseCertificateErrorNamesTheSource(t *testing.T) {
	_, err := seal.ParseCertificate([]byte("not a certificate"), seal.OriginFile, "/tmp/broken.pem")

	if err == nil {
		t.Fatal("ParseCertificate() accepted invalid input")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("/tmp/broken.pem")) {
		t.Errorf("error %q does not name the source", err)
	}
}

func TestLoadCertificateReadsALocalFileWithoutClusterAccess(t *testing.T) {
	pemBytes, _ := certificatePEM(t)
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}

	certificate, err := seal.LoadCertificate(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadCertificate() returned error: %v", err)
	}

	if certificate.Origin != seal.OriginFile {
		t.Errorf("origin = %s, want file", certificate.Origin)
	}
	if certificate.PublicKey == nil {
		t.Error("no public key was parsed")
	}
}

func TestLoadCertificateRequiresAPath(t *testing.T) {
	if _, err := seal.LoadCertificate(context.Background(), ""); err == nil {
		t.Error("LoadCertificate() accepted an empty path")
	}
}

func TestFetchCertificateWithoutAClusterConnectionFails(t *testing.T) {
	_, err := seal.FetchCertificate(context.Background(), nil, seal.DefaultController())

	if err == nil {
		t.Error("FetchCertificate() succeeded without a cluster connection")
	}
}

func TestCachedCertificateIsReturnedWithItsAge(t *testing.T) {
	pemBytes, _ := certificatePEM(t)
	cache := seal.NewCache(t.TempDir())
	stored, err := seal.ParseCertificate(pemBytes, seal.OriginController, "kube-system/sealed-secrets-controller")
	if err != nil {
		t.Fatalf("ParseCertificate() returned error: %v", err)
	}

	if err := cache.Store("https://prod.example", seal.DefaultController(), stored); err != nil {
		t.Fatalf("Store() returned error: %v", err)
	}
	loaded, age, err := cache.Load("https://prod.example", seal.DefaultController())
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if !bytes.Equal(loaded.PEM, pemBytes) {
		t.Error("cached certificate differs from the stored one")
	}
	if loaded.Origin != seal.OriginCache {
		t.Errorf("origin = %s, want cache", loaded.Origin)
	}
	if age < 0 || age > time.Minute {
		t.Errorf("age = %v, want a small positive duration", age)
	}
}

func TestLoadReportsErrNotCachedWhenNothingWasStored(t *testing.T) {
	cache := seal.NewCache(t.TempDir())

	_, _, err := cache.Load("https://prod.example", seal.DefaultController())

	if !errors.Is(err, seal.ErrNotCached) {
		t.Fatalf("error = %v, want ErrNotCached", err)
	}
}

func TestEachControllerOnAClusterIsCachedSeparately(t *testing.T) {
	cache := seal.NewCache(t.TempDir())
	first, _ := certificatePEM(t)
	second, _ := certificatePEM(t)
	teamA := seal.Controller{Namespace: "team-a", Name: "sealed-secrets"}
	teamB := seal.Controller{Namespace: "team-b", Name: "sealed-secrets"}

	storeCertificate(t, cache, "https://prod.example", teamA, first)
	storeCertificate(t, cache, "https://prod.example", teamB, second)

	loadedA, _, err := cache.Load("https://prod.example", teamA)
	if err != nil {
		t.Fatalf("Load(team-a) returned error: %v", err)
	}
	loadedB, _, err := cache.Load("https://prod.example", teamB)
	if err != nil {
		t.Fatalf("Load(team-b) returned error: %v", err)
	}

	if !bytes.Equal(loadedA.PEM, first) || !bytes.Equal(loadedB.PEM, second) {
		t.Error("controllers on the same cluster share a cache entry")
	}
}

func TestTheSameControllerNameOnDifferentClustersIsCachedSeparately(t *testing.T) {
	cache := seal.NewCache(t.TempDir())
	production, _ := certificatePEM(t)
	staging, _ := certificatePEM(t)

	storeCertificate(t, cache, "https://prod.example", seal.DefaultController(), production)
	storeCertificate(t, cache, "https://staging.example", seal.DefaultController(), staging)

	loaded, _, err := cache.Load("https://prod.example", seal.DefaultController())
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if !bytes.Equal(loaded.PEM, production) {
		t.Error("clusters share a cache entry")
	}
}

func TestStoreReplacesAPreviouslyCachedCertificate(t *testing.T) {
	cache := seal.NewCache(t.TempDir())
	first, _ := certificatePEM(t)
	rotated, _ := certificatePEM(t)

	storeCertificate(t, cache, "https://prod.example", seal.DefaultController(), first)
	storeCertificate(t, cache, "https://prod.example", seal.DefaultController(), rotated)

	loaded, _, err := cache.Load("https://prod.example", seal.DefaultController())
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if !bytes.Equal(loaded.PEM, rotated) {
		t.Error("Store() did not replace the earlier certificate")
	}
}

func storeCertificate(t *testing.T, cache *seal.Cache, cluster string, controller seal.Controller, pemBytes []byte) {
	t.Helper()
	certificate, err := seal.ParseCertificate(pemBytes, seal.OriginController, controller.String())
	if err != nil {
		t.Fatalf("ParseCertificate() returned error: %v", err)
	}
	if err := cache.Store(cluster, controller, certificate); err != nil {
		t.Fatalf("Store() returned error: %v", err)
	}
}
