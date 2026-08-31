package secret_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// certificateAndKey issues a self-signed certificate and returns both halves in
// PEM form, the shape a TLS secret is built from.
func certificateAndKey(t *testing.T, commonName string, hosts []string, validFor time.Duration) ([]byte, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(validFor),
		DNSNames:     hosts,
		IPAddresses:  []net.IP{net.ParseIP("10.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certificatePEM, keyPEM
}

func TestTLSEntriesUsesTheKeyNamesKubernetesExpects(t *testing.T) {
	certificate, key := certificateAndKey(t, "example.com", []string{"example.com"}, time.Hour)

	entries, err := secret.TLSEntries(certificate, key)
	if err != nil {
		t.Fatalf("TLSEntries() returned error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Key.String() != "tls.crt" || entries[1].Key.String() != "tls.key" {
		t.Errorf("keys = %s, %s, want tls.crt, tls.key", entries[0].Key, entries[1].Key)
	}
}

func TestAMismatchedCertificateAndKeyIsRejected(t *testing.T) {
	certificate, _ := certificateAndKey(t, "example.com", nil, time.Hour)
	_, otherKey := certificateAndKey(t, "other.example", nil, time.Hour)

	_, err := secret.TLSEntries(certificate, otherKey)

	if err == nil {
		t.Fatal("TLSEntries() accepted a key belonging to another certificate")
	}
	if !strings.Contains(err.Error(), "do not match") {
		t.Errorf("error = %q, want it to say the pair does not match", err)
	}
}

func TestSomethingThatIsNotACertificateIsRejected(t *testing.T) {
	_, key := certificateAndKey(t, "example.com", nil, time.Hour)

	if _, err := secret.TLSEntries([]byte("not a certificate"), key); err == nil {
		t.Error("TLSEntries() accepted a file that is not a certificate")
	}
}

func TestDescribeCertificateReportsWhatItCoversAndWhenItExpires(t *testing.T) {
	certificate, _ := certificateAndKey(t, "example.com", []string{"example.com", "www.example.com"}, 48*time.Hour)

	details, err := secret.DescribeCertificate(certificate)
	if err != nil {
		t.Fatalf("DescribeCertificate() returned error: %v", err)
	}

	if details.Subject != "example.com" {
		t.Errorf("subject = %q, want example.com", details.Subject)
	}
	if len(details.Hosts) != 3 {
		t.Errorf("hosts = %v, want both names and the address", details.Hosts)
	}
	if details.Expired() {
		t.Error("a certificate valid for two days was reported as expired")
	}
	if !strings.Contains(details.Summary(), "example.com") {
		t.Errorf("summary = %q, want it to name the subject", details.Summary())
	}
}

func TestAnExpiredCertificateIsReportedAsSuch(t *testing.T) {
	certificate, _ := certificateAndKey(t, "old.example", nil, -time.Hour)

	details, err := secret.DescribeCertificate(certificate)
	if err != nil {
		t.Fatalf("DescribeCertificate() returned error: %v", err)
	}

	if !details.Expired() {
		t.Error("an expired certificate was not reported as expired")
	}
}

func TestDescribeCertificateRejectsSomethingThatIsNotPEM(t *testing.T) {
	if _, err := secret.DescribeCertificate([]byte("nonsense")); err == nil {
		t.Error("DescribeCertificate() accepted input that is not PEM")
	}
}

func TestATLSSecretCarriesTheRightType(t *testing.T) {
	certificate, key := certificateAndKey(t, "example.com", nil, time.Hour)
	name, err := secret.NewName("web-tls")
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}
	entries, err := secret.TLSEntries(certificate, key)
	if err != nil {
		t.Fatalf("TLSEntries: %v", err)
	}
	draft := secret.Draft{Namespace: "web", Name: name, Type: secret.TypeTLS}
	for _, entry := range entries {
		draft.Entries.Set(entry)
	}

	built, err := secret.Build(draft)
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}

	if string(built.Type) != "kubernetes.io/tls" {
		t.Errorf("type = %q, want kubernetes.io/tls", built.Type)
	}
	if len(built.Data["tls.crt"]) == 0 || len(built.Data["tls.key"]) == 0 {
		t.Error("both halves of the pair should be in the secret")
	}
}
