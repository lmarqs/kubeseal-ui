package secret

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Keys a TLS secret holds, named as Kubernetes expects them.
const (
	TLSCertificateKey = "tls.crt"
	TLSPrivateKeyKey  = "tls.key"
)

// CertificateDetails is what a certificate says about itself, shown so the right
// file can be confirmed before it is sealed. It contains nothing secret.
type CertificateDetails struct {
	Subject string
	Hosts   []string
	Expires time.Time
}

// Expired reports whether the certificate is already past its validity.
func (d CertificateDetails) Expired() bool {
	return time.Now().After(d.Expires)
}

// Summary describes the certificate in one line.
func (d CertificateDetails) Summary() string {
	parts := []string{d.Subject}
	if len(d.Hosts) > 0 {
		parts = append(parts, "for "+strings.Join(d.Hosts, ", "))
	}
	parts = append(parts, "expires "+d.Expires.Format("2 Jan 2006"))

	return strings.Join(parts, " · ")
}

// DescribeCertificate reads what a PEM certificate says about itself.
func DescribeCertificate(certificate []byte) (CertificateDetails, error) {
	block, _ := pem.Decode(certificate)
	if block == nil {
		return CertificateDetails{}, errors.New("this is not a PEM certificate")
	}

	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertificateDetails{}, fmt.Errorf("reading the certificate: %w", err)
	}

	hosts := append([]string{}, parsed.DNSNames...)
	for _, address := range parsed.IPAddresses {
		hosts = append(hosts, address.String())
	}

	return CertificateDetails{
		Subject: parsed.Subject.CommonName,
		Hosts:   hosts,
		Expires: parsed.NotAfter,
	}, nil
}

// TLSEntries checks that a certificate and private key belong together and turns
// them into the two entries a TLS secret holds.
//
// The pair is verified here rather than after sealing, because a mismatch found
// later cannot be diagnosed without the private key.
func TLSEntries(certificate, key []byte) ([]Entry, error) {
	if _, err := tls.X509KeyPair(certificate, key); err != nil {
		return nil, fmt.Errorf("the certificate and key do not match: %w", err)
	}

	return []Entry{
		{Key: TLSCertificateKey, Value: certificate, Source: SourceFile},
		{Key: TLSPrivateKeyKey, Value: key, Source: SourceFile},
	}, nil
}
