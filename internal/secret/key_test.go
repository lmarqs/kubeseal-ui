package secret_test

import (
	"strings"
	"testing"

	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

func TestNewKeyAcceptsKeysKubernetesAllows(t *testing.T) {
	for _, value := range []string{"DB_PASSWORD", "ca.crt", "tls-key", "a", "0", "config.json"} {
		if _, err := secret.NewKey(value); err != nil {
			t.Errorf("NewKey(%q) returned error: %v", value, err)
		}
	}
}

func TestNewKeyRejectsKeysKubernetesWouldReject(t *testing.T) {
	for _, value := range []string{"", "has space", "slash/key", "dollar$", "..", "."} {
		if _, err := secret.NewKey(value); err == nil {
			t.Errorf("NewKey(%q) accepted an invalid key", value)
		}
	}
}

func TestNewKeyErrorNamesTheOffendingKey(t *testing.T) {
	_, err := secret.NewKey("bad key")

	if err == nil {
		t.Fatal("NewKey() accepted an invalid key")
	}
	if !strings.Contains(err.Error(), "bad key") {
		t.Errorf("error %q does not mention the rejected key", err)
	}
}

func TestNewNameAcceptsDNSSubdomains(t *testing.T) {
	for _, value := range []string{"db-creds", "a", "my.secret.name", strings.Repeat("a", 253)} {
		if _, err := secret.NewName(value); err != nil {
			t.Errorf("NewName(%q) returned error: %v", value, err)
		}
	}
}

func TestNewNameRejectsInvalidSecretNames(t *testing.T) {
	for _, value := range []string{"", "UPPER", "-leading", "trailing-", "under_score", strings.Repeat("a", 254)} {
		if _, err := secret.NewName(value); err == nil {
			t.Errorf("NewName(%q) accepted an invalid name", value)
		}
	}
}
