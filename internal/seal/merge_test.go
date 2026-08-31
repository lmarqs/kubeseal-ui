package seal_test

import (
	"crypto/rsa"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	corev1 "k8s.io/api/core/v1"

	"github.com/lmarqs/kubeseal-ui/internal/seal"
)

// sealedFile writes a sealed secret holding the given values and returns its path.
func sealedFile(t *testing.T, key *rsa.PrivateKey, scope ssv1alpha1.SealingScope, values map[string][]byte) string {
	t.Helper()

	rendered, err := seal.NewSealer(&key.PublicKey).
		Seal(secretWith("payments", "db-creds", values), scope, seal.FormatYAML)
	if err != nil {
		t.Fatalf("sealing the starting file: %v", err)
	}

	path := filepath.Join(t.TempDir(), "db-creds-sealed.yaml")
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		t.Fatalf("writing the starting file: %v", err)
	}

	return path
}

func TestReadingASealedSecretFileReportsWhatItHoldsWithoutDecryptingIt(t *testing.T) {
	key := controllerKey(t)
	path := sealedFile(t, key, ssv1alpha1.NamespaceWideScope, map[string][]byte{
		"DB_PASSWORD": []byte("hunter2"),
		"API_TOKEN":   []byte("t0ken"),
	})

	existing, err := seal.ReadExisting(path)
	if err != nil {
		t.Fatalf("ReadExisting() returned error: %v", err)
	}

	if existing.Name != "db-creds" || existing.Namespace != "payments" {
		t.Errorf("identity = %s/%s, want payments/db-creds", existing.Namespace, existing.Name)
	}
	if existing.Scope != ssv1alpha1.NamespaceWideScope {
		t.Errorf("scope = %v, want the scope recorded in the file", existing.Scope)
	}
	want := []string{"API_TOKEN", "DB_PASSWORD"}
	if len(existing.Keys) != len(want) {
		t.Fatalf("keys = %v, want %v", existing.Keys, want)
	}
	for i := range want {
		if existing.Keys[i] != want[i] {
			t.Errorf("key %d = %q, want %q", i, existing.Keys[i], want[i])
		}
	}
	if !existing.Has("DB_PASSWORD") || existing.Has("ABSENT") {
		t.Error("Has() does not agree with the keys reported")
	}
}

func TestReadingSomethingThatIsNotASealedSecretIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.yaml")
	if err := os.WriteFile(path, []byte("apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n"), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	_, err := seal.ReadExisting(path)

	if !errors.Is(err, seal.ErrNotASealedSecret) {
		t.Fatalf("error = %v, want ErrNotASealedSecret", err)
	}
}

func TestReadingAMissingFileSaysSo(t *testing.T) {
	_, err := seal.ReadExisting(filepath.Join(t.TempDir(), "absent.yaml"))

	if err == nil {
		t.Error("ReadExisting() accepted a file that is not there")
	}
}

func TestMergingKeepsTheValuesAlreadySealedAndAddsTheNewOne(t *testing.T) {
	key := controllerKey(t)
	path := sealedFile(t, key, ssv1alpha1.StrictScope, map[string][]byte{"DB_PASSWORD": []byte("hunter2")})
	existing, err := seal.ReadExisting(path)
	if err != nil {
		t.Fatalf("ReadExisting: %v", err)
	}
	incoming := secretWith("payments", "db-creds", map[string][]byte{"API_TOKEN": []byte("t0ken")})

	result, err := seal.NewSealer(&key.PublicKey).Merge(existing, incoming, nil, seal.FormatYAML)
	if err != nil {
		t.Fatalf("Merge() returned error: %v", err)
	}

	if len(result.Added) != 1 || result.Added[0] != "API_TOKEN" {
		t.Errorf("added = %v, want just API_TOKEN", result.Added)
	}
	if len(result.Replaced) != 0 || len(result.Removed) != 0 {
		t.Errorf("nothing should have been replaced or removed: %+v", result)
	}

	// The point of merging: both the untouched value and the new one must decrypt.
	unsealed := unseal(t, parseSealed(t, result.Sealed), key)
	if got := string(unsealed.Data["DB_PASSWORD"]); got != "hunter2" {
		t.Errorf("DB_PASSWORD = %q, want the value that was already sealed", got)
	}
	if got := string(unsealed.Data["API_TOKEN"]); got != "t0ken" {
		t.Errorf("API_TOKEN = %q, want the newly added value", got)
	}
}

func TestMergingReplacesTheValueOfAKeyAlreadyThere(t *testing.T) {
	key := controllerKey(t)
	path := sealedFile(t, key, ssv1alpha1.StrictScope, map[string][]byte{"DB_PASSWORD": []byte("old")})
	existing, err := seal.ReadExisting(path)
	if err != nil {
		t.Fatalf("ReadExisting: %v", err)
	}
	incoming := secretWith("payments", "db-creds", map[string][]byte{"DB_PASSWORD": []byte("rotated")})

	result, err := seal.NewSealer(&key.PublicKey).Merge(existing, incoming, nil, seal.FormatYAML)
	if err != nil {
		t.Fatalf("Merge() returned error: %v", err)
	}

	if len(result.Replaced) != 1 || result.Replaced[0] != "DB_PASSWORD" {
		t.Errorf("replaced = %v, want DB_PASSWORD", result.Replaced)
	}
	if got := string(unseal(t, parseSealed(t, result.Sealed), key).Data["DB_PASSWORD"]); got != "rotated" {
		t.Errorf("DB_PASSWORD = %q, want the replacement value", got)
	}
}

func TestMergingRemovesAKeyWithoutTouchingTheOthers(t *testing.T) {
	key := controllerKey(t)
	path := sealedFile(t, key, ssv1alpha1.StrictScope, map[string][]byte{
		"DB_PASSWORD": []byte("hunter2"),
		"OLD_TOKEN":   []byte("stale"),
	})
	existing, err := seal.ReadExisting(path)
	if err != nil {
		t.Fatalf("ReadExisting: %v", err)
	}

	result, err := seal.NewSealer(&key.PublicKey).
		Merge(existing, nil, []string{"OLD_TOKEN"}, seal.FormatYAML)
	if err != nil {
		t.Fatalf("Merge() returned error: %v", err)
	}

	if len(result.Removed) != 1 || result.Removed[0] != "OLD_TOKEN" {
		t.Errorf("removed = %v, want OLD_TOKEN", result.Removed)
	}
	unsealed := unseal(t, parseSealed(t, result.Sealed), key)
	if _, found := unsealed.Data["OLD_TOKEN"]; found {
		t.Error("the removed key is still there")
	}
	if got := string(unsealed.Data["DB_PASSWORD"]); got != "hunter2" {
		t.Errorf("DB_PASSWORD = %q, want it left alone", got)
	}
}

func TestRemovingEveryKeyIsRefused(t *testing.T) {
	key := controllerKey(t)
	path := sealedFile(t, key, ssv1alpha1.StrictScope, map[string][]byte{"ONLY": []byte("value")})
	existing, err := seal.ReadExisting(path)
	if err != nil {
		t.Fatalf("ReadExisting: %v", err)
	}

	_, err = seal.NewSealer(&key.PublicKey).Merge(existing, nil, []string{"ONLY"}, seal.FormatYAML)

	if !errors.Is(err, seal.ErrWouldEmpty) {
		t.Fatalf("error = %v, want ErrWouldEmpty", err)
	}
}

func TestMergingUsesTheScopeAndIdentityRecordedInTheFile(t *testing.T) {
	key := controllerKey(t)
	// A namespace-wide file, merged into with a secret naming something else.
	path := sealedFile(t, key, ssv1alpha1.NamespaceWideScope, map[string][]byte{"DB_PASSWORD": []byte("hunter2")})
	existing, err := seal.ReadExisting(path)
	if err != nil {
		t.Fatalf("ReadExisting: %v", err)
	}
	incoming := secretWith("elsewhere", "different-name", map[string][]byte{"API_TOKEN": []byte("t0ken")})

	result, err := seal.NewSealer(&key.PublicKey).Merge(existing, incoming, nil, seal.FormatYAML)
	if err != nil {
		t.Fatalf("Merge() returned error: %v", err)
	}

	merged := parseSealed(t, result.Sealed)
	if merged.Name != "db-creds" || merged.Namespace != "payments" {
		t.Errorf("identity = %s/%s, want the file's own", merged.Namespace, merged.Name)
	}
	if merged.Scope() != ssv1alpha1.NamespaceWideScope {
		t.Errorf("scope = %v, want the file's own", merged.Scope())
	}
	// Both values must still decrypt, which only holds if the label matched.
	unsealed := unseal(t, merged, key)
	if string(unsealed.Data["DB_PASSWORD"]) != "hunter2" || string(unsealed.Data["API_TOKEN"]) != "t0ken" {
		t.Error("a value stopped decrypting after the merge")
	}
}

func TestMergedOutputStillLeaksNothing(t *testing.T) {
	key := controllerKey(t)
	path := sealedFile(t, key, ssv1alpha1.StrictScope, map[string][]byte{"DB_PASSWORD": []byte("hunter2")})
	existing, err := seal.ReadExisting(path)
	if err != nil {
		t.Fatalf("ReadExisting: %v", err)
	}
	incoming := secretWith("payments", "db-creds", map[string][]byte{"API_TOKEN": []byte("t0ken")})

	result, err := seal.NewSealer(&key.PublicKey).Merge(existing, incoming, nil, seal.FormatYAML)
	if err != nil {
		t.Fatalf("Merge() returned error: %v", err)
	}

	for _, plaintext := range []string{"hunter2", "t0ken"} {
		if strings.Contains(string(result.Sealed), plaintext) {
			t.Errorf("the merged file leaks %q:\n%s", plaintext, result.Sealed)
		}
	}
}

func TestWriteFileReplacesTheContentsInOneStep(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "sealed.yaml")

	if err := seal.WriteFile(path, []byte("first")); err != nil {
		t.Fatalf("WriteFile() returned error: %v", err)
	}
	if err := seal.WriteFile(path, []byte("second")); err != nil {
		t.Fatalf("second WriteFile() returned error: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if string(contents) != "second" {
		t.Errorf("contents = %q, want the second write", contents)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Errorf("permissions = %o, want 600", permissions)
	}
}

func TestMergingWithoutACertificateFails(t *testing.T) {
	key := controllerKey(t)
	path := sealedFile(t, key, ssv1alpha1.StrictScope, map[string][]byte{"a": []byte("1")})
	existing, err := seal.ReadExisting(path)
	if err != nil {
		t.Fatalf("ReadExisting: %v", err)
	}

	_, err = seal.NewSealer(nil).Merge(existing, &corev1.Secret{}, nil, seal.FormatYAML)

	if err == nil {
		t.Error("Merge() succeeded without a certificate")
	}
}
