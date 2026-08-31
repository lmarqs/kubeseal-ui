package seal_test

import (
	"bytes"
	"crypto/rsa"
	"testing"
	"time"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/bitnami/sealed-secrets/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/yaml"

	"github.com/lmarqs/kubeseal-ui/internal/seal"
)

// controllerKey stands in for a sealed-secrets controller's key pair.
func controllerKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privateKey, _, err := crypto.GeneratePrivateKeyAndCert(2048, time.Hour, "ksui-test")
	if err != nil {
		t.Fatalf("generating controller key: %v", err)
	}
	return privateKey
}

func secretWith(namespace, name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Type:       corev1.SecretTypeOpaque,
		Data:       data,
	}
}

func parseSealed(t *testing.T, rendered []byte) *ssv1alpha1.SealedSecret {
	t.Helper()
	var sealed ssv1alpha1.SealedSecret
	if err := yaml.Unmarshal(rendered, &sealed); err != nil {
		t.Fatalf("parsing sealed secret: %v\n%s", err, rendered)
	}
	return &sealed
}

func unseal(t *testing.T, sealed *ssv1alpha1.SealedSecret, key *rsa.PrivateKey) *corev1.Secret {
	t.Helper()
	unsealed, err := sealed.Unseal(scheme.Codecs, map[string]*rsa.PrivateKey{"controller": key})
	if err != nil {
		t.Fatalf("controller could not decrypt the sealed secret: %v", err)
	}
	return unsealed
}

func TestTheControllerKeyCanDecryptASealedSecret(t *testing.T) {
	key := controllerKey(t)
	built := secretWith("payments", "db-creds", map[string][]byte{
		"DB_PASSWORD": []byte("hunter2"),
		"ca.crt":      []byte("-----BEGIN CERTIFICATE-----"),
	})

	rendered, err := seal.NewSealer(&key.PublicKey).Seal(built, ssv1alpha1.StrictScope, seal.FormatYAML)
	if err != nil {
		t.Fatalf("Seal() returned error: %v", err)
	}

	unsealed := unseal(t, parseSealed(t, rendered), key)
	if got := string(unsealed.Data["DB_PASSWORD"]); got != "hunter2" {
		t.Errorf("DB_PASSWORD = %q, want %q", got, "hunter2")
	}
	if got := string(unsealed.Data["ca.crt"]); got != "-----BEGIN CERTIFICATE-----" {
		t.Errorf("ca.crt = %q, want the certificate contents", got)
	}
}

func TestSealedOutputNeverContainsThePlaintext(t *testing.T) {
	key := controllerKey(t)
	built := secretWith("payments", "db-creds", map[string][]byte{"DB_PASSWORD": []byte("hunter2")})

	rendered, err := seal.NewSealer(&key.PublicKey).Seal(built, ssv1alpha1.StrictScope, seal.FormatYAML)
	if err != nil {
		t.Fatalf("Seal() returned error: %v", err)
	}

	if bytes.Contains(rendered, []byte("hunter2")) {
		t.Errorf("sealed output leaks the plaintext value:\n%s", rendered)
	}
}

func TestSealedSecretKeepsTheNameNamespaceAndTypeOfTheSecret(t *testing.T) {
	key := controllerKey(t)
	built := secretWith("payments", "db-creds", map[string][]byte{"a": []byte("1")})

	rendered, err := seal.NewSealer(&key.PublicKey).Seal(built, ssv1alpha1.StrictScope, seal.FormatYAML)
	if err != nil {
		t.Fatalf("Seal() returned error: %v", err)
	}

	sealed := parseSealed(t, rendered)
	if sealed.Kind != "SealedSecret" || sealed.APIVersion != "bitnami.com/v1alpha1" {
		t.Errorf("type meta = %s %s, want bitnami.com/v1alpha1 SealedSecret", sealed.APIVersion, sealed.Kind)
	}
	if sealed.Name != "db-creds" || sealed.Namespace != "payments" {
		t.Errorf("object meta = %s/%s, want payments/db-creds", sealed.Namespace, sealed.Name)
	}
	if sealed.Spec.Template.Type != corev1.SecretTypeOpaque {
		t.Errorf("template type = %q, want %q", sealed.Spec.Template.Type, corev1.SecretTypeOpaque)
	}
}

func TestStrictScopeSetsNoScopeAnnotations(t *testing.T) {
	key := controllerKey(t)
	built := secretWith("payments", "db-creds", map[string][]byte{"a": []byte("1")})

	rendered, err := seal.NewSealer(&key.PublicKey).Seal(built, ssv1alpha1.StrictScope, seal.FormatYAML)
	if err != nil {
		t.Fatalf("Seal() returned error: %v", err)
	}

	sealed := parseSealed(t, rendered)
	if scope := sealed.Scope(); scope != ssv1alpha1.StrictScope {
		t.Errorf("scope = %v, want StrictScope", scope)
	}
}

func TestNamespaceWideScopeSurvivesRenamingTheSecret(t *testing.T) {
	key := controllerKey(t)
	built := secretWith("payments", "db-creds", map[string][]byte{"a": []byte("1")})

	rendered, err := seal.NewSealer(&key.PublicKey).Seal(built, ssv1alpha1.NamespaceWideScope, seal.FormatYAML)
	if err != nil {
		t.Fatalf("Seal() returned error: %v", err)
	}

	sealed := parseSealed(t, rendered)
	if scope := sealed.Scope(); scope != ssv1alpha1.NamespaceWideScope {
		t.Fatalf("scope = %v, want NamespaceWideScope", scope)
	}

	// A namespace-wide secret is bound to the namespace only, so renaming it must
	// not stop the controller from decrypting it.
	sealed.Name = "renamed"
	if got := string(unseal(t, sealed, key).Data["a"]); got != "1" {
		t.Errorf("a = %q, want %q after renaming", got, "1")
	}
}

func TestClusterWideScopeSurvivesMovingToAnotherNamespace(t *testing.T) {
	key := controllerKey(t)
	built := secretWith("payments", "db-creds", map[string][]byte{"a": []byte("1")})

	rendered, err := seal.NewSealer(&key.PublicKey).Seal(built, ssv1alpha1.ClusterWideScope, seal.FormatYAML)
	if err != nil {
		t.Fatalf("Seal() returned error: %v", err)
	}

	sealed := parseSealed(t, rendered)
	sealed.Namespace = "elsewhere"
	if got := string(unseal(t, sealed, key).Data["a"]); got != "1" {
		t.Errorf("a = %q, want %q after moving namespace", got, "1")
	}
}

func TestStrictlyScopedSecretCannotBeDecryptedUnderAnotherName(t *testing.T) {
	key := controllerKey(t)
	built := secretWith("payments", "db-creds", map[string][]byte{"a": []byte("1")})

	rendered, err := seal.NewSealer(&key.PublicKey).Seal(built, ssv1alpha1.StrictScope, seal.FormatYAML)
	if err != nil {
		t.Fatalf("Seal() returned error: %v", err)
	}

	sealed := parseSealed(t, rendered)
	sealed.Name = "renamed"
	if _, err := sealed.Unseal(scheme.Codecs, map[string]*rsa.PrivateKey{"c": key}); err == nil {
		t.Error("renamed strictly-scoped secret decrypted, want failure")
	}
}

func TestJSONFormatIsAlsoSupported(t *testing.T) {
	key := controllerKey(t)
	built := secretWith("payments", "db-creds", map[string][]byte{"a": []byte("1")})

	rendered, err := seal.NewSealer(&key.PublicKey).Seal(built, ssv1alpha1.StrictScope, seal.FormatJSON)
	if err != nil {
		t.Fatalf("Seal() returned error: %v", err)
	}

	if !bytes.HasPrefix(bytes.TrimSpace(rendered), []byte("{")) {
		t.Errorf("output is not JSON:\n%s", rendered)
	}
	// JSON is valid YAML, so the same parser confirms the document is well formed.
	if got := unseal(t, parseSealed(t, rendered), key); string(got.Data["a"]) != "1" {
		t.Errorf("a = %q, want %q", got.Data["a"], "1")
	}
}

func TestSealingWithoutACertificateFails(t *testing.T) {
	built := secretWith("payments", "db-creds", map[string][]byte{"a": []byte("1")})

	if _, err := seal.NewSealer(nil).Seal(built, ssv1alpha1.StrictScope, seal.FormatYAML); err == nil {
		t.Error("Seal() succeeded without a certificate, want failure")
	}
}

func TestParseFormatAcceptsOnlyYAMLAndJSON(t *testing.T) {
	for _, value := range []string{"yaml", "YAML", "json"} {
		if _, err := seal.ParseFormat(value); err != nil {
			t.Errorf("ParseFormat(%q) returned error: %v", value, err)
		}
	}
	for _, value := range []string{"", "xml", "toml"} {
		if _, err := seal.ParseFormat(value); err == nil {
			t.Errorf("ParseFormat(%q) accepted an unsupported format", value)
		}
	}
}
