package secret_test

import (
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

func draftWith(t *testing.T, entries ...secret.Entry) secret.Draft {
	t.Helper()
	name, err := secret.NewName("db-creds")
	if err != nil {
		t.Fatalf("NewName() returned error: %v", err)
	}
	draft := secret.Draft{Namespace: "payments", Name: name, Type: secret.TypeOpaque}
	for _, entry := range entries {
		draft.Entries.Set(entry)
	}
	return draft
}

func TestBuildProducesAnOpaqueSecretCarryingEveryEntry(t *testing.T) {
	draft := draftWith(t, literal(t, "DB_PASSWORD", "hunter2"), literal(t, "ca.crt", "PEM"))

	built, err := secret.Build(draft)
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}

	if built.Kind != "Secret" || built.APIVersion != "v1" {
		t.Errorf("type meta = %s %s, want v1 Secret", built.APIVersion, built.Kind)
	}
	if built.Name != "db-creds" || built.Namespace != "payments" {
		t.Errorf("object meta = %s/%s, want payments/db-creds", built.Namespace, built.Name)
	}
	if built.Type != corev1.SecretTypeOpaque {
		t.Errorf("type = %q, want %q", built.Type, corev1.SecretTypeOpaque)
	}
	if got := string(built.Data["DB_PASSWORD"]); got != "hunter2" {
		t.Errorf("data[DB_PASSWORD] = %q, want %q", got, "hunter2")
	}
	if got := string(built.Data["ca.crt"]); got != "PEM" {
		t.Errorf("data[ca.crt] = %q, want %q", got, "PEM")
	}
}

func TestBuildRejectsADraftWithoutAName(t *testing.T) {
	draft := draftWith(t, literal(t, "a", "1"))
	draft.Name = ""

	_, err := secret.Build(draft)

	if err == nil {
		t.Fatal("Build() accepted a draft without a name")
	}
}

func TestBuildRejectsADraftWithoutANamespace(t *testing.T) {
	draft := draftWith(t, literal(t, "a", "1"))
	draft.Namespace = ""

	_, err := secret.Build(draft)

	if err == nil {
		t.Fatal("Build() accepted a draft without a namespace")
	}
}

func TestBuildRejectsADraftWithNoEntries(t *testing.T) {
	_, err := secret.Build(draftWith(t))

	if !errors.Is(err, secret.ErrNoEntries) {
		t.Fatalf("error = %v, want ErrNoEntries", err)
	}
}
