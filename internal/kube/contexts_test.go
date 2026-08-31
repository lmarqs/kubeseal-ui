package kube_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
)

const twoContextKubeconfig = `
apiVersion: v1
kind: Config
current-context: staging
clusters:
  - name: prod-cluster
    cluster:
      server: https://prod.example:6443
  - name: staging-cluster
    cluster:
      server: https://staging.example:6443
contexts:
  - name: prod
    context:
      cluster: prod-cluster
      user: prod-user
      namespace: payments
  - name: staging
    context:
      cluster: staging-cluster
      user: staging-user
users:
  - name: prod-user
    user: {}
  - name: staging-user
    user: {}
`

func writeKubeconfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing kubeconfig: %v", err)
	}
	return path
}

func TestContextsAreListedSortedWithCurrentContext(t *testing.T) {
	path := writeKubeconfig(t, twoContextKubeconfig)

	contexts, current, err := kube.New(path, "").Contexts()
	if err != nil {
		t.Fatalf("Contexts() returned error: %v", err)
	}

	if current != "staging" {
		t.Errorf("current context = %q, want %q", current, "staging")
	}
	want := []kube.Context{
		{Name: "prod", Cluster: "prod-cluster", Namespace: "payments"},
		{Name: "staging", Cluster: "staging-cluster"},
	}
	if len(contexts) != len(want) {
		t.Fatalf("got %d contexts, want %d: %+v", len(contexts), len(want), contexts)
	}
	for i := range want {
		if contexts[i] != want[i] {
			t.Errorf("context %d = %+v, want %+v", i, contexts[i], want[i])
		}
	}
}

func TestExplicitContextOverridesTheKubeconfigCurrentContext(t *testing.T) {
	path := writeKubeconfig(t, twoContextKubeconfig)

	_, current, err := kube.New(path, "prod").Contexts()
	if err != nil {
		t.Fatalf("Contexts() returned error: %v", err)
	}

	if current != "prod" {
		t.Errorf("current context = %q, want %q", current, "prod")
	}
}

func TestKubeconfigWithoutContextsReportsErrNoContexts(t *testing.T) {
	path := writeKubeconfig(t, "apiVersion: v1\nkind: Config\n")

	_, _, err := kube.New(path, "").Contexts()

	if !errors.Is(err, kube.ErrNoContexts) {
		t.Fatalf("error = %v, want ErrNoContexts", err)
	}
}

func TestDefaultNamespaceComesFromTheSelectedContext(t *testing.T) {
	path := writeKubeconfig(t, twoContextKubeconfig)

	namespace, err := kube.New(path, "prod").DefaultNamespace()
	if err != nil {
		t.Fatalf("DefaultNamespace() returned error: %v", err)
	}

	if namespace != "payments" {
		t.Errorf("namespace = %q, want %q", namespace, "payments")
	}
}

func TestDefaultNamespaceFallsBackToDefaultWhenContextDeclaresNone(t *testing.T) {
	path := writeKubeconfig(t, twoContextKubeconfig)

	namespace, err := kube.New(path, "staging").DefaultNamespace()
	if err != nil {
		t.Fatalf("DefaultNamespace() returned error: %v", err)
	}

	if namespace != "default" {
		t.Errorf("namespace = %q, want %q", namespace, "default")
	}
}
