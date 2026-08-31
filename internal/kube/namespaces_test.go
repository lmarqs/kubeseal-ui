package kube_test

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
)

func namespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func TestNamespacesAreListedSortedByName(t *testing.T) {
	clientset := fake.NewClientset(namespace("payments"), namespace("default"), namespace("kube-system"))

	names, err := kube.NewCluster(clientset).Namespaces(context.Background())
	if err != nil {
		t.Fatalf("Namespaces() returned error: %v", err)
	}

	want := []string{"default", "kube-system", "payments"}
	if len(names) != len(want) {
		t.Fatalf("namespaces = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("namespace %d = %q, want %q", i, names[i], want[i])
		}
	}
}

func TestNamespacesReportsForbiddenSoTheWizardCanAskInstead(t *testing.T) {
	clientset := fake.NewClientset()
	clientset.PrependReactor("list", "namespaces",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Resource: "namespaces"}, "", errors.New("user cannot list namespaces"))
		})

	_, err := kube.NewCluster(clientset).Namespaces(context.Background())

	if !errors.Is(err, kube.ErrForbidden) {
		t.Fatalf("error = %v, want ErrForbidden", err)
	}
}
