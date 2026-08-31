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
	"github.com/lmarqs/kubeseal-ui/internal/seal"
)

func service(namespace, name string, labels map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels},
	}
}

func TestDiscoverControllersPrefersTheStockInstallation(t *testing.T) {
	clientset := fake.NewClientset(
		service("kube-system", "sealed-secrets-controller", nil),
		service("infra", "sealed-secrets", map[string]string{"app.kubernetes.io/name": "sealed-secrets"}),
	)

	found, err := kube.NewCluster(clientset).DiscoverControllers(context.Background())
	if err != nil {
		t.Fatalf("DiscoverControllers() returned error: %v", err)
	}

	want := []seal.Controller{seal.DefaultController()}
	if len(found) != 1 || found[0] != want[0] {
		t.Errorf("controllers = %v, want %v", found, want)
	}
}

func TestDiscoverControllersFindsLabelledServicesInAnyNamespace(t *testing.T) {
	labels := map[string]string{"app.kubernetes.io/name": "sealed-secrets"}
	clientset := fake.NewClientset(
		service("team-b", "sealed-secrets", labels),
		service("team-a", "sealed-secrets", labels),
		service("default", "unrelated", nil),
	)

	found, err := kube.NewCluster(clientset).DiscoverControllers(context.Background())
	if err != nil {
		t.Fatalf("DiscoverControllers() returned error: %v", err)
	}

	want := []seal.Controller{
		{Namespace: "team-a", Name: "sealed-secrets"},
		{Namespace: "team-b", Name: "sealed-secrets"},
	}
	if len(found) != len(want) {
		t.Fatalf("controllers = %v, want %v", found, want)
	}
	for i := range want {
		if found[i] != want[i] {
			t.Errorf("controller %d = %v, want %v", i, found[i], want[i])
		}
	}
}

func TestDiscoverControllersFallsBackToTheNamingConvention(t *testing.T) {
	clientset := fake.NewClientset(
		service("infra", "my-sealed-secrets-controller", nil),
		service("default", "postgres", nil),
	)

	found, err := kube.NewCluster(clientset).DiscoverControllers(context.Background())
	if err != nil {
		t.Fatalf("DiscoverControllers() returned error: %v", err)
	}

	want := seal.Controller{Namespace: "infra", Name: "my-sealed-secrets-controller"}
	if len(found) != 1 || found[0] != want {
		t.Errorf("controllers = %v, want [%v]", found, want)
	}
}

func TestDiscoverControllersReportsNoneWhenNothingMatches(t *testing.T) {
	clientset := fake.NewClientset(service("default", "postgres", nil))

	found, err := kube.NewCluster(clientset).DiscoverControllers(context.Background())
	if err != nil {
		t.Fatalf("DiscoverControllers() returned error: %v", err)
	}

	if len(found) != 0 {
		t.Errorf("controllers = %v, want none", found)
	}
}

func TestDiscoverControllersReportsForbiddenWhenServicesCannotBeListed(t *testing.T) {
	clientset := fake.NewClientset()
	clientset.PrependReactor("list", "services",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Resource: "services"}, "", errors.New("nope"))
		})

	_, err := kube.NewCluster(clientset).DiscoverControllers(context.Background())

	if !errors.Is(err, kube.ErrForbidden) {
		t.Fatalf("error = %v, want ErrForbidden", err)
	}
}
