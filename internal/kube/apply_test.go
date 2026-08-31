package kube_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
)

var sealedSecretGVR = schema.GroupVersionResource{
	Group: "bitnami.com", Version: "v1alpha1", Resource: "sealedsecrets",
}

const sealedSecretManifest = `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db-creds
  namespace: payments
spec:
  encryptedData:
    DB_PASSWORD: AgBy8hCi
`

// dynamicClient builds a fake dynamic client that knows the SealedSecret kind.
func dynamicClient(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{sealedSecretGVR: "SealedSecretList"}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds, objects...)
}

func sealedSecret(namespace, name string, keys ...string) *unstructured.Unstructured {
	encrypted := map[string]any{}
	for _, key := range keys {
		encrypted[key] = "AgBy8hCi"
	}

	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "bitnami.com/v1alpha1",
		"kind":       "SealedSecret",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec":       map[string]any{"encryptedData": encrypted},
	}}
}

// discoveryWith makes the fake clientset report the given resources for a group.
func discoveryWith(groupVersion string, resourceNames ...string) *fake.Clientset {
	clientset := fake.NewClientset()

	resources := make([]metav1.APIResource, 0, len(resourceNames))
	for _, name := range resourceNames {
		resources = append(resources, metav1.APIResource{Name: name})
	}
	clientset.Resources = []*metav1.APIResourceList{
		{GroupVersion: groupVersion, APIResources: resources},
	}

	return clientset
}

func TestAClusterWithTheControllerInstalledSupportsSealedSecrets(t *testing.T) {
	clientset := discoveryWith("bitnami.com/v1alpha1", "sealedsecrets")

	supported, err := kube.NewCluster(clientset, nil).Supported(context.Background())
	if err != nil {
		t.Fatalf("Supported() returned error: %v", err)
	}

	if !supported {
		t.Error("Supported() = false, want true when the resource is present")
	}
}

func TestAClusterWithoutTheCustomResourceDoesNotSupportSealedSecrets(t *testing.T) {
	clientset := discoveryWith("v1", "secrets")

	supported, err := kube.NewCluster(clientset, nil).Supported(context.Background())
	if err != nil {
		t.Fatalf("Supported() returned error: %v", err)
	}

	if supported {
		t.Error("Supported() = true, want false when the resource is absent")
	}
}

func TestExistingReportsTheKeysASealedSecretAlreadyHolds(t *testing.T) {
	client := dynamicClient(sealedSecret("payments", "db-creds", "DB_PASSWORD", "API_TOKEN"))

	found, keys, err := kube.NewCluster(fake.NewClientset(), client).
		Existing(context.Background(), "payments", "db-creds")
	if err != nil {
		t.Fatalf("Existing() returned error: %v", err)
	}

	if !found {
		t.Fatal("Existing() did not find the sealed secret")
	}
	want := []string{"API_TOKEN", "DB_PASSWORD"}
	if len(keys) != len(want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("key %d = %q, want %q", i, keys[i], want[i])
		}
	}
}

func TestExistingReportsNothingWhenTheSealedSecretIsAbsent(t *testing.T) {
	client := dynamicClient()

	found, _, err := kube.NewCluster(fake.NewClientset(), client).
		Existing(context.Background(), "payments", "db-creds")
	if err != nil {
		t.Fatalf("Existing() returned error: %v", err)
	}

	if found {
		t.Error("Existing() found a sealed secret that is not there")
	}
}

func TestApplySendsTheManifestToTheRightResource(t *testing.T) {
	client := dynamicClient()
	var captured k8stesting.PatchAction
	client.PrependReactor("patch", "sealedsecrets",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			captured = action.(k8stesting.PatchAction)
			return true, sealedSecret("payments", "db-creds", "DB_PASSWORD"), nil
		})

	err := kube.NewCluster(fake.NewClientset(), client).
		Apply(context.Background(), []byte(sealedSecretManifest), false)
	if err != nil {
		t.Fatalf("Apply() returned error: %v", err)
	}

	if captured == nil {
		t.Fatal("nothing was sent to the cluster")
	}
	if captured.GetName() != "db-creds" || captured.GetNamespace() != "payments" {
		t.Errorf("applied %s/%s, want payments/db-creds", captured.GetNamespace(), captured.GetName())
	}
	if captured.GetPatchType() != types.ApplyPatchType {
		t.Errorf("patch type = %v, want a server-side apply", captured.GetPatchType())
	}
	if !strings.Contains(string(captured.GetPatch()), "DB_PASSWORD") {
		t.Errorf("the manifest was not what got applied:\n%s", captured.GetPatch())
	}
}

func TestApplyReportsAClashWithAnotherFieldManager(t *testing.T) {
	client := dynamicClient()
	client.PrependReactor("patch", "sealedsecrets",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrorsConflict()
		})

	err := kube.NewCluster(fake.NewClientset(), client).
		Apply(context.Background(), []byte(sealedSecretManifest), false)

	if !errors.Is(err, kube.ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}
}

func TestApplyRefusesAManifestWithoutAName(t *testing.T) {
	err := kube.NewCluster(fake.NewClientset(), dynamicClient()).
		Apply(context.Background(), []byte("apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\n"), false)

	if err == nil {
		t.Error("Apply() accepted a manifest with no name")
	}
}

func TestApplyWithoutADynamicClientExplainsWhyItCannot(t *testing.T) {
	err := kube.NewCluster(fake.NewClientset(), nil).
		Apply(context.Background(), []byte(sealedSecretManifest), false)

	if err == nil {
		t.Error("Apply() succeeded with no client to apply through")
	}
}

// apiErrorsConflict builds the error the API server returns when another field
// manager owns fields an apply would change.
func apierrorsConflict() error {
	return apierrors.NewConflict(
		schema.GroupResource{Group: "bitnami.com", Resource: "sealedsecrets"},
		"db-creds",
		errors.New("conflict with \"kubectl\""),
	)
}
