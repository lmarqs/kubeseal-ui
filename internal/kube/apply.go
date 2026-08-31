package kube

import (
	"context"
	"errors"
	"fmt"
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"
)

// fieldManager identifies this tool as the owner of the fields it applies, so a
// later apply by ksui updates them and a clash with another tool is reported
// rather than silently overwritten.
const fieldManager = "ksui"

// sealedSecretResource is where SealedSecrets live in the API.
var sealedSecretResource = schema.GroupVersionResource{
	Group:    "bitnami.com",
	Version:  "v1alpha1",
	Resource: "sealedsecrets",
}

// ErrConflict reports that another field manager owns fields this apply would
// change, so it was refused until forced.
var ErrConflict = errors.New("another tool owns part of this sealed secret")

// ErrNotSupported reports that the cluster does not know about SealedSecrets,
// which usually means the controller is not installed.
var ErrNotSupported = errors.New("this cluster has no SealedSecret resource")

// Supported reports whether SealedSecrets can be applied to this cluster at all.
//
// The context is part of the signature for consistency with the other queries,
// even though client-go's discovery interface offers no way to pass one on.
func (c *Cluster) Supported(_ context.Context) (bool, error) {
	groupVersion := sealedSecretResource.GroupVersion().String()

	resources, err := c.clientset.Discovery().ServerResourcesForGroupVersion(groupVersion)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("asking the cluster about %s: %w", groupVersion, err)
	}

	for _, resource := range resources.APIResources {
		if resource.Name == sealedSecretResource.Resource {
			return true, nil
		}
	}

	return false, nil
}

// Existing reports whether a sealed secret of this name is already in the cluster
// and which keys it holds, so an overwrite can be described before it happens.
// The keys are readable without decrypting anything.
func (c *Cluster) Existing(ctx context.Context, namespace, name string) (bool, []string, error) {
	if c.dynamic == nil {
		return false, nil, errors.New("this cluster connection cannot read sealed secrets")
	}

	found, err := c.dynamic.Resource(sealedSecretResource).
		Namespace(namespace).
		Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return false, nil, nil
	case apierrors.IsForbidden(err):
		return false, nil, fmt.Errorf("looking for an existing sealed secret: %w: %w", ErrForbidden, err)
	case err != nil:
		return false, nil, fmt.Errorf("looking for an existing sealed secret: %w", err)
	}

	return true, encryptedKeysOf(found), nil
}

// encryptedKeysOf lists the keys a sealed secret currently holds.
func encryptedKeysOf(object *unstructured.Unstructured) []string {
	data, found, err := unstructured.NestedMap(object.Object, "spec", "encryptedData")
	if !found || err != nil {
		return nil
	}

	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
}

// Apply sends the sealed secret to the cluster, letting the API server merge it
// with whatever is already there.
//
// Forcing takes ownership of fields another tool manages, so it is only done when
// asked for explicitly.
func (c *Cluster) Apply(ctx context.Context, manifest []byte, force bool) error {
	if c.dynamic == nil {
		return errors.New("this cluster connection cannot apply sealed secrets")
	}

	object := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(manifest, object); err != nil {
		return fmt.Errorf("reading the sealed secret to apply: %w", err)
	}

	name := object.GetName()
	if name == "" {
		return errors.New("the sealed secret has no name")
	}

	_, err := c.dynamic.Resource(sealedSecretResource).
		Namespace(object.GetNamespace()).
		Patch(ctx, name, types.ApplyPatchType, manifest, metav1.PatchOptions{
			FieldManager: fieldManager,
			Force:        &force,
		})
	switch {
	case apierrors.IsConflict(err):
		return fmt.Errorf("applying %s: %w: %w", name, ErrConflict, err)
	case apierrors.IsForbidden(err):
		return fmt.Errorf("applying %s: %w: %w", name, ErrForbidden, err)
	case apierrors.IsNotFound(err):
		return fmt.Errorf("applying %s: %w: %w", name, ErrNotSupported, err)
	case err != nil:
		return fmt.Errorf("applying %s: %w", name, err)
	}

	return nil
}
