package kube

import (
	"context"
	"errors"
	"fmt"
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ErrForbidden reports that the current credentials may not perform a request.
// Callers use it to fall back to asking the user instead of failing outright.
var ErrForbidden = errors.New("forbidden")

// Namespaces lists the namespaces visible to the current credentials, sorted by
// name.
func (c *Cluster) Namespaces(ctx context.Context) ([]string, error) {
	list, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsForbidden(err) {
			return nil, fmt.Errorf("listing namespaces: %w: %w", ErrForbidden, err)
		}
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}

	names := make([]string, 0, len(list.Items))
	for _, namespace := range list.Items {
		names = append(names, namespace.Name)
	}
	sort.Strings(names)

	return names, nil
}
