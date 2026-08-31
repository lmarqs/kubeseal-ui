package kube

import (
	"context"
	"fmt"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/lmarqs/kubeseal-ui/internal/seal"
)

// controllerLabelSelector matches the Service the sealed-secrets Helm chart
// installs; the name heuristic below covers installations that do not set it.
const controllerLabelSelector = "app.kubernetes.io/name=sealed-secrets"

// controllerNameFragment identifies controller Services by naming convention.
const controllerNameFragment = "sealed-secrets"

// DiscoverControllers locates sealed-secrets controller Services, preferring the
// stock installation and widening the search only when that is absent. An empty
// result is not an error: the caller offers manual entry or an offline
// certificate instead.
func (c *Cluster) DiscoverControllers(ctx context.Context) ([]seal.Controller, error) {
	if found, err := c.hasDefaultController(ctx); err != nil {
		return nil, err
	} else if found {
		return []seal.Controller{seal.DefaultController()}, nil
	}

	labelled, err := c.servicesMatching(ctx, controllerLabelSelector, nil)
	if err != nil {
		return nil, err
	}
	if len(labelled) > 0 {
		return labelled, nil
	}

	return c.servicesMatching(ctx, "", func(name string) bool {
		return strings.Contains(name, controllerNameFragment)
	})
}

// hasDefaultController reports whether the stock controller Service exists.
func (c *Cluster) hasDefaultController(ctx context.Context) (bool, error) {
	controller := seal.DefaultController()

	_, err := c.clientset.CoreV1().
		Services(controller.Namespace).
		Get(ctx, controller.Name, metav1.GetOptions{})
	switch {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err):
		return false, nil
	case apierrors.IsForbidden(err):
		// Not being allowed to look does not mean it is absent; keep searching.
		return false, nil
	default:
		return false, fmt.Errorf("looking up controller %s: %w", controller, err)
	}
}

// servicesMatching lists Services across all namespaces, optionally narrowed by a
// label selector and a name predicate.
func (c *Cluster) servicesMatching(
	ctx context.Context,
	labelSelector string,
	nameMatches func(string) bool,
) ([]seal.Controller, error) {
	list, err := c.clientset.CoreV1().
		Services(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		if apierrors.IsForbidden(err) {
			return nil, fmt.Errorf("searching for sealed-secrets controllers: %w: %w", ErrForbidden, err)
		}
		return nil, fmt.Errorf("searching for sealed-secrets controllers: %w", err)
	}

	controllers := make([]seal.Controller, 0, len(list.Items))
	for _, service := range list.Items {
		if nameMatches != nil && !nameMatches(service.Name) {
			continue
		}
		controllers = append(controllers, seal.Controller{Namespace: service.Namespace, Name: service.Name})
	}
	sortControllers(controllers)

	return controllers, nil
}

func sortControllers(controllers []seal.Controller) {
	sort.Slice(controllers, func(i, j int) bool {
		if controllers[i].Namespace != controllers[j].Namespace {
			return controllers[i].Namespace < controllers[j].Namespace
		}
		return controllers[i].Name < controllers[j].Name
	})
}
