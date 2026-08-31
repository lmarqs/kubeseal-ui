// Package kube wraps the Kubernetes interactions ksui needs: reading kubeconfig,
// listing namespaces, locating sealed-secrets controllers and applying manifests.
package kube

import (
	"errors"

	"k8s.io/client-go/tools/clientcmd"
)

// ErrNoContexts reports a kubeconfig that declares no usable contexts.
var ErrNoContexts = errors.New("kubeconfig declares no contexts")

// Client talks to a single cluster, selected by kubeconfig context.
type Client struct {
	config          clientcmd.ClientConfig
	contextOverride string
}

// New builds a Client from the kubeconfig found in the usual locations, or from
// kubeconfigPath when that is not empty. An empty contextName keeps whichever
// context the kubeconfig marks as current.
func New(kubeconfigPath, contextName string) *Client {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}

	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}

	return &Client{
		config:          clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides),
		contextOverride: contextName,
	}
}

// ClientConfig exposes the underlying configuration, which also satisfies
// kubeseal.ClientConfig.
func (c *Client) ClientConfig() clientcmd.ClientConfig {
	return c.config
}
