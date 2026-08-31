package kube

import (
	"fmt"
	"sort"
)

// Context is a kubeconfig context the user can pick from.
type Context struct {
	Name    string
	Cluster string
	// Namespace is the default namespace the context declares, if any.
	Namespace string
}

// Contexts lists the contexts declared in the kubeconfig, sorted by name, along
// with the name of the one currently selected. It reads only local files.
func (c *Client) Contexts() ([]Context, string, error) {
	raw, err := c.config.RawConfig()
	if err != nil {
		return nil, "", fmt.Errorf("reading kubeconfig: %w", err)
	}
	if len(raw.Contexts) == 0 {
		return nil, "", ErrNoContexts
	}

	names := make([]string, 0, len(raw.Contexts))
	for name := range raw.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)

	contexts := make([]Context, 0, len(names))
	for _, name := range names {
		entry := raw.Contexts[name]
		contexts = append(contexts, Context{
			Name:      name,
			Cluster:   entry.Cluster,
			Namespace: entry.Namespace,
		})
	}

	return contexts, c.currentContext(raw.CurrentContext), nil
}

// currentContext prefers an explicit override over the kubeconfig's own
// current-context, mirroring how clientcmd resolves the active context.
func (c *Client) currentContext(fromKubeconfig string) string {
	if c.contextOverride != "" {
		return c.contextOverride
	}
	return fromKubeconfig
}

// DefaultNamespace reports the namespace the active context targets, falling back
// to "default" when the context does not name one.
func (c *Client) DefaultNamespace() (string, error) {
	namespace, _, err := c.config.Namespace()
	if err != nil {
		return "", fmt.Errorf("resolving default namespace: %w", err)
	}
	return namespace, nil
}
