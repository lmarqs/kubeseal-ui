package kube

import (
	"fmt"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// Cluster answers live queries about one cluster. It is separate from Client so
// that everything requiring network access sits behind a single seam.
type Cluster struct {
	clientset kubernetes.Interface
	// dynamic reads and applies SealedSecrets, whose type this binary does not
	// compile against. It may be nil, in which case those operations report why.
	dynamic dynamic.Interface
}

// NewCluster wraps existing clients, which lets tests supply fakes.
func NewCluster(clientset kubernetes.Interface, dynamicClient dynamic.Interface) *Cluster {
	return &Cluster{clientset: clientset, dynamic: dynamicClient}
}

// Connect builds a clientset for the context selected in the kubeconfig. It does
// not contact the cluster; the first query does.
func (c *Client) Connect() (*Cluster, error) {
	restConfig, err := c.config.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("building client configuration: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("creating Kubernetes client: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("creating Kubernetes client: %w", err)
	}

	return NewCluster(clientset, dynamicClient), nil
}
