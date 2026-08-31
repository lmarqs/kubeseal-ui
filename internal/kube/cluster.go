package kube

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
)

// Cluster answers live queries about one cluster. It is separate from Client so
// that everything requiring network access sits behind a single seam.
type Cluster struct {
	clientset kubernetes.Interface
}

// NewCluster wraps an existing clientset, which lets tests supply a fake.
func NewCluster(clientset kubernetes.Interface) *Cluster {
	return &Cluster{clientset: clientset}
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

	return NewCluster(clientset), nil
}
