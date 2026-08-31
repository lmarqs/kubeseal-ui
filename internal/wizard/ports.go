// Package wizard is the interactive terminal flow for creating a SealedSecret.
//
// It drives the sealing logic rather than containing it, and reaches the outside
// world only through the interfaces declared here, so every screen can be
// exercised with stand-ins and no cluster.
package wizard

import (
	"context"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
	"github.com/lmarqs/kubeseal-ui/internal/seal"
)

// Clusters is the local kubeconfig and the clusters it describes.
type Clusters interface {
	// Contexts lists the available contexts and names the current one.
	Contexts() ([]kube.Context, string, error)
	// Open connects to one context.
	Open(contextName string) (Connection, error)
}

// Connection is everything the wizard can do with one cluster, gathered together
// because all of it depends on which context was chosen.
type Connection struct {
	Cluster      Cluster
	Certificates Certificates
	Validator    Validator
	// Server is the cluster's address, which identifies it when caching.
	Server string
}

// Cluster is what the wizard asks of a live cluster.
type Cluster interface {
	Namespaces(ctx context.Context) ([]string, error)
	DiscoverControllers(ctx context.Context) ([]seal.Controller, error)
}

// Certificates supplies the certificate to seal with. seal.Resolver implements it.
type Certificates interface {
	Resolve(ctx context.Context, controller seal.Controller) (seal.Certificate, error)
}

// Validator asks a controller whether it could decrypt a sealed secret.
type Validator interface {
	Validate(ctx context.Context, controller seal.Controller, sealed []byte) error
}

// Writer persists a finished sealed secret.
type Writer interface {
	Write(path string, sealed []byte) error
}

// Options is everything the wizard needs to run, supplied by the caller.
type Options struct {
	Clusters Clusters
	Writer   Writer

	// Prefills come from flags, letting the wizard skip questions already answered.
	Context   string
	Namespace string
	Name      string

	// DefaultOutputPath is offered when saving to a file.
	DefaultOutputPath func(name string) string
}
