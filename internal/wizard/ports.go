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
	Applier      Applier
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

// Applier puts a sealed secret into the cluster.
type Applier interface {
	// Supported reports whether the cluster knows about SealedSecrets at all.
	Supported(ctx context.Context) (bool, error)
	// Existing reports whether one of this name is already there, and which keys it
	// holds, so an overwrite can be described before it happens.
	Existing(ctx context.Context, namespace, name string) (found bool, keys []string, err error)
	// Apply sends the sealed secret, taking ownership of contested fields only when
	// force is set.
	Apply(ctx context.Context, sealed []byte, force bool) error
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

	// Merge, when set, means the wizard is editing an existing sealed secret file
	// rather than creating one. Its name, namespace and scope are fixed by the file.
	Merge *seal.Existing

	// DefaultOutputPath is offered when saving to a file.
	DefaultOutputPath func(name string) string
}
