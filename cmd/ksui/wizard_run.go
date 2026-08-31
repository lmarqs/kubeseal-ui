package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
	"github.com/lmarqs/kubeseal-ui/internal/seal"
	"github.com/lmarqs/kubeseal-ui/internal/wizard"
)

// runWizard asks the questions interactively, then does whatever the user chose at
// the end. This is the wiring layer: it decides which implementations the wizard
// talks to.
func runWizard(cmd *cobra.Command, o *options) error {
	result, err := wizard.Run(
		wizard.Options{
			Clusters:          wizardClusters{options: o},
			Writer:            fileWriter{},
			Context:           o.kubeContext,
			Namespace:         o.namespace,
			Name:              o.name,
			DefaultOutputPath: defaultOutputPath,
		},
		cmd.ErrOrStderr(),
		cmd.InOrStdin(),
	)
	if err != nil {
		return err
	}

	if result.PrintToStdout && result.Sealed != nil {
		return seal.WriteTo(cmd.OutOrStdout(), result.Sealed)
	}
	if result.Outcome != "" {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), result.Outcome)
	}

	return nil
}

// defaultOutputPath is the file name offered when saving, alongside the manifests
// a secret usually lives with.
func defaultOutputPath(name string) string {
	return "./" + name + "-sealed.yaml"
}

// wizardClusters gives the wizard access to clusters described by the kubeconfig.
type wizardClusters struct {
	options *options
}

func (w wizardClusters) Contexts() ([]kube.Context, string, error) {
	return kube.New(w.options.kubeconfig, "").Contexts()
}

func (w wizardClusters) Open(contextName string) (wizard.Connection, error) {
	client := kube.New(w.options.kubeconfig, contextName)

	cluster, err := client.Connect()
	if err != nil {
		return wizard.Connection{}, err
	}

	// The address is only used to keep one cluster's cached certificates apart from
	// another's, so not knowing it costs nothing but caching.
	server, _ := client.Server()

	return wizard.Connection{
		Cluster: cluster,
		Certificates: &seal.Resolver{
			CertPath:     w.options.certPath,
			ClientConfig: client.ClientConfig(),
			Cluster:      server,
			Cache:        w.options.certCache(),
		},
		Validator: controllerValidator{clientConfig: client.ClientConfig()},
		Server:    server,
	}, nil
}

// controllerValidator asks a controller whether it could decrypt a sealed secret.
type controllerValidator struct {
	clientConfig clientcmd.ClientConfig
}

func (v controllerValidator) Validate(
	ctx context.Context,
	controller seal.Controller,
	sealed []byte,
) error {
	ctx, cancel := context.WithTimeout(ctx, seal.DefaultFetchTimeout)
	defer cancel()

	return seal.Validate(ctx, v.clientConfig, controller, sealed)
}

// fileWriter saves a sealed secret where the wizard was told to put it.
type fileWriter struct{}

func (fileWriter) Write(path string, sealed []byte) error {
	if directory := filepath.Dir(path); directory != "" {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return fmt.Errorf("creating directory for %s: %w", path, err)
		}
	}

	if err := os.WriteFile(path, sealed, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	return nil
}
