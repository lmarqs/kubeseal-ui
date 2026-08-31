package main

import (
	"github.com/spf13/cobra"
)

const rootLongHelp = `ksui walks you through creating a Bitnami SealedSecret:
pick a cluster and namespace, name the secret, enter its values one by one,
then validate, apply, or write out the sealed YAML.

Sealing happens in-process — the kubeseal binary is not required.

The interactive wizard renders on stderr and the sealed secret is written to
stdout, so "ksui > my-secret.yaml" works as expected.`

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "ksui",
		Short: "Interactive wizard for creating Bitnami SealedSecrets",
		Long:  rootLongHelp,
		Args:  cobra.NoArgs,
		// Errors and usage are reported by main() so exit codes and hints stay consistent.
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.AddCommand(newVersionCommand())
	return root
}
