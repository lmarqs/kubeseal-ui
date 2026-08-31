package main

import (
	"github.com/spf13/cobra"
)

const rootLongHelp = `ksui creates Bitnami SealedSecrets.

Sealing happens in-process, so the kubeseal binary is not required. Flags shared
with kubeseal keep kubeseal's names and meanings.

The sealed secret is written to stdout and everything else to stderr, so
redirection works as expected:

  ksui --name db-creds --from-literal DB_PASSWORD=hunter2 > db-creds.yaml

The interactive wizard is not available yet; describe the secret with flags for
now.`

func newRootCommand() *cobra.Command {
	opts := &options{}

	root := &cobra.Command{
		Use:   "ksui",
		Short: "Create Bitnami SealedSecrets",
		Long:  rootLongHelp,
		Args:  noArguments,
		// main() reports errors so exit codes and hints stay consistent.
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.fetchCert {
				return runFetchCert(cmd, opts)
			}
			return runSeal(cmd, opts)
		},
	}

	// Malformed flags are the caller's mistake, so they exit 2 like other usage
	// errors rather than looking like a runtime failure.
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError(err, "run 'ksui --help' to see the available flags")
	})

	opts.register(root.Flags())
	root.AddCommand(newVersionCommand())

	return root
}

func noArguments(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return usageErrorf("describe the secret with flags", "unexpected argument %q", args[0])
	}
	return nil
}
