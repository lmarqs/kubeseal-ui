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

Run it with no flags to be walked through the questions: which cluster and
namespace, what the secret is called, then its values one at a time.`

func newRootCommand() *cobra.Command {
	opts := &options{}

	root := &cobra.Command{
		Use:   "ksui",
		Short: "Create Bitnami SealedSecrets",
		Long:  rootLongHelp,
		Args:  noArguments("describe the secret with flags"),
		// main() reports errors so exit codes and hints stay consistent.
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.fetchCert {
				return runFetchCert(cmd, opts)
			}
			// Flags that already describe a secret are taken at face value; the
			// wizard only appears when there is something left to ask and a terminal
			// to ask it on.
			if opts.describesSecret() || !interactive(opts.ci) {
				return runSeal(cmd, opts)
			}
			return runWizard(cmd, opts)
		},
	}

	// Malformed flags are the caller's mistake, so they exit 2 like other usage
	// errors rather than looking like a runtime failure.
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError(err, "run 'ksui --help' to see the available flags")
	})

	opts.register(root.Flags())
	root.AddCommand(newMergeCommand())
	root.AddCommand(newVersionCommand())

	return root
}

// noArguments rejects positional arguments as a usage error, so a command that
// takes none exits 2 with a hint like every other correctable mistake.
func noArguments(hint string) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) > 0 {
			return usageErrorf(hint, "unexpected argument %q", args[0])
		}
		return nil
	}
}
