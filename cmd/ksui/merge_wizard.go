package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/lmarqs/kubeseal-ui/internal/seal"
	"github.com/lmarqs/kubeseal-ui/internal/wizard"
)

// runMergeWizard walks through the keys of an existing sealed secret file.
func runMergeWizard(cmd *cobra.Command, o *options) error {
	existing, err := seal.ReadExisting(o.mergeTarget)
	if err != nil {
		return usageError(err, "point it at a file containing a SealedSecret")
	}

	result, err := wizard.Run(
		wizard.Options{
			Clusters:          wizardClusters{options: o},
			Writer:            fileWriter{},
			Context:           o.kubeContext,
			Merge:             &existing,
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
