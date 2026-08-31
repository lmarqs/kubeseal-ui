package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"

	"github.com/lmarqs/kubeseal-ui/internal/seal"
	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

const mergeLongHelp = `Add, replace or remove keys in a sealed secret file that already exists.

The file's name, namespace and sealing scope are used as they are, because those
three decide what the controller will accept when decrypting; changing them would
make the values already in the file unreadable.

Values already sealed cannot be shown. A key can be given a new value or removed,
never read back.

Run it with just a file to be walked through the keys interactively.`

func newMergeCommand() *cobra.Command {
	opts := &options{}

	command := &cobra.Command{
		Use:   "merge <file>",
		Short: "Add, replace or remove keys in an existing sealed secret file",
		Long:  mergeLongHelp,
		Args:  exactlyOneFile,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.mergeTarget = args[0]

			if opts.describesMerge() || !interactive(opts.ci) {
				return runMerge(cmd, opts)
			}
			return runMergeWizard(cmd, opts)
		},
	}

	opts.registerMergeFlags(command.Flags())

	return command
}

func exactlyOneFile(_ *cobra.Command, args []string) error {
	switch len(args) {
	case 1:
		return nil
	case 0:
		return usageErrorf("name the sealed secret file to merge into", "no file given")
	default:
		return usageErrorf("merge into one file at a time", "expected one file, got %d", len(args))
	}
}

// runMerge changes the file according to the flags, without asking anything.
func runMerge(cmd *cobra.Command, o *options) error {
	existing, err := seal.ReadExisting(o.mergeTarget)
	if err != nil {
		return usageError(err, "point it at a file containing a SealedSecret")
	}

	if !o.describesMerge() {
		return usageErrorf(
			"pass --from-literal, --from-file or --remove",
			"nothing to change in %s", o.mergeTarget)
	}

	format, err := o.mergeFormat(existing)
	if err != nil {
		return err
	}

	// The built secret shares its value buffers with the draft, so the draft is
	// scrubbed here, once sealing is over, rather than where it was assembled.
	draft, err := o.mergeDraft(cmd, existing)
	defer draft.Entries.Scrub()
	if err != nil {
		return err
	}

	incoming, err := incomingSecret(draft)
	if err != nil {
		return err
	}

	certificate, err := o.resolveCertificate(cmd.Context())
	if err != nil {
		return runtimeError(err, "pass --cert to seal with a certificate file")
	}
	reportCertificate(cmd.ErrOrStderr(), certificate)

	result, err := seal.NewSealer(certificate.PublicKey).Merge(existing, incoming, o.remove, format)
	if err != nil {
		if errors.Is(err, seal.ErrWouldEmpty) {
			return usageError(err, "a sealed secret must keep at least one key")
		}
		return err
	}

	if err := seal.WriteFile(existing.Path, result.Sealed); err != nil {
		return err
	}

	_, _ = fmt.Fprintln(cmd.ErrOrStderr(), describeMerge(result, existing.Path))

	return nil
}

// mergeDraft assembles the new values, taking the file's own identity so the
// encryption label matches what is already sealed there. The draft is empty when the
// run only removes keys.
func (o *options) mergeDraft(cmd *cobra.Command, existing seal.Existing) (secret.Draft, error) {
	if len(o.entries.literals) == 0 && len(o.entries.files) == 0 {
		return secret.Draft{}, nil
	}

	name, err := secret.NewName(existing.Name)
	if err != nil {
		return secret.Draft{}, usageError(err, "the file's metadata.name is not a valid secret name")
	}

	draft := secret.Draft{
		Namespace: existing.Namespace,
		Name:      name,
		Type:      existing.Type,
	}

	if err := o.collectLiterals(&draft); err != nil {
		return draft, err
	}
	if err := o.collectFiles(&draft, cmd.InOrStdin()); err != nil {
		return draft, err
	}

	return draft, nil
}

// incomingSecret renders the new values as a Secret, or nothing when the run only
// removes keys.
func incomingSecret(draft secret.Draft) (*corev1.Secret, error) {
	if draft.Entries.Len() == 0 {
		return nil, nil
	}
	return secret.Build(draft)
}

// mergeFormat keeps the file in the shape it already has, unless told otherwise.
func (o *options) mergeFormat(existing seal.Existing) (seal.Format, error) {
	if o.format != "" {
		return seal.ParseFormat(o.format)
	}
	if bytes.HasPrefix(bytes.TrimSpace(existing.Raw()), []byte("{")) {
		return seal.FormatJSON, nil
	}
	return seal.FormatYAML, nil
}

// describeMerge reports what changed, by key name only.
func describeMerge(result seal.MergeResult, path string) string {
	changes := make([]string, 0, 3)

	for _, change := range []struct {
		label string
		keys  []string
	}{
		{"added", result.Added},
		{"replaced", result.Replaced},
		{"removed", result.Removed},
	} {
		if len(change.keys) > 0 {
			changes = append(changes, change.label+" "+strings.Join(change.keys, ", "))
		}
	}

	if len(changes) == 0 {
		return "nothing changed in " + path
	}

	return fmt.Sprintf("updated %s: %s", path, strings.Join(changes, "; "))
}
