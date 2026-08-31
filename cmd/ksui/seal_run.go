package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/lmarqs/kubeseal-ui/internal/seal"
	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// runSeal seals a secret described entirely by flags. Progress and warnings go to
// stderr; the sealed secret is the only thing written to stdout.
func runSeal(cmd *cobra.Command, o *options) error {
	ctx := cmd.Context()

	format, err := seal.ParseFormat(o.format)
	if err != nil {
		return usageError(err, "use --format yaml or --format json")
	}

	if err := o.requireSealingInput(); err != nil {
		return err
	}

	draft, err := o.draft(cmd.InOrStdin())
	if err != nil {
		return err
	}
	defer draft.Entries.Scrub()

	built, err := secret.Build(draft)
	if err != nil {
		if errors.Is(err, secret.ErrNoEntries) {
			return usageError(err, "pass --from-literal or --from-file, or --allow-empty-data to seal nothing")
		}
		return err
	}

	certificate, err := o.resolveCertificate(ctx)
	if err != nil {
		return runtimeError(err, "pass --cert to seal with a certificate file, "+
			"or --controller-namespace and --controller-name if the controller is installed elsewhere")
	}
	reportCertificate(cmd.ErrOrStderr(), certificate)

	sealed, err := seal.NewSealer(certificate.PublicKey).Seal(built, o.scope, format)
	if err != nil {
		return err
	}

	if err := o.runValidation(ctx, cmd.ErrOrStderr(), certificate, sealed); err != nil {
		return err
	}

	return o.writeSealed(cmd, sealed)
}

// runFetchCert prints the controller's certificate, which callers can keep for
// later offline sealing with --cert.
func runFetchCert(cmd *cobra.Command, o *options) error {
	certificate, err := o.resolveCertificate(cmd.Context())
	if err != nil {
		return runtimeError(err, "check --controller-namespace and --controller-name")
	}

	_, err = cmd.OutOrStdout().Write(certificate.PEM)
	return err
}

// requireSealingInput reports missing input as a usage error rather than prompting,
// so scripted and non-interactive runs fail predictably.
func (o *options) requireSealingInput() error {
	if o.name == "" {
		return usageErrorf("pass --name", "the secret needs a name")
	}
	if len(o.entries.literals) == 0 && len(o.entries.files) == 0 && !o.allowEmptyData {
		return usageErrorf("pass --from-literal key=value or --from-file [key=]path",
			"the secret has no entries")
	}
	return nil
}

// resolveCertificate obtains the certificate to seal with, caching what it fetches.
func (o *options) resolveCertificate(ctx context.Context) (seal.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, seal.DefaultFetchTimeout)
	defer cancel()

	// A certificate file is enough on its own, so nothing here touches the
	// kubeconfig or the cache.
	if o.certPath != "" {
		return seal.LoadCertificate(ctx, o.certPath)
	}

	resolver := &seal.Resolver{
		ClientConfig: o.client().ClientConfig(),
		Cluster:      o.clusterIdentity(),
		Cache:        o.certCache(),
	}

	return resolver.Resolve(ctx, o.controller())
}

// clusterIdentity names the cluster for cache purposes. A cluster we cannot
// identify simply goes uncached.
func (o *options) clusterIdentity() string {
	server, err := o.client().Server()
	if err != nil {
		return ""
	}
	return server
}

// certCache returns the on-disk certificate cache, or nil when there is nowhere
// to put it. Caching is a convenience, so failing to set it up is not fatal.
func (o *options) certCache() *seal.Cache {
	directory, err := seal.DefaultCacheDir()
	if err != nil {
		return nil
	}
	return seal.NewCache(directory)
}

// reportCertificate says which certificate was used, and warns when the controller
// could not be reached and a cached copy stood in for it.
func reportCertificate(stderr io.Writer, certificate seal.Certificate) {
	if certificate.Stale() {
		_, _ = fmt.Fprintf(stderr,
			"warning: could not reach the controller, sealing with the certificate cached at %s\n",
			certificate.RetrievedAt.Format("15:04 on 2 Jan"))
		_, _ = fmt.Fprintf(stderr, "warning: %v\n", certificate.FetchError)
	}
}

// runValidation checks the sealed secret against the controller when asked to.
func (o *options) runValidation(
	ctx context.Context,
	stderr io.Writer,
	certificate seal.Certificate,
	sealed []byte,
) error {
	if !o.validate {
		return nil
	}

	if o.certPath != "" || certificate.Stale() {
		_, _ = fmt.Fprintln(stderr, "warning: skipping validation, the controller is not reachable")
		return nil
	}

	if err := seal.Validate(ctx, o.client().ClientConfig(), o.controller(), sealed); err != nil {
		return validationError(err, "check that --scope, --namespace and --name match how the secret will be applied")
	}

	_, _ = fmt.Fprintln(stderr, "validated: the controller can decrypt this sealed secret")
	return nil
}

// writeSealed sends the sealed secret to stdout, or to the file requested with -w.
func (o *options) writeSealed(cmd *cobra.Command, sealed []byte) error {
	if o.outputPath == "" {
		return seal.WriteTo(cmd.OutOrStdout(), sealed)
	}

	if err := os.MkdirAll(filepath.Dir(o.outputPath), 0o755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", o.outputPath, err)
	}
	if err := os.WriteFile(o.outputPath, sealed, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", o.outputPath, err)
	}

	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\n", o.outputPath)
	return nil
}
