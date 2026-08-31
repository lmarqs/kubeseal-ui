package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/bitnami/sealed-secrets/pkg/kubeseal"
	"github.com/spf13/pflag"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
	"github.com/lmarqs/kubeseal-ui/internal/seal"
	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// stdinPaths are the ways a caller can ask for a value to be read from stdin,
// which keeps secrets out of shell history.
var stdinPaths = map[string]bool{"-": true, "/dev/stdin": true}

// options is everything the command line can specify. Flags shared with kubeseal
// keep kubeseal's names and meanings.
type options struct {
	kubeconfig  string
	kubeContext string

	namespace string
	name      string
	scope     ssv1alpha1.SealingScope
	entries   entrySources

	certPath            string
	controllerName      string
	controllerNamespace string

	format     string
	outputPath string

	allowEmptyData bool
	validate       bool
	fetchCert      bool
	ci             bool
}

// entrySources collects the repeatable value flags.
type entrySources struct {
	literals []string
	files    []string
}

func (o *options) register(flags *pflag.FlagSet) {
	flags.StringVar(&o.kubeconfig, "kubeconfig", "", "path to the kubeconfig file to use")
	flags.StringVar(&o.kubeContext, "context", "", "kubeconfig context to use")

	flags.StringVarP(&o.namespace, "namespace", "n", "", "namespace of the secret")
	flags.StringVar(&o.name, "name", "", "name of the secret")
	flags.Var(&o.scope, "scope", "sealing scope: strict, namespace-wide or cluster-wide")

	flags.StringArrayVar(&o.entries.literals, "from-literal", nil,
		"secret entry given as key=value (repeatable)")
	flags.StringArrayVar(&o.entries.files, "from-file", nil,
		"secret entry read from a file, as [key=]path; path may be - to read stdin (repeatable)")

	flags.StringVar(&o.certPath, "cert", "", "certificate file or URL to seal with, instead of asking the controller")
	flags.StringVar(&o.controllerName, "controller-name", seal.DefaultControllerName,
		"name of the sealed-secrets controller")
	flags.StringVar(&o.controllerNamespace, "controller-namespace", seal.DefaultControllerNamespace,
		"namespace of the sealed-secrets controller")

	flags.StringVarP(&o.format, "format", "o", "yaml", "output format: yaml or json")
	flags.StringVarP(&o.outputPath, "sealed-secret-file", "w", "",
		"write the sealed secret to this file instead of stdout")

	flags.BoolVar(&o.allowEmptyData, "allow-empty-data", false, "allow sealing a secret that has no entries")
	flags.BoolVar(&o.validate, "validate", false, "check that the controller can decrypt the sealed secret")
	flags.BoolVar(&o.fetchCert, "fetch-cert", false, "print the controller certificate to stdout and exit")
	flags.BoolVar(&o.ci, "ci", false, "never draw the wizard; report what is missing instead of asking")
}

// controller is the controller these options point at.
func (o *options) controller() seal.Controller {
	return seal.Controller{Namespace: o.controllerNamespace, Name: o.controllerName}
}

// client builds the kubeconfig-backed client these options describe.
func (o *options) client() *kube.Client {
	return kube.New(o.kubeconfig, o.kubeContext)
}

// draft assembles the secret described by the flags, reading any file-backed
// values into memory.
func (o *options) draft(stdin io.Reader) (secret.Draft, error) {
	name, err := secret.NewName(o.name)
	if err != nil {
		return secret.Draft{}, usageError(err, "pass --name with a valid Kubernetes secret name")
	}

	namespace, err := o.resolveNamespace()
	if err != nil {
		return secret.Draft{}, err
	}

	draft := secret.Draft{
		Namespace:  namespace,
		Name:       name,
		Type:       secret.TypeOpaque,
		AllowEmpty: o.allowEmptyData,
	}

	if err := o.collectLiterals(&draft); err != nil {
		return secret.Draft{}, err
	}
	if err := o.collectFiles(&draft, stdin); err != nil {
		return secret.Draft{}, err
	}

	return draft, nil
}

// resolveNamespace prefers an explicit --namespace and otherwise takes the one the
// active kubeconfig context declares, the way kubectl does.
func (o *options) resolveNamespace() (string, error) {
	if o.namespace != "" {
		return o.namespace, nil
	}

	namespace, err := o.client().DefaultNamespace()
	if err != nil || namespace == "" {
		return "", usageErrorf("pass --namespace", "cannot tell which namespace to use")
	}

	return namespace, nil
}

func (o *options) collectLiterals(draft *secret.Draft) error {
	for _, literal := range o.entries.literals {
		key, value, found := strings.Cut(literal, "=")
		if !found {
			return usageErrorf("write it as --from-literal key=value",
				"malformed --from-literal %q", literal)
		}

		parsed, err := secret.NewKey(key)
		if err != nil {
			return usageError(err, "secret keys may contain letters, digits, '-', '_' and '.'")
		}

		draft.Entries.Set(secret.Entry{Key: parsed, Value: []byte(value), Source: secret.SourceLiteral})
	}

	return nil
}

func (o *options) collectFiles(draft *secret.Draft, stdin io.Reader) error {
	for _, spec := range o.entries.files {
		key, path := kubeseal.ParseFromFile(spec)
		if key == "" {
			return usageErrorf("write it as --from-file key=path", "cannot tell which key %q sets", spec)
		}

		parsed, err := secret.NewKey(key)
		if err != nil {
			return usageError(err, "secret keys may contain letters, digits, '-', '_' and '.'")
		}

		value, err := readValue(path, stdin)
		if err != nil {
			return err
		}

		draft.Entries.Set(secret.Entry{Key: parsed, Value: value, Source: secret.SourceFile, Path: path})
	}

	return nil
}

// readValue reads a value from a file, or from stdin when asked to.
func readValue(path string, stdin io.Reader) ([]byte, error) {
	if stdinPaths[path] {
		if stdin == nil {
			return nil, usageErrorf("pipe the value in", "nothing is available on stdin to read %q from", path)
		}

		value, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("reading value from stdin: %w", err)
		}
		return value, nil
	}

	value, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, usageErrorf("check the path", "no such file: %s", path)
		}
		return nil, fmt.Errorf("reading value from %s: %w", path, err)
	}

	return value, nil
}
