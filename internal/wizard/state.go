package wizard

import (
	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"

	"github.com/lmarqs/kubeseal-ui/internal/seal"
	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// state is everything the wizard has collected. It lives outside the individual
// screens so that going back never discards work: entries survive a change of
// namespace, scope or name.
type state struct {
	options Options

	contextName string
	connection  Connection

	draft secret.Draft
	scope ssv1alpha1.SealingScope

	controllers []seal.Controller
	controller  seal.Controller
	certificate seal.Certificate

	// sealed is the current sealed secret, or nil when the draft has changed since
	// it was produced and it must be sealed again.
	sealed []byte

	// outcome describes what the wizard ended up doing, reported once it exits.
	outcome string
	// printToStdout asks the caller to write the sealed secret to stdout.
	printToStdout bool
}

// invalidate marks the sealed secret as out of date, which makes the review step
// seal again when it is next shown.
func (s *state) invalidate() {
	s.sealed = nil
}
