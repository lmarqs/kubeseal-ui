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
	// scopeChosen distinguishes a deliberate choice of the strict default from not
	// having been asked yet, so the breadcrumb never claims an unmade decision.
	scopeChosen bool

	controllers []seal.Controller
	controller  seal.Controller
	certificate seal.Certificate

	// sealed is the current sealed secret, or nil when the draft has changed since
	// it was produced and it must be sealed again.
	sealed []byte

	// removing are keys to drop from the file being merged into.
	removing []string

	// outcome describes what the wizard ended up doing, reported once it exits.
	outcome string
	// printToStdout asks the caller to write the sealed secret to stdout.
	printToStdout bool
}

// merging reports whether an existing file is being edited.
func (s *state) merging() bool {
	return s.options.Merge != nil
}

// markForRemoval records that a key already sealed in the file should go.
func (s *state) markForRemoval(key string) {
	for _, existing := range s.removing {
		if existing == key {
			return
		}
	}
	s.removing = append(s.removing, key)
}

// keepKey cancels a pending removal, which is what giving the key a new value
// means: merging drops removed keys after adding new ones, so a key left marked
// would lose the value just entered.
func (s *state) keepKey(key string) {
	for index, existing := range s.removing {
		if existing == key {
			s.removing = append(s.removing[:index], s.removing[index+1:]...)
			return
		}
	}
}

// adoptControllers records what discovery found. Discovery is a convenience: when
// it fails or finds nothing, the stock location stands.
func (s *state) adoptControllers(discovered controllersDiscoveredMsg) {
	if discovered.err == nil {
		s.controllers = discovered.controllers
	}
	if len(discovered.controllers) > 0 {
		s.controller = discovered.controllers[0]
		return
	}
	s.controller = seal.DefaultController()
}

// invalidate marks the sealed secret as out of date, which makes the review step
// seal again when it is next shown.
func (s *state) invalidate() {
	s.sealed = nil
}
