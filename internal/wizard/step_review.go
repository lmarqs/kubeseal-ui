package wizard

import (
	"context"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/lmarqs/kubeseal-ui/internal/seal"
	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// reviewStep shows the sealed secret before anything is done with it. What is on
// screen here is already encrypted, so it is safe to display in full.
type reviewStep struct {
	state    *state
	viewport viewport.Model
	ready    bool
	working  string
	failure  error
	spinner  spinner
}

func newReviewStep(state *state) *reviewStep {
	return &reviewStep{state: state, spinner: newSpinner()}
}

func (s *reviewStep) Heading() string { return "Ready to seal" }

func (s *reviewStep) Footer() string {
	if !s.ready {
		return ""
	}
	return "↑/↓ scroll   enter continue"
}

func (s *reviewStep) Init() tea.Cmd {
	// Anything the user changed upstream cleared the sealed secret, so it is sealed
	// again here. The certificate is usually cached, making this instant.
	if s.state.sealed != nil {
		s.ready = true
		s.load()
		return nil
	}

	s.ready = false
	s.working = "Fetching the controller certificate…"

	return tea.Batch(s.spinner.tick(), s.sealNow())
}

type sealedMsg struct {
	sealed      []byte
	certificate seal.Certificate
	err         error
}

// sealNow obtains a certificate and encrypts the draft with it.
func (s *reviewStep) sealNow() tea.Cmd {
	wizardState := s.state

	return func() tea.Msg {
		built, err := secret.Build(wizardState.draft)
		if err != nil {
			return sealedMsg{err: err}
		}

		certificate, err := wizardState.connection.Certificates.Resolve(context.Background(), wizardState.controller)
		if err != nil {
			return sealedMsg{err: err}
		}

		sealed, err := seal.NewSealer(certificate.PublicKey).
			Seal(built, wizardState.scope, seal.FormatYAML)
		if err != nil {
			return sealedMsg{err: err}
		}

		return sealedMsg{sealed: sealed, certificate: certificate}
	}
}

func (s *reviewStep) Update(message tea.Msg) (step, tea.Cmd) {
	switch typed := message.(type) {
	case sealedMsg:
		s.working = ""
		if typed.err != nil {
			s.failure = typed.err
			return s, nil
		}
		s.state.sealed = typed.sealed
		s.state.certificate = typed.certificate
		s.ready = true
		s.load()
		return s, nil

	case spinnerTickMsg:
		if s.ready || s.failure != nil {
			return s, nil
		}
		var cmd tea.Cmd
		s.spinner, cmd = s.spinner.update()
		return s, cmd

	case tea.WindowSizeMsg:
		s.viewport.Width = typed.Width - 4
		s.viewport.Height = viewportHeight(typed.Height)
		return s, nil

	case tea.KeyMsg:
		if !s.ready {
			return s, nil
		}
		if typed.String() == "enter" {
			return newActionsStep(s.state), nil
		}
		var cmd tea.Cmd
		s.viewport, cmd = s.viewport.Update(message)
		return s, cmd
	}

	return s, nil
}

// viewportHeight leaves room for the frame around the manifest while keeping the
// pane usable on a short terminal.
func viewportHeight(terminalHeight int) int {
	const frame = 16
	if remaining := terminalHeight - frame; remaining > 5 {
		return remaining
	}
	return 5
}

// load puts the sealed secret in the scrollable pane.
func (s *reviewStep) load() {
	if s.viewport.Width == 0 {
		s.viewport = viewport.New(76, 12)
	}
	s.viewport.SetContent(string(s.state.sealed))
	s.viewport.GotoTop()
}

func (s *reviewStep) View() string {
	if s.failure != nil {
		return indent(problem(s.failure,
			"Check that the controller is reachable, or restart with --cert to seal offline."))
	}
	if !s.ready {
		return indent(s.spinner.view(s.working))
	}

	return s.viewport.View() + "\n\n" + indent(s.certificateLine())
}

// certificateLine says which controller and certificate the secret was sealed for,
// since that decides whether it can ever be decrypted.
func (s *reviewStep) certificateLine() string {
	parts := []string{"controller " + s.state.controller.String()}

	switch {
	case s.state.certificate.Stale():
		parts = append(parts, warningStyle.Render(markWarning+" certificate from the cache; controller unreachable"))
	case s.state.certificate.Origin == seal.OriginCache:
		parts = append(parts, mutedStyle.Render("certificate from the cache"))
	case s.state.certificate.Origin == seal.OriginFile:
		parts = append(parts, mutedStyle.Render("certificate from "+s.state.certificate.Source))
	default:
		parts = append(parts, successStyle.Render(markOK+" certificate fetched"))
	}

	return mutedStyle.Render(strings.Join(parts, "   "))
}
