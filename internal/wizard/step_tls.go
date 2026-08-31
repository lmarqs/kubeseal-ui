package wizard

import (
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// tlsStep collects a certificate and its private key from files and checks they
// belong together before either is sealed.
type tlsStep struct {
	state           *state
	form            *huh.Form
	certificatePath string
	keyPath         string
	details         string
	warning         string
	failure         string
}

func newTLSStep(state *state) *tlsStep {
	return &tlsStep{state: state}
}

func (s *tlsStep) Heading() string { return "Where are the certificate and key?" }
func (s *tlsStep) Footer() string  { return "enter next field" }

func (s *tlsStep) Init() tea.Cmd {
	if !spent(s.form) {
		return nil
	}

	s.form = huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Certificate").
			Placeholder("./tls.crt").
			Value(&s.certificatePath).
			Validate(validateReadableFile),
		huh.NewInput().
			Title("Private key").
			Placeholder("./tls.key").
			Value(&s.keyPath).
			Validate(validateReadableFile),
	)).WithShowHelp(false).WithShowErrors(true)

	return s.form.Init()
}

func (s *tlsStep) Update(message tea.Msg) (step, tea.Cmd) {
	if s.form == nil {
		return s, nil
	}

	model, cmd := s.form.Update(message)
	if form, ok := model.(*huh.Form); ok {
		s.form = form
	}
	if s.form.State != huh.StateCompleted {
		return s, cmd
	}

	if err := s.collect(); err != nil {
		s.failure = err.Error()
		// The paths are kept, so the form comes back filled in for correcting.
		s.form = nil
		return s, s.Init()
	}

	return newReviewStep(s.state), nil
}

// collect reads both files, checks the pair, and describes the certificate so the
// right one can be recognised before sealing.
func (s *tlsStep) collect() error {
	certificate, err := os.ReadFile(expandHome(s.certificatePath))
	if err != nil {
		return err
	}

	key, err := os.ReadFile(expandHome(s.keyPath))
	if err != nil {
		return err
	}

	entries, err := secret.TLSEntries(certificate, key)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		s.state.draft.Entries.Set(entry)
	}
	s.state.invalidate()
	s.describe(certificate)

	return nil
}

// describe records what the certificate says about itself, and warns when it has
// already expired — sealing it would work but deploying it would not.
func (s *tlsStep) describe(certificate []byte) {
	details, err := secret.DescribeCertificate(certificate)
	if err != nil {
		return
	}

	s.details = details.Summary()
	if details.Expired() {
		s.warning = markWarning + " this certificate has already expired"
	}
}

func (s *tlsStep) View() string {
	if s.form == nil {
		return indent(mutedStyle.Render("preparing…"))
	}

	body := s.form.View()
	if s.details != "" {
		body += "\n" + indent(mutedStyle.Render(s.details))
	}
	if s.warning != "" {
		body += "\n" + indent(warningStyle.Render(s.warning))
	}
	if s.failure != "" {
		body += "\n" + indent(failureStyle.Render(markFailed+" "+s.failure))
	}

	return body
}
