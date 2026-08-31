package wizard

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// typeStep asks what kind of secret this is. It comes before the questions about
// contents, because the kind decides what those questions are.
type typeStep struct {
	state  *state
	form   *huh.Form
	chosen secret.Type
}

func newTypeStep(state *state) *typeStep {
	return &typeStep{state: state}
}

func (s *typeStep) Heading() string { return "What kind of secret?" }
func (s *typeStep) Footer() string  { return "↑/↓ choose   enter confirm" }

func (s *typeStep) Init() tea.Cmd {
	if !spent(s.form) {
		return nil
	}

	s.chosen = s.state.draft.Type
	if s.chosen == "" {
		s.chosen = secret.TypeOpaque
	}

	s.form = huh.NewForm(huh.NewGroup(
		huh.NewSelect[secret.Type]().
			Options(
				huh.NewOption("generic — your own keys and values", secret.TypeOpaque),
				huh.NewOption("image pull secret — credentials for a registry", secret.TypeDockerRegistry),
				huh.NewOption("TLS — a certificate and its private key", secret.TypeTLS),
			).
			Value(&s.chosen),
	)).WithShowHelp(false).WithShowErrors(false)

	return s.form.Init()
}

func (s *typeStep) Update(message tea.Msg) (step, tea.Cmd) {
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

	// Entries collected for one kind of secret rarely make sense for another, so
	// they are dropped rather than carried into a form that cannot show them.
	if s.chosen != s.state.draft.Type && s.state.draft.Entries.Len() > 0 {
		s.state.draft.Entries.Scrub()
	}

	s.state.draft.Type = s.chosen
	s.state.invalidate()

	return newNameStep(s.state), nil
}

func (s *typeStep) View() string {
	if s.form == nil {
		return indent(mutedStyle.Render("preparing…"))
	}

	body := s.form.View()
	if s.state.draft.Entries.Len() > 0 && s.chosen != s.state.draft.Type {
		body += "\n" + indent(warningStyle.Render(
			markWarning+" changing the kind of secret discards the entries already given"))
	}

	return body
}
