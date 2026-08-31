package wizard

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// nameStep asks what the secret is called, validating as it is typed so a name
// Kubernetes would reject is caught here rather than on apply.
type nameStep struct {
	state *state
	form  *huh.Form
	typed string
	asked bool
}

func newNameStep(state *state) *nameStep {
	return &nameStep{state: state}
}

func (s *nameStep) Heading() string { return "What is the secret called?" }
func (s *nameStep) Footer() string  { return "enter confirm" }

func (s *nameStep) Init() tea.Cmd {
	if s.state.options.Name != "" && !s.asked {
		s.asked = true
		if name, err := secret.NewName(s.state.options.Name); err == nil {
			s.state.draft.Name = name
			s.state.invalidate()
			return advanceTo(newScopeStep(s.state))
		}
	}
	if s.form != nil {
		return nil
	}

	s.typed = s.state.draft.Name.String()
	s.form = huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Secret name").
			Placeholder("db-creds").
			Value(&s.typed).
			Validate(func(value string) error {
				_, err := secret.NewName(value)
				return err
			}),
	)).WithShowHelp(false).WithShowErrors(true)

	return s.form.Init()
}

func (s *nameStep) Update(message tea.Msg) (step, tea.Cmd) {
	if next, ok := message.(advanceMsg); ok {
		return next.step, next.step.Init()
	}
	if s.form == nil {
		return s, nil
	}

	model, cmd := s.form.Update(message)
	if form, ok := model.(*huh.Form); ok {
		s.form = form
	}
	if s.form.State == huh.StateCompleted {
		name, err := secret.NewName(s.typed)
		if err != nil {
			return s, nil
		}
		s.state.draft.Name = name
		s.state.invalidate()
		return newScopeStep(s.state), nil
	}

	return s, cmd
}

func (s *nameStep) View() string {
	if s.form == nil {
		return indent(mutedStyle.Render("preparing…"))
	}
	return s.form.View()
}

// advanceMsg carries a step that a prefilled answer skipped ahead to.
type advanceMsg struct {
	step step
}

func advanceTo(next step) tea.Cmd {
	return func() tea.Msg { return advanceMsg{step: next} }
}
