package wizard

import (
	"errors"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// dockerStep collects registry credentials and turns them into the single
// .dockerconfigjson entry an image pull secret holds. It replaces the entries
// screen, since the shape of this secret is fixed.
type dockerStep struct {
	state   *state
	form    *huh.Form
	auth    secret.DockerAuth
	failure string
}

func newDockerStep(state *state) *dockerStep {
	return &dockerStep{state: state}
}

func (s *dockerStep) Heading() string { return "Which registry, and as whom?" }
func (s *dockerStep) Footer() string  { return "enter next field" }

func (s *dockerStep) Init() tea.Cmd {
	if !spent(s.form) {
		return nil
	}

	if s.auth.Server == "" {
		s.auth.Server = secret.DefaultRegistry
	}

	s.form = huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Registry").
			Description("Docker Hub by default.").
			Value(&s.auth.Server).
			Validate(required("registry")),
		huh.NewInput().
			Title("Username").
			Value(&s.auth.Username).
			Validate(required("username")),
		huh.NewInput().
			Title("Password or token").
			EchoMode(huh.EchoModePassword).
			Value(&s.auth.Password).
			Validate(required("password")),
		huh.NewInput().
			Title("Email").
			Description("Optional; most registries ignore it.").
			Value(&s.auth.Email),
	)).WithShowHelp(false).WithShowErrors(true)

	return s.form.Init()
}

func (s *dockerStep) Update(message tea.Msg) (step, tea.Cmd) {
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

	entry, err := secret.DockerEntry(s.auth)
	if err != nil {
		s.failure = err.Error()
		// The answers are kept, so the form comes back filled in for correcting.
		s.form = nil
		return s, s.Init()
	}

	s.state.draft.Entries.Set(entry)
	s.state.invalidate()

	return newReviewStep(s.state), nil
}

func (s *dockerStep) View() string {
	if s.form == nil {
		return indent(mutedStyle.Render("preparing…"))
	}

	body := s.form.View()
	if s.failure != "" {
		body += "\n" + indent(failureStyle.Render(markFailed+" "+s.failure))
	}

	return body
}

// required rejects a blank answer, naming the field so the message is useful.
func required(what string) func(string) error {
	return func(value string) error {
		if strings.TrimSpace(value) == "" {
			return errors.New(what + " is required")
		}
		return nil
	}
}
