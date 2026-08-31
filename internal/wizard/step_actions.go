package wizard

import (
	"context"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/charmbracelet/huh"

	"github.com/lmarqs/kubeseal-ui/internal/seal"
)

// action is something that can be done with a finished sealed secret.
type action int

const (
	actionValidate action = iota
	actionSave
	actionPrint
	actionQuit
)

// actionsStep offers what to do with the sealed secret. It can be returned to, so
// validating and then saving is one pass rather than two.
type actionsStep struct {
	state *state

	form   *huh.Form
	chosen action

	saveForm *huh.Form
	savePath string

	busy    string
	message string
	failure string
	spinner spinner
}

func newActionsStep(state *state) *actionsStep {
	return &actionsStep{state: state, spinner: newSpinner()}
}

func (s *actionsStep) Heading() string { return "What now?" }

func (s *actionsStep) Footer() string {
	if s.saveForm != nil {
		return "enter save"
	}
	if s.busy != "" {
		return ""
	}
	return "↑/↓ choose   enter do it"
}

func (s *actionsStep) Init() tea.Cmd {
	if s.form != nil {
		return nil
	}

	s.form = huh.NewForm(huh.NewGroup(
		huh.NewSelect[action]().
			Options(s.choices()...).
			Value(&s.chosen),
	)).WithShowHelp(false).WithShowErrors(false)

	return s.form.Init()
}

// choices leaves out what cannot work: validation needs a reachable controller.
func (s *actionsStep) choices() []huh.Option[action] {
	options := make([]huh.Option[action], 0, 4)

	if s.canValidate() {
		options = append(options, huh.NewOption("check the controller can decrypt it", actionValidate))
	}
	options = append(options,
		huh.NewOption("save it to a file", actionSave),
		huh.NewOption("print it and quit", actionPrint),
		huh.NewOption("quit without saving", actionQuit),
	)

	return options
}

// canValidate reports whether asking the controller is possible at all.
func (s *actionsStep) canValidate() bool {
	if s.state.connection.Validator == nil {
		return false
	}
	return !s.state.certificate.Stale() && s.state.certificate.Origin != seal.OriginFile
}

type validatedMsg struct {
	err error
}

type savedMsg struct {
	path string
	err  error
}

func (s *actionsStep) Update(message tea.Msg) (step, tea.Cmd) {
	switch typed := message.(type) {
	case validatedMsg:
		s.busy = ""
		if typed.err != nil {
			s.failure = typed.err.Error()
			return s, nil
		}
		s.message = markOK + " the controller can decrypt this sealed secret"
		return s, nil

	case savedMsg:
		s.busy = ""
		if typed.err != nil {
			s.failure = typed.err.Error()
			return s, nil
		}
		return s, finish("wrote " + typed.path)

	case spinnerTickMsg:
		if s.busy == "" {
			return s, nil
		}
		var cmd tea.Cmd
		s.spinner, cmd = s.spinner.update()
		return s, cmd
	}

	if s.busy != "" {
		return s, nil
	}
	if s.saveForm != nil {
		return s.updateSave(message)
	}

	return s.updateChoice(message)
}

func (s *actionsStep) updateChoice(message tea.Msg) (step, tea.Cmd) {
	model, cmd := s.form.Update(message)
	if form, ok := model.(*huh.Form); ok {
		s.form = form
	}
	if s.form.State != huh.StateCompleted {
		return s, cmd
	}

	// Reset so the menu works again after an action that stays on this screen.
	s.form.State = huh.StateNormal
	s.failure = ""

	switch s.chosen {
	case actionValidate:
		return s, s.validate()
	case actionSave:
		s.askWhereToSave()
		return s, s.saveForm.Init()
	case actionPrint:
		return s, finishPrinting()
	default:
		return s, finish("nothing written")
	}
}

func (s *actionsStep) updateSave(message tea.Msg) (step, tea.Cmd) {
	model, cmd := s.saveForm.Update(message)
	if form, ok := model.(*huh.Form); ok {
		s.saveForm = form
	}
	if s.saveForm.State != huh.StateCompleted {
		return s, cmd
	}

	s.saveForm = nil
	return s, s.save()
}

func (s *actionsStep) askWhereToSave() {
	if s.savePath == "" {
		s.savePath = s.state.options.DefaultOutputPath(s.state.draft.Name.String())
	}

	s.saveForm = huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Where should it be written?").
			Value(&s.savePath),
	)).WithShowHelp(false).WithShowErrors(true)
}

func (s *actionsStep) validate() tea.Cmd {
	s.busy = "Asking the controller…"
	return tea.Batch(s.spinner.tick(), s.validateCmd())
}

// validateCmd is the work itself, kept apart from the spinner that accompanies it.
func (s *actionsStep) validateCmd() tea.Cmd {
	wizardState := s.state

	return func() tea.Msg {
		err := wizardState.connection.Validator.Validate(
			context.Background(), wizardState.controller, wizardState.sealed)
		return validatedMsg{err: err}
	}
}

func (s *actionsStep) save() tea.Cmd {
	s.busy = "Writing…"
	return tea.Batch(s.spinner.tick(), s.saveCmd())
}

// saveCmd is the work itself, kept apart from the spinner that accompanies it.
func (s *actionsStep) saveCmd() tea.Cmd {
	path := s.savePath
	wizardState := s.state

	return func() tea.Msg {
		err := wizardState.options.Writer.Write(path, wizardState.sealed)
		return savedMsg{path: path, err: err}
	}
}

func (s *actionsStep) View() string {
	if s.busy != "" {
		return indent(s.spinner.view(s.busy))
	}

	form := s.form
	if s.saveForm != nil {
		form = s.saveForm
	}

	sections := make([]string, 0, 4)
	if form != nil {
		sections = append(sections, form.View())
	}

	if !s.canValidate() {
		sections = append(sections, indent(mutedStyle.Render(
			"Checking with the controller is not possible from here.")))
	}
	if s.message != "" {
		sections = append(sections, indent(successStyle.Render(s.message)))
	}
	if s.failure != "" {
		sections = append(sections, indent(failureStyle.Render(markFailed+" "+s.failure)))
	}

	return strings.Join(sections, "\n\n")
}
