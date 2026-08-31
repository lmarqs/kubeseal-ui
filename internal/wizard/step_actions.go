package wizard

import (
	"context"
	"errors"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/charmbracelet/huh"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
	"github.com/lmarqs/kubeseal-ui/internal/seal"
)

// action is something that can be done with a finished sealed secret.
type action int

const (
	actionValidate action = iota
	actionApply
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

	// plan is set while an apply is waiting to be confirmed.
	plan *applyPlan
	// conflict is set when an apply was refused because another tool owns fields.
	conflict bool

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
	switch {
	case s.busy != "":
		return ""
	case s.plan != nil && s.conflict:
		return "f apply anyway   n cancel"
	case s.plan != nil:
		return "y apply   n cancel"
	case s.saveForm != nil:
		return "enter save"
	default:
		return "↑/↓ choose   enter do it"
	}
}

// handleEscape dismisses a pending apply rather than leaving the screen.
func (s *actionsStep) handleEscape() bool {
	if s.plan == nil {
		return false
	}
	s.cancelApply()
	return true
}

func (s *actionsStep) cancelApply() {
	s.plan = nil
	s.conflict = false
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
	if s.state.connection.Applier != nil {
		options = append(options, huh.NewOption("apply it to the cluster", actionApply))
	}
	options = append(options,
		huh.NewOption(s.saveLabel(), actionSave),
		huh.NewOption("print it and quit", actionPrint),
		huh.NewOption("quit without saving", actionQuit),
	)

	return options
}

// saveLabel names the save action after what it actually does.
func (s *actionsStep) saveLabel() string {
	if s.state.merging() {
		return "write it back to " + s.state.options.Merge.Path
	}
	return "save it to a file"
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

	case applyPlannedMsg:
		s.busy = ""
		s.acceptPlan(typed.plan)
		return s, nil

	case appliedMsg:
		s.busy = ""
		return s.afterApply(typed.err)

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
	if s.plan != nil {
		return s.confirmApply(message)
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
	case actionApply:
		return s, s.startApply()
	case actionSave:
		s.askWhereToSave()
		return s, s.saveForm.Init()
	case actionPrint:
		return s, finishPrinting()
	default:
		return s, finish("nothing written")
	}
}

// startApply works out what applying would change before anything is sent.
func (s *actionsStep) startApply() tea.Cmd {
	s.busy = "Checking what is already in the cluster…"
	s.message = ""
	return tea.Batch(s.spinner.tick(), planApply(s.state))
}

// acceptPlan shows what the apply would do, or explains why it cannot happen.
func (s *actionsStep) acceptPlan(plan applyPlan) {
	switch {
	case plan.err != nil:
		s.failure = plan.err.Error()
		if hint := applyFailureHint(plan.err); hint != "" {
			s.failure += "\n" + hint
		}
	case !plan.supported:
		s.failure = "this cluster has no SealedSecret resource, so the controller " +
			"does not appear to be installed"
	default:
		s.plan = &plan
	}
}

// confirmApply waits for an explicit yes, because applying changes the cluster.
func (s *actionsStep) confirmApply(message tea.Msg) (step, tea.Cmd) {
	key, ok := message.(tea.KeyMsg)
	if !ok {
		return s, nil
	}

	switch key.String() {
	case "y", "enter":
		if s.conflict {
			return s, nil
		}
		return s, s.apply(false)
	case "f":
		if !s.conflict {
			return s, nil
		}
		return s, s.apply(true)
	case "n", "q":
		s.cancelApply()
	}

	return s, nil
}

func (s *actionsStep) apply(force bool) tea.Cmd {
	s.busy = "Applying…"
	s.failure = ""
	return tea.Batch(s.spinner.tick(), applyNow(s.state, force))
}

// afterApply reports the outcome, offering to force only when that is the problem.
func (s *actionsStep) afterApply(err error) (step, tea.Cmd) {
	if err == nil {
		return s, finish("applied " + s.state.draft.Name.String() + " to " + s.state.contextName)
	}

	s.failure = err.Error()
	if hint := applyFailureHint(err); hint != "" {
		s.failure += "\n" + hint
	}
	s.conflict = errors.Is(err, kube.ErrConflict)
	if !s.conflict {
		s.plan = nil
	}

	return s, nil
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
		s.savePath = s.defaultSavePath()
	}

	s.saveForm = huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Where should it be written?").
			Value(&s.savePath),
	)).WithShowHelp(false).WithShowErrors(true)
}

// defaultSavePath offers the file being edited, or a name derived from the secret.
func (s *actionsStep) defaultSavePath() string {
	if s.state.merging() {
		return s.state.options.Merge.Path
	}
	return s.state.options.DefaultOutputPath(s.state.draft.Name.String())
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

	if s.plan != nil {
		return s.confirmationView()
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

// confirmationView describes the change about to be made to the cluster.
func (s *actionsStep) confirmationView() string {
	sections := []string{indent(s.plan.describe(s.state.draft.Namespace, s.state.draft.Name.String()))}

	if s.failure != "" {
		sections = append(sections, indent(failureStyle.Render(markFailed+" "+s.failure)))
	}
	if s.conflict {
		sections = append(sections, indent(warningStyle.Render(
			markWarning+" applying anyway takes ownership of the contested fields")))
	}

	return strings.Join(sections, "\n\n")
}
