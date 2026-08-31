package wizard

import (
	"context"
	"errors"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
)

// typeNamespaceOption is the sentinel choice that turns the picker into a text
// field, for clusters where listing namespaces is not permitted or the wanted one
// does not exist yet.
const typeNamespaceOption = "\x00type"

// namespaceStep asks which namespace the secret belongs to. Namespaces are listed
// from the cluster where that is allowed, and typed in where it is not.
type namespaceStep struct {
	state   *state
	form    *huh.Form
	chosen  string
	typed   string
	failure error
	notice  string
	// typing is set when the namespace is entered as text rather than picked, which
	// changes which keys do anything.
	typing bool
	// pickable is set once a list of namespaces has been read, which is what makes
	// leaving the text field for the list possible.
	pickable   bool
	namespaces []string
	loaded     bool
	loading    bool
	spinner    spinner
	asked      bool
}

func newNamespaceStep(state *state) *namespaceStep {
	return &namespaceStep{state: state, spinner: newSpinner()}
}

func (s *namespaceStep) Heading() string { return "Which namespace?" }

func (s *namespaceStep) Footer() string {
	switch {
	case s.form == nil:
		return ""
	case s.typing:
		return "enter confirm"
	default:
		return "↑/↓ choose   / filter   enter confirm"
	}
}

// handleEscape leaves the text field for the list of namespaces, when there is a
// list to go back to, rather than leaving the screen.
func (s *namespaceStep) handleEscape() (bool, tea.Cmd) {
	if !s.typing || !s.pickable {
		return false, nil
	}

	s.typing = false
	s.rebuild()

	return true, s.form.Init()
}

func (s *namespaceStep) Init() tea.Cmd {
	// A namespace given with --namespace needs no question, but the screen stays in
	// the stack so it can be revisited.
	if s.state.options.Namespace != "" && !s.asked {
		s.asked = true
		s.chosen = s.state.options.Namespace
		s.accept(s.chosen)
		return advanceTo(newTypeStep(s.state))
	}
	if !spent(s.form) {
		return nil
	}
	if s.loaded {
		s.rebuild()
		return s.form.Init()
	}

	s.loading = true

	return tea.Batch(s.spinner.tick(), listNamespaces(s.state.connection.Cluster))
}

type namespacesLoadedMsg struct {
	namespaces []string
	err        error
}

func listNamespaces(cluster Cluster) tea.Cmd {
	return func() tea.Msg {
		namespaces, err := cluster.Namespaces(context.Background())
		return namespacesLoadedMsg{namespaces: namespaces, err: err}
	}
}

func (s *namespaceStep) Update(message tea.Msg) (step, tea.Cmd) {
	switch typed := message.(type) {
	case advanceMsg:
		return typed.step, typed.step.Init()

	case namespacesLoadedMsg:
		s.loading = false
		s.loaded = true
		s.adopt(typed.namespaces, typed.err)
		s.rebuild()
		return s, s.form.Init()

	case spinnerTickMsg:
		if !s.loading {
			return s, nil
		}
		var cmd tea.Cmd
		s.spinner, cmd = s.spinner.update()
		return s, cmd
	}

	if s.form == nil {
		return s, nil
	}

	model, cmd := s.form.Update(message)
	if form, ok := model.(*huh.Form); ok {
		s.form = form
	}
	if s.form.State == huh.StateCompleted {
		// Choosing "type a namespace" swaps the picker for a text field rather than
		// moving on with nothing.
		if !s.typing && s.chosen == typeNamespaceOption {
			s.typing = true
			s.notice = ""
			s.rebuild()
			return s, s.form.Init()
		}

		chosen := s.chosen
		if s.typing {
			chosen = s.typed
		}
		s.accept(chosen)
		return newTypeStep(s.state), nil
	}

	return s, cmd
}

// accept records the namespace, discarding any sealed secret made for another one.
func (s *namespaceStep) accept(namespace string) {
	s.state.draft.Namespace = namespace
	s.state.invalidate()
}

// adopt records what listing the namespaces produced. A cluster that will not
// list them is not a failure: the namespace is typed in instead.
func (s *namespaceStep) adopt(namespaces []string, err error) {
	if err != nil {
		s.noticeFor(err)
		s.typing = true
		s.chosen = typeNamespaceOption
		return
	}

	s.namespaces = namespaces
	s.pickable = true
	s.typing = false
}

// rebuild makes the form for whichever way the namespace is being given.
func (s *namespaceStep) rebuild() {
	if s.typing {
		s.form = s.typedForm()
		return
	}

	options := make([]huh.Option[string], 0, len(s.namespaces)+1)
	for _, namespace := range s.namespaces {
		options = append(options, huh.NewOption(namespace, namespace))
	}
	options = append(options, huh.NewOption("✎ type a namespace…", typeNamespaceOption))

	s.chosen = s.preselected(s.namespaces)
	s.form = huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Options(options...).
			Filtering(true).
			Value(&s.chosen),
	)).WithShowHelp(false).WithShowErrors(false)
}

// typedForm asks for a namespace as free text, for when it cannot be listed or
// does not exist yet.
func (s *namespaceStep) typedForm() *huh.Form {
	if s.typed == "" {
		s.typed = s.state.draft.Namespace
	}

	return huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Namespace").
			Placeholder("payments").
			Value(&s.typed).
			Validate(validateNamespace),
	)).WithShowHelp(false).WithShowErrors(true)
}

// preselected favours the namespace already chosen, so returning to this screen
// does not lose the answer.
func (s *namespaceStep) preselected(namespaces []string) string {
	for _, namespace := range namespaces {
		if namespace == s.state.draft.Namespace {
			return namespace
		}
	}
	if len(namespaces) > 0 {
		return namespaces[0]
	}
	return typeNamespaceOption
}

func (s *namespaceStep) noticeFor(err error) {
	if errors.Is(err, kube.ErrForbidden) {
		s.notice = markWarning + " you are not allowed to list namespaces here, so type the name instead"
		return
	}
	s.notice = fmt.Sprintf("%s could not list namespaces: %v", markWarning, err)
}

func (s *namespaceStep) View() string {
	if s.loading {
		return indent(s.spinner.view("Listing namespaces…"))
	}
	if s.failure != nil {
		return indent(problem(s.failure, "Check that kubectl can reach this cluster."))
	}
	if s.form == nil {
		return indent(mutedStyle.Render("preparing…"))
	}

	body := s.form.View()
	if s.notice != "" {
		body = warningStyle.Render(s.notice) + "\n\n" + body
	}

	return body
}

// validateNamespace keeps the wizard from producing a name Kubernetes will reject.
func validateNamespace(value string) error {
	if value == "" {
		return errors.New("namespace is required")
	}
	if problems := kube.ValidateNamespace(value); problems != nil {
		return problems
	}
	return nil
}
