package wizard

import (
	"context"
	"errors"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
	"github.com/lmarqs/kubeseal-ui/internal/seal"
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
	typing  bool
	loading bool
	spinner spinner
	asked   bool
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

func (s *namespaceStep) Init() tea.Cmd {
	if s.state.options.Namespace != "" && !s.asked {
		s.asked = true
		s.chosen = s.state.options.Namespace
		return s.accept(s.chosen)
	}
	if s.form != nil {
		return nil
	}

	s.loading = true
	cluster := s.state.connection.Cluster

	// Controller discovery starts alongside the namespace list so the certificate is
	// usually ready by the time the review screen needs it.
	return tea.Batch(s.spinner.tick(), listNamespaces(cluster), discoverControllers(cluster))
}

type namespacesLoadedMsg struct {
	namespaces []string
	err        error
}

type controllersDiscoveredMsg struct {
	controllers []seal.Controller
	err         error
}

func listNamespaces(cluster Cluster) tea.Cmd {
	return func() tea.Msg {
		namespaces, err := cluster.Namespaces(context.Background())
		return namespacesLoadedMsg{namespaces: namespaces, err: err}
	}
}

func discoverControllers(cluster Cluster) tea.Cmd {
	return func() tea.Msg {
		controllers, err := cluster.DiscoverControllers(context.Background())
		return controllersDiscoveredMsg{controllers: controllers, err: err}
	}
}

func (s *namespaceStep) Update(message tea.Msg) (step, tea.Cmd) {
	switch typed := message.(type) {
	case namespacesLoadedMsg:
		s.loading = false
		s.build(typed.namespaces, typed.err)
		return s, s.form.Init()

	case controllersDiscoveredMsg:
		// Discovery is a convenience: if it fails, the review screen falls back to
		// the default controller and reports what happened there.
		if typed.err == nil {
			s.state.controllers = typed.controllers
		}
		if len(typed.controllers) > 0 {
			s.state.controller = typed.controllers[0]
		} else {
			s.state.controller = seal.DefaultController()
		}
		return s, nil

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
			s.form = s.typedForm()
			return s, s.form.Init()
		}

		chosen := s.chosen
		if s.typing {
			chosen = s.typed
		}
		return newTypeStep(s.state), s.accept(chosen)
	}

	return s, cmd
}

// accept records the namespace, discarding any sealed secret made for another one.
func (s *namespaceStep) accept(namespace string) tea.Cmd {
	s.state.draft.Namespace = namespace
	s.state.invalidate()
	return nil
}

// build offers the namespaces that could be listed, and always offers typing one
// in as well, since a namespace may not exist yet.
func (s *namespaceStep) build(namespaces []string, err error) {
	if err != nil {
		s.noticeFor(err)
		s.typing = true
		s.form = s.typedForm()
		s.chosen = typeNamespaceOption
		return
	}

	s.typing = false
	options := make([]huh.Option[string], 0, len(namespaces)+1)
	for _, namespace := range namespaces {
		options = append(options, huh.NewOption(namespace, namespace))
	}
	options = append(options, huh.NewOption("✎ type a namespace…", typeNamespaceOption))

	s.chosen = s.preselected(namespaces)
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
