package wizard

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
)

// contextStep asks which cluster to seal for. Contexts are read from the local
// kubeconfig, so this screen never waits on the network.
type contextStep struct {
	state    *state
	form     *huh.Form
	chosen   string
	failure  error
	opening  bool
	spinner  spinner
	prefixed bool
}

func newContextStep(state *state) *contextStep {
	return &contextStep{state: state, spinner: newSpinner()}
}

func (s *contextStep) Heading() string { return "Which cluster?" }

func (s *contextStep) Footer() string {
	if s.form == nil || s.opening {
		return ""
	}
	return "↑/↓ choose   / filter   enter confirm"
}

func (s *contextStep) Init() tea.Cmd {
	// A cluster chosen with --context needs no question, but the screen stays in
	// the stack so it can be revisited.
	if s.state.options.Context != "" && !s.prefixed {
		s.prefixed = true
		s.chosen = s.state.options.Context
		return s.openCluster()
	}
	if s.form != nil {
		return nil
	}

	return func() tea.Msg {
		contexts, current, err := s.state.options.Clusters.Contexts()
		return contextsLoadedMsg{contexts: contexts, current: current, err: err}
	}
}

type contextsLoadedMsg struct {
	contexts []kube.Context
	current  string
	err      error
}

type clusterOpenedMsg struct {
	connection Connection
	err        error
}

func (s *contextStep) Update(message tea.Msg) (step, tea.Cmd) {
	switch typed := message.(type) {
	case contextsLoadedMsg:
		if typed.err != nil {
			s.failure = typed.err
			return s, nil
		}
		s.buildForm(typed.contexts, typed.current)
		return s, s.form.Init()

	case clusterOpenedMsg:
		s.opening = false
		if typed.err != nil {
			s.failure = typed.err
			return s, nil
		}
		s.state.contextName = s.chosen
		s.state.connection = typed.connection
		s.state.invalidate()
		return afterCluster(s.state), nil

	case spinnerTickMsg:
		if !s.opening {
			return s, nil
		}
		var cmd tea.Cmd
		s.spinner, cmd = s.spinner.update()
		return s, cmd
	}

	if s.form == nil || s.opening {
		return s, nil
	}

	model, cmd := s.form.Update(message)
	if form, ok := model.(*huh.Form); ok {
		s.form = form
	}
	if s.form.State == huh.StateCompleted {
		return s, s.openCluster()
	}

	return s, cmd
}

// buildForm offers the contexts, with the current one selected so that pressing
// enter does the expected thing.
func (s *contextStep) buildForm(contexts []kube.Context, current string) {
	options := make([]huh.Option[string], 0, len(contexts))
	for _, context := range contexts {
		label := context.Name
		if context.Name == current {
			label += "  (current)"
		}
		if context.Namespace != "" {
			label += mutedStyle.Render("  namespace " + context.Namespace)
		}
		options = append(options, huh.NewOption(label, context.Name))
	}

	s.chosen = current
	s.form = huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Options(options...).
			Filtering(true).
			Value(&s.chosen),
	)).WithShowHelp(false).WithShowErrors(false)
}

func (s *contextStep) openCluster() tea.Cmd {
	s.opening = true
	chosen := s.chosen

	return tea.Batch(s.spinner.tick(), func() tea.Msg {
		connection, err := s.state.options.Clusters.Open(chosen)
		return clusterOpenedMsg{connection: connection, err: err}
	})
}

func (s *contextStep) View() string {
	if s.failure != nil {
		return indent(problem(s.failure, "Check that kubectl can reach this cluster."))
	}
	if s.opening {
		return indent(s.spinner.view(fmt.Sprintf("Connecting to %s…", s.chosen)))
	}
	if s.form == nil {
		return indent(s.spinner.view("Reading kubeconfig…"))
	}

	return s.form.View()
}

// afterCluster is the next question once a cluster is chosen. When editing an
// existing file there is nothing else to ask: its namespace, name, kind and scope
// are already decided.
func afterCluster(state *state) step {
	if state.merging() {
		return newEntriesStep(state)
	}
	return newNamespaceStep(state)
}

// problem renders a failure with something the user can do about it.
func problem(err error, hint string) string {
	return failureStyle.Render(markFailed+" "+err.Error()) + "\n\n" + mutedStyle.Render(hint)
}
