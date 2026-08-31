package wizard

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
	"github.com/lmarqs/kubeseal-ui/internal/seal"
)

// contextStep asks which cluster to seal for. Contexts are read from the local
// kubeconfig, so this screen never waits on the network.
type contextStep struct {
	state   *state
	form    *huh.Form
	chosen  string
	failure error
	opening bool
	spinner spinner
	// contexts is kept so that returning to this screen redraws the list rather
	// than reading the kubeconfig again.
	contexts []kube.Context
	current  string
	loaded   bool
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
	if !spent(s.form) {
		return nil
	}

	if s.loaded {
		s.buildForm()
		return s.form.Init()
	}

	return loadContexts(s.state.options.Clusters)
}

func loadContexts(clusters Clusters) tea.Cmd {
	return func() tea.Msg {
		contexts, current, err := clusters.Contexts()
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

type controllersDiscoveredMsg struct {
	controllers []seal.Controller
	err         error
}

func discoverControllers(cluster Cluster) tea.Cmd {
	return func() tea.Msg {
		controllers, err := cluster.DiscoverControllers(context.Background())
		return controllersDiscoveredMsg{controllers: controllers, err: err}
	}
}

func (s *contextStep) Update(message tea.Msg) (step, tea.Cmd) {
	switch typed := message.(type) {
	case contextsLoadedMsg:
		if typed.err != nil {
			s.failure = typed.err
			return s, nil
		}
		s.contexts, s.current, s.loaded = typed.contexts, typed.current, true
		s.buildForm()
		return s, s.form.Init()

	case clusterOpenedMsg:
		s.opening = false
		if typed.err != nil {
			s.failure = typed.err
			// The list comes back so another cluster can be tried; a cluster that
			// cannot be reached must not be the end of the wizard.
			return s, s.reopenList()
		}
		s.state.contextName = s.chosen
		s.state.connection = typed.connection
		s.state.invalidate()
		// Discovery starts as soon as there is a cluster to ask, so the certificate is
		// usually ready by the time the review screen needs it. It runs on every path,
		// including editing a file, where no further questions are asked.
		return afterCluster(s.state), discoverControllers(typed.connection.Cluster)

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

// reopenList puts the list of clusters back on screen after an attempt to open
// one failed, keeping the failure visible above it.
func (s *contextStep) reopenList() tea.Cmd {
	if !s.loaded {
		return loadContexts(s.state.options.Clusters)
	}
	s.buildForm()
	return s.form.Init()
}

// buildForm offers the contexts, with the one already chosen selected so that
// pressing enter does the expected thing.
func (s *contextStep) buildForm() {
	options := make([]huh.Option[string], 0, len(s.contexts))
	for _, context := range s.contexts {
		label := context.Name
		if context.Name == s.current {
			label += "  (current)"
		}
		if context.Namespace != "" {
			label += mutedStyle.Render("  namespace " + context.Namespace)
		}
		options = append(options, huh.NewOption(label, context.Name))
	}

	if s.chosen == "" {
		s.chosen = s.current
	}
	s.form = huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Options(options...).
			Filtering(true).
			Value(&s.chosen),
	)).WithShowHelp(false).WithShowErrors(false)
}

func (s *contextStep) openCluster() tea.Cmd {
	s.opening = true
	s.failure = nil
	chosen := s.chosen

	return tea.Batch(s.spinner.tick(), func() tea.Msg {
		connection, err := s.state.options.Clusters.Open(chosen)
		return clusterOpenedMsg{connection: connection, err: err}
	})
}

func (s *contextStep) View() string {
	if s.opening {
		return indent(s.spinner.view(fmt.Sprintf("Connecting to %s…", s.chosen)))
	}
	if s.form == nil {
		if s.failure != nil {
			return indent(problem(s.failure, "Check that kubectl can reach this cluster."))
		}
		return indent(s.spinner.view("Reading kubeconfig…"))
	}

	if s.failure != nil {
		return indent(problem(s.failure, "Choose another cluster, or check that kubectl can reach this one.")) +
			"\n\n" + s.form.View()
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
