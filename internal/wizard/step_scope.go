package wizard

import (
	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

// scopeStep asks how tightly the sealed secret should be bound to where it lives.
// The consequences are spelled out on screen, because choosing wrongly here is the
// usual reason a sealed secret cannot be decrypted later.
type scopeStep struct {
	state  *state
	form   *huh.Form
	chosen ssv1alpha1.SealingScope
}

func newScopeStep(state *state) *scopeStep {
	return &scopeStep{state: state}
}

func (s *scopeStep) Heading() string { return "How should it be scoped?" }
func (s *scopeStep) Footer() string  { return "↑/↓ choose   enter confirm" }

func (s *scopeStep) Init() tea.Cmd {
	if s.form != nil {
		return nil
	}

	s.chosen = s.state.scope
	s.form = huh.NewForm(huh.NewGroup(
		huh.NewSelect[ssv1alpha1.SealingScope]().
			Options(s.choices()...).
			Value(&s.chosen),
	)).WithShowHelp(false).WithShowErrors(false)

	return s.form.Init()
}

// choices describes each scope in terms of what it allows, using the secret's own
// name and namespace so the consequence is concrete.
func (s *scopeStep) choices() []huh.Option[ssv1alpha1.SealingScope] {
	name := s.state.draft.Name.String()
	namespace := s.state.draft.Namespace

	return []huh.Option[ssv1alpha1.SealingScope]{
		huh.NewOption(
			"strict — only as "+name+" in "+namespace+"  (recommended)",
			ssv1alpha1.StrictScope),
		huh.NewOption(
			"namespace-wide — under any name in "+namespace,
			ssv1alpha1.NamespaceWideScope),
		huh.NewOption(
			"cluster-wide — any name in any namespace  (least restrictive)",
			ssv1alpha1.ClusterWideScope),
	}
}

func (s *scopeStep) Update(message tea.Msg) (step, tea.Cmd) {
	if s.form == nil {
		return s, nil
	}

	model, cmd := s.form.Update(message)
	if form, ok := model.(*huh.Form); ok {
		s.form = form
	}
	if s.form.State == huh.StateCompleted {
		s.state.scope = s.chosen
		s.state.scopeChosen = true
		s.state.invalidate()
		return newEntriesStep(s.state), nil
	}

	return s, cmd
}

func (s *scopeStep) View() string {
	if s.form == nil {
		return indent(mutedStyle.Render("preparing…"))
	}

	explanation := mutedStyle.Render(
		"Anything outside the chosen scope cannot decrypt the secret, so renaming or\n" +
			"moving it later may break it.")

	return s.form.View() + "\n" + indent(explanation)
}
