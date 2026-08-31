package wizard

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// The wizard needs this much room to lay out a breadcrumb, a body and a footer.
const (
	minimumWidth  = 80
	minimumHeight = 20
)

// step is one screen. Returning a different step from Update descends into it;
// the app itself handles going back, so steps never need to know what came before.
type step interface {
	// Init starts any work the step needs, such as loading data.
	Init() tea.Cmd
	// Update handles one message and returns the step to show next.
	Update(tea.Msg) (step, tea.Cmd)
	// View renders the body of the screen.
	View() string
	// Heading names the question being asked.
	Heading() string
	// Footer lists the keys that do something on this screen.
	Footer() string
}

// app is the root model. It owns the frame around every screen, the keys that mean
// the same thing everywhere, and the stack that makes going back possible.
type app struct {
	state *state
	stack []step

	width  int
	height int

	// quitting is set once the wizard is finishing, so the frame is not redrawn.
	quitting bool
}

// newApp builds the wizard, starting at the first question that has not already
// been answered by a flag.
func newApp(options Options) *app {
	wizardState := &state{options: options}
	wizardState.draft.Type = secret.TypeOpaque

	application := &app{state: wizardState}
	application.stack = []step{newContextStep(wizardState)}

	return application
}

func (a *app) Init() tea.Cmd {
	return a.current().Init()
}

func (a *app) current() step {
	return a.stack[len(a.stack)-1]
}

func (a *app) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch typed := message.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = typed.Width, typed.Height
		return a, nil

	case tea.KeyMsg:
		// Ctrl+C belongs to the terminal: leave immediately rather than treating it
		// as a wizard key.
		if typed.Type == tea.KeyCtrlC {
			a.quitting = true
			a.state.draft.Entries.Scrub()
			return a, tea.Quit
		}
		if typed.String() == "esc" && a.canGoBack() {
			return a, a.goBack()
		}

	case finishedMsg:
		a.quitting = true
		a.state.outcome = typed.outcome
		a.state.printToStdout = typed.print
		return a, tea.Quit
	}

	next, cmd := a.current().Update(message)
	if next == nil {
		return a, cmd
	}

	if next != a.current() {
		a.stack = append(a.stack, next)
		return a, tea.Batch(cmd, next.Init())
	}

	return a, cmd
}

// canGoBack reports whether there is an earlier screen to return to.
func (a *app) canGoBack() bool {
	return len(a.stack) > 1
}

// goBack returns to the previous screen, keeping everything collected so far.
func (a *app) goBack() tea.Cmd {
	a.stack = a.stack[:len(a.stack)-1]
	return a.current().Init()
}

func (a *app) View() string {
	if a.quitting {
		return ""
	}
	if a.tooSmall() {
		return a.resizeNotice()
	}

	current := a.current()

	sections := []string{
		titleStyle.Render("ksui") + mutedStyle.Render("  ·  seal a Kubernetes secret"),
		a.breadcrumb(),
		"",
		headingStyle.Render(current.Heading()),
		"",
		current.View(),
	}

	return strings.Join(sections, "\n") + "\n\n" + mutedStyle.Render(a.footer(current))
}

// tooSmall reports whether the terminal is below the size the wizard needs. A zero
// size means no resize message has arrived yet, which is not a failure.
func (a *app) tooSmall() bool {
	if a.width == 0 || a.height == 0 {
		return false
	}
	return a.width < minimumWidth || a.height < minimumHeight
}

func (a *app) resizeNotice() string {
	return warningStyle.Render(fmt.Sprintf(
		"%s terminal is %d×%d; ksui needs at least %d×%d.",
		markWarning, a.width, a.height, minimumWidth, minimumHeight,
	)) + "\n" + mutedStyle.Render("Resize the window to continue.")
}

// breadcrumb shows the choices made so far, so the answers stay visible while
// later questions are answered.
func (a *app) breadcrumb() string {
	parts := make([]string, 0, 5)

	if a.state.contextName != "" {
		parts = append(parts, "cluster "+a.state.contextName)
	}
	if a.state.draft.Namespace != "" {
		parts = append(parts, "namespace "+a.state.draft.Namespace)
	}
	if a.state.draft.Name != "" {
		parts = append(parts, "secret "+a.state.draft.Name.String())
	}
	if a.state.scopeChosen {
		parts = append(parts, "scope "+a.state.scope.String())
	}
	if count := a.state.draft.Entries.Len(); count > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", count, pluralise(count, "entry", "entries")))
	}

	if len(parts) == 0 {
		return mutedStyle.Render("nothing chosen yet")
	}

	return mutedStyle.Render(strings.Join(parts, " ▸ "))
}

// footer combines the step's own keys with the ones that always work.
func (a *app) footer(current step) string {
	keys := current.Footer()
	if a.canGoBack() {
		keys += "   esc back"
	}
	return keys + "   ctrl+c quit"
}

// finishedMsg ends the wizard, reporting what was done.
type finishedMsg struct {
	outcome string
	// print asks the caller to write the sealed secret to stdout.
	print bool
}

func finish(outcome string) tea.Cmd {
	return func() tea.Msg { return finishedMsg{outcome: outcome} }
}

// finishPrinting ends the wizard and hands the sealed secret back for stdout.
func finishPrinting() tea.Cmd {
	return func() tea.Msg { return finishedMsg{outcome: "printed to stdout", print: true} }
}

func pluralise(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

// indent lays out a block of lines inside the frame.
func indent(body string) string {
	return lipgloss.NewStyle().PaddingLeft(2).Render(body)
}
