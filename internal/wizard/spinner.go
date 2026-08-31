package wizard

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// spinnerFrames is the braille cycle, which reads as motion in any terminal font
// that covers box drawing.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const spinnerInterval = 80 * time.Millisecond

// spinner marks work whose duration is unknown, such as a request to the cluster.
type spinner struct {
	frame int
}

func newSpinner() spinner { return spinner{} }

type spinnerTickMsg struct{}

func (s spinner) tick() tea.Cmd {
	return tea.Tick(spinnerInterval, func(time.Time) tea.Msg { return spinnerTickMsg{} })
}

func (s spinner) update() (spinner, tea.Cmd) {
	s.frame = (s.frame + 1) % len(spinnerFrames)
	return s, s.tick()
}

// view renders the spinner ahead of a description of what is being waited on.
func (s spinner) view(what string) string {
	return selectedStyle.Render(spinnerFrames[s.frame]) + " " + what
}
