package wizard

import (
	"fmt"
	"io"

	tea "github.com/charmbracelet/bubbletea"
)

// Result is what the wizard produced.
type Result struct {
	// Sealed is the sealed secret, or nil if the wizard was left before sealing.
	Sealed []byte
	// PrintToStdout is set when the user asked for the manifest on stdout.
	PrintToStdout bool
	// Outcome describes in words what was done, for reporting afterwards.
	Outcome string
}

// Run draws the wizard and returns what it produced.
//
// The interface is drawn on output, which the caller points at stderr, leaving
// stdout free for the sealed secret itself.
func Run(options Options, output io.Writer, input io.Reader) (Result, error) {
	application := newApp(options)

	program := tea.NewProgram(
		application,
		tea.WithOutput(output),
		tea.WithInput(input),
		tea.WithAltScreen(),
	)

	finished, err := program.Run()
	if err != nil {
		return Result{}, fmt.Errorf("running the wizard: %w", err)
	}

	final, ok := finished.(*app)
	if !ok {
		return Result{}, nil
	}

	// Values are overwritten on the way out; Go cannot promise no copy survives, but
	// nothing is left lying around deliberately.
	defer final.state.draft.Entries.Scrub()

	return Result{
		Sealed:        final.state.sealed,
		PrintToStdout: final.state.printToStdout,
		Outcome:       final.state.outcome,
	}, nil
}
