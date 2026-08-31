package wizard

import (
	"context"
	"errors"
	"fmt"
	"io"

	tea "github.com/charmbracelet/bubbletea"
)

// ErrInterrupted reports that the wizard was abandoned by an interrupt rather
// than left through one of its own actions, so the caller can tell the two apart
// when choosing an exit code.
var ErrInterrupted = errors.New("interrupted")

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
// stdout free for the sealed secret itself. Cancelling ctx closes the wizard and
// reports ErrInterrupted.
func Run(ctx context.Context, options Options, output io.Writer, input io.Reader) (Result, error) {
	application := newApp(options)

	// Signals are the caller's to handle: Bubble Tea's own handler would turn a
	// SIGTERM into an ordinary quit, which looks exactly like a clean exit.
	program := tea.NewProgram(
		application,
		tea.WithOutput(output),
		tea.WithInput(input),
		tea.WithAltScreen(),
		tea.WithContext(ctx),
		tea.WithoutSignalHandler(),
	)

	finished, err := program.Run()

	// Values are overwritten on the way out; Go cannot promise no copy survives, but
	// nothing is left lying around deliberately.
	final, ok := finished.(*app)
	if ok {
		defer final.state.draft.Entries.Scrub()
	}

	if err != nil {
		if errors.Is(err, tea.ErrInterrupted) || errors.Is(err, context.Canceled) {
			return Result{}, ErrInterrupted
		}
		return Result{}, fmt.Errorf("running the wizard: %w", err)
	}
	if !ok {
		return Result{}, nil
	}

	return Result{
		Sealed:        final.state.sealed,
		PrintToStdout: final.state.printToStdout,
		Outcome:       final.state.outcome,
	}, nil
}
