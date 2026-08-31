package wizard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// valueSource is how the user wants to supply one value.
type valueSource int

const (
	sourceTyped valueSource = iota
	sourceFromFile
	sourceMultiline
)

// entryStep adds one entry, or replaces the value of an existing one.
//
// It asks in two parts: where the value comes from, then the key and the value
// itself. Typed values are masked, and there is deliberately no way to load a
// value through a temporary file, so plaintext never reaches the disk.
type entryStep struct {
	state *state

	// replacing is set when an existing key's value is being replaced.
	replacing secret.Key

	sourceForm *huh.Form
	valueForm  *huh.Form
	source     valueSource

	key      string
	typed    string
	path     string
	failure  string
	finished bool
}

func newEntryStep(state *state, replacing secret.Key) *entryStep {
	return &entryStep{state: state, replacing: replacing, key: replacing.String()}
}

func (s *entryStep) Heading() string {
	if s.replacing != "" {
		return "Replace the value of " + s.replacing.String()
	}
	return "Add an entry"
}

func (s *entryStep) Footer() string {
	switch {
	case s.valueForm == nil:
		return "↑/↓ choose   enter confirm"
	case s.source == sourceMultiline:
		return "enter new line   ctrl+d done"
	default:
		return "enter next field"
	}
}

func (s *entryStep) Init() tea.Cmd {
	if s.sourceForm != nil || s.valueForm != nil {
		return nil
	}

	s.sourceForm = huh.NewForm(huh.NewGroup(
		huh.NewSelect[valueSource]().
			Title("Where does the value come from?").
			Options(
				huh.NewOption("type it in", sourceTyped),
				huh.NewOption("read it from a file", sourceFromFile),
				huh.NewOption("type several lines, for a certificate or JSON", sourceMultiline),
			).
			Value(&s.source),
	)).WithShowHelp(false).WithShowErrors(false)

	return s.sourceForm.Init()
}

func (s *entryStep) Update(message tea.Msg) (step, tea.Cmd) {
	if s.finished {
		return s, nil
	}

	if s.valueForm == nil {
		return s.updateSource(message)
	}

	return s.updateValue(message)
}

func (s *entryStep) updateSource(message tea.Msg) (step, tea.Cmd) {
	model, cmd := s.sourceForm.Update(message)
	if form, ok := model.(*huh.Form); ok {
		s.sourceForm = form
	}
	if s.sourceForm.State == huh.StateCompleted {
		s.buildValueForm()
		return s, s.valueForm.Init()
	}

	return s, cmd
}

func (s *entryStep) updateValue(message tea.Msg) (step, tea.Cmd) {
	model, cmd := s.valueForm.Update(message)
	if form, ok := model.(*huh.Form); ok {
		s.valueForm = form
	}
	if s.valueForm.State != huh.StateCompleted {
		return s, cmd
	}

	if err := s.commit(); err != nil {
		s.failure = err.Error()
		// Let the user correct the answer rather than losing what they typed.
		s.valueForm.State = huh.StateNormal
		return s, nil
	}

	s.finished = true
	return newEntriesStep(s.state), nil
}

// buildValueForm asks for the key, unless replacing a value, and for the value in
// whichever shape was chosen.
func (s *entryStep) buildValueForm() {
	fields := make([]huh.Field, 0, 2)

	if s.replacing == "" {
		fields = append(fields, huh.NewInput().
			Title("Key").
			Placeholder("DB_PASSWORD").
			Value(&s.key).
			Validate(func(value string) error {
				_, err := secret.NewKey(value)
				return err
			}))
	}

	switch s.source {
	case sourceFromFile:
		fields = append(fields, huh.NewInput().
			Title("Path to the file holding the value").
			Placeholder("./ca.crt").
			Value(&s.path).
			Validate(validateReadableFile))

	case sourceMultiline:
		fields = append(fields, huh.NewText().
			Title("Value").
			Description("Paste or type the value, then press ctrl+d.").
			Value(&s.typed))

	default:
		fields = append(fields, huh.NewInput().
			Title("Value").
			EchoMode(huh.EchoModePassword).
			Value(&s.typed))
	}

	s.valueForm = huh.NewForm(huh.NewGroup(fields...)).
		WithShowHelp(false).
		WithShowErrors(true).
		WithKeyMap(s.keyMap())
}

// keyMap makes a multiline value behave the way a text editor does. By default a
// newline submits the field, which would cut a pasted certificate off at its first
// line; here newline inserts a line and ctrl+d finishes.
func (s *entryStep) keyMap() *huh.KeyMap {
	keys := huh.NewDefaultKeyMap()
	if s.source != sourceMultiline {
		return keys
	}

	done := key.NewBinding(key.WithKeys("ctrl+d"), key.WithHelp("ctrl+d", "done"))
	keys.Text.NewLine = key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "new line"))
	keys.Text.Next = done
	keys.Text.Submit = done

	return keys
}

// commit validates the answers and records the entry.
func (s *entryStep) commit() error {
	key := s.replacing
	if key == "" {
		parsed, err := secret.NewKey(strings.TrimSpace(s.key))
		if err != nil {
			return err
		}
		key = parsed
	}

	value, source, err := s.value()
	if err != nil {
		return err
	}

	s.state.draft.Entries.Set(secret.Entry{
		Key:    key,
		Value:  value,
		Source: source,
		Path:   s.path,
	})
	s.state.keepKey(key.String())
	s.state.invalidate()

	return nil
}

// value reads the value from wherever it was said to come from.
func (s *entryStep) value() ([]byte, secret.Source, error) {
	if s.source != sourceFromFile {
		source := secret.SourceLiteral
		if s.source == sourceMultiline {
			source = secret.SourceEditor
		}
		return []byte(s.typed), source, nil
	}

	// The file is read now rather than at sealing time, so a file that disappears
	// in between cannot fail the seal.
	contents, err := os.ReadFile(expandHome(s.path))
	if err != nil {
		return nil, 0, fmt.Errorf("reading %s: %w", s.path, err)
	}

	return contents, secret.SourceFile, nil
}

func (s *entryStep) View() string {
	form := s.sourceForm
	if s.valueForm != nil {
		form = s.valueForm
	}
	if form == nil {
		return indent(mutedStyle.Render("preparing…"))
	}

	body := form.View()
	if s.failure != "" {
		body += "\n" + indent(failureStyle.Render(markFailed+" "+s.failure))
	}
	if s.valueForm != nil && s.replacing == "" && s.state.draft.Entries.Has(secret.Key(strings.TrimSpace(s.key))) {
		body += "\n" + indent(warningStyle.Render(
			markWarning+" "+s.key+" already exists and its value will be replaced"))
	}

	return body
}

// validateReadableFile checks the file before the form moves on, so a typo is
// caught while it is still easy to fix.
func validateReadableFile(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("a path is required")
	}

	info, err := os.Stat(expandHome(value))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no such file: %s", value)
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", value)
	}

	return nil
}

// expandHome resolves a leading ~ so typed paths behave like shell paths.
func expandHome(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}

	return filepath.Join(home, strings.TrimPrefix(path, "~"))
}
