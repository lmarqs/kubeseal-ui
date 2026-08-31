package wizard

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// entriesStep is where the secret's values are collected one at a time, and can be
// listed, replaced and removed before anything is sealed.
//
// Values are never shown. Each row reports only its key, where the value came from
// and how large it is, so a shoulder-surfer and the terminal's scrollback learn
// nothing.
type entriesStep struct {
	state  *state
	cursor int
	// confirmingRemoval is the key awaiting a second keypress before it is dropped.
	confirmingRemoval secret.Key
	notice            string
}

func newEntriesStep(state *state) *entriesStep {
	return &entriesStep{state: state}
}

func (s *entriesStep) Heading() string {
	if s.state.merging() {
		return "What should change in " + s.state.options.Merge.Path + "?"
	}
	return "What goes in the secret?"
}

func (s *entriesStep) Footer() string {
	keys := "a add"
	if s.state.draft.Entries.Len() > 0 {
		keys += "   e replace   d remove   ↑/↓ move"
		keys += "   enter seal"
	}
	return keys
}

func (s *entriesStep) Init() tea.Cmd {
	s.clampCursor()
	return nil
}

func (s *entriesStep) Update(message tea.Msg) (step, tea.Cmd) {
	key, ok := message.(tea.KeyMsg)
	if !ok {
		return s, nil
	}

	pressed := key.String()

	// Any key other than a second "d" cancels a pending removal.
	if s.confirmingRemoval != "" && pressed != "d" {
		s.confirmingRemoval = ""
	}

	switch pressed {
	case "a":
		return newEntryStep(s.state, ""), nil

	case "e":
		if entry, found := s.selected(); found {
			return newEntryStep(s.state, entry.Key), nil
		}

	case "d":
		s.remove()

	case "up", "k":
		s.move(-1)

	case "down", "j":
		s.move(1)

	case "enter":
		if !s.readyToSeal() {
			return s, nil
		}
		return newReviewStep(s.state), nil
	}

	return s, nil
}

// readyToSeal reports whether there is anything worth sealing yet, explaining what
// is missing when there is not.
func (s *entriesStep) readyToSeal() bool {
	if s.state.merging() {
		if len(s.state.removing) == 0 && !s.hasNewValues() {
			s.notice = markWarning + " nothing has changed yet"
			return false
		}
		return true
	}

	if s.state.draft.Entries.Len() == 0 {
		s.notice = markWarning + " add at least one entry first"
		return false
	}

	return true
}

// hasNewValues reports whether any entry carries a value to seal, as opposed to
// standing in for one already sealed in the file.
func (s *entriesStep) hasNewValues() bool {
	for _, entry := range s.state.draft.Entries.All() {
		if entry.Source != secret.SourceExisting {
			return true
		}
	}
	return false
}

// remove drops the selected entry, asking for confirmation first because the value
// cannot be recovered by any means other than typing it again.
func (s *entriesStep) remove() {
	entry, found := s.selected()
	if !found {
		return
	}

	if s.confirmingRemoval != entry.Key {
		s.confirmingRemoval = entry.Key
		s.notice = fmt.Sprintf("%s press d again to remove %s", markWarning, entry.Key)
		return
	}

	if entry.Source == secret.SourceExisting {
		s.state.markForRemoval(entry.Key.String())
	}
	s.state.draft.Entries.Remove(entry.Key)
	s.state.invalidate()
	s.confirmingRemoval = ""
	s.notice = "removed " + entry.Key.String()
	s.clampCursor()
}

func (s *entriesStep) move(by int) {
	s.cursor += by
	s.clampCursor()
}

func (s *entriesStep) clampCursor() {
	count := s.state.draft.Entries.Len()
	if s.cursor >= count {
		s.cursor = count - 1
	}
	if s.cursor < 0 {
		s.cursor = 0
	}
}

func (s *entriesStep) selected() (secret.Entry, bool) {
	entries := s.state.draft.Entries.All()
	if s.cursor < 0 || s.cursor >= len(entries) {
		return secret.Entry{}, false
	}
	return entries[s.cursor], true
}

func (s *entriesStep) View() string {
	entries := s.state.draft.Entries.All()
	if len(entries) == 0 {
		empty := mutedStyle.Render("No entries yet. Press ") +
			selectedStyle.Render("a") + mutedStyle.Render(" to add one.")
		if s.notice != "" {
			empty += "\n\n" + warningStyle.Render(s.notice)
		}
		return indent(empty)
	}

	rows := make([]string, 0, len(entries)+2)
	rows = append(rows, mutedStyle.Render(fmt.Sprintf(
		"%d %s", len(entries), pluralise(len(entries), "entry", "entries"))))
	rows = append(rows, "")

	for index, entry := range entries {
		rows = append(rows, s.row(index, entry))
	}

	rows = append(rows, "")
	rows = append(rows, mutedStyle.Render(s.explanation()))

	if s.notice != "" {
		rows = append(rows, "", warningStyle.Render(s.notice))
	}

	return indent(strings.Join(rows, "\n"))
}

// explanation says what the screen guarantees, which differs when editing a file
// whose values cannot be read back.
func (s *entriesStep) explanation() string {
	if s.state.merging() {
		return "Values already sealed cannot be shown, only replaced or removed."
	}
	return "Values stay masked and are never written to disk unencrypted."
}

// row renders one entry: its key, a mask standing in for the value, and where the
// value came from.
func (s *entriesStep) row(index int, entry secret.Entry) string {
	marker := "  "
	key := entry.Key.String()
	if index == s.cursor {
		marker = selectedStyle.Render("▸ ")
		key = selectedStyle.Render(key)
	}

	return fmt.Sprintf("%s%-24s %s   %s",
		marker, key, maskStyle.Render(mask), mutedStyle.Render(provenance(entry)))
}

// provenance says where a value came from and how big it is, which is enough to
// spot a mistake without revealing anything.
func provenance(entry secret.Entry) string {
	switch entry.Source {
	case secret.SourceFile:
		return fmt.Sprintf("file %s · %s", entry.Path, size(len(entry.Value)))
	case secret.SourceEditor:
		return fmt.Sprintf("typed in the editor · %s", size(len(entry.Value)))
	case secret.SourceExisting:
		return "already sealed · value not viewable"
	default:
		return fmt.Sprintf("typed · %s", size(len(entry.Value)))
	}
}

func size(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	return fmt.Sprintf("%.1f KiB", float64(bytes)/1024)
}
