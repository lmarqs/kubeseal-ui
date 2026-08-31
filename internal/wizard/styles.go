package wizard

import "github.com/charmbracelet/lipgloss"

// Colours are declared by role rather than by appearance, and as adaptive pairs so
// the wizard reads correctly on light and dark terminals. Values are the basic
// ANSI palette, which every terminal theme defines, so nothing depends on true
// colour being available.
var (
	fgEmphasis = lipgloss.AdaptiveColor{Light: "0", Dark: "15"}
	fgMuted    = lipgloss.AdaptiveColor{Light: "8", Dark: "8"}
	accent     = lipgloss.AdaptiveColor{Light: "4", Dark: "12"}
	warning    = lipgloss.AdaptiveColor{Light: "3", Dark: "11"}
	failure    = lipgloss.AdaptiveColor{Light: "1", Dark: "9"}
	success    = lipgloss.AdaptiveColor{Light: "2", Dark: "10"}
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(fgEmphasis)
	headingStyle  = lipgloss.NewStyle().Bold(true).Foreground(accent)
	mutedStyle    = lipgloss.NewStyle().Foreground(fgMuted)
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(accent)
	warningStyle  = lipgloss.NewStyle().Foreground(warning)
	failureStyle  = lipgloss.NewStyle().Foreground(failure)
	successStyle  = lipgloss.NewStyle().Foreground(success)
	maskStyle     = lipgloss.NewStyle().Foreground(fgMuted)
)

// Status is never conveyed by colour alone; each marker carries a glyph too.
const (
	markOK      = "✓"
	markFailed  = "✗"
	markWarning = "⚠"
	mask        = "••••••••"
)
