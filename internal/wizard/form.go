package wizard

import "github.com/charmbracelet/huh"

// spent reports whether a form can still be used.
//
// A huh form is single-use: once it is submitted it ignores every message and
// renders nothing, and that finished state cannot be cleared from outside huh —
// assigning StateNormal back leaves it blank. Screens therefore build a fresh
// form whenever theirs is spent, which is what makes returning to an earlier
// answer, and correcting a rejected one, work at all.
func spent(form *huh.Form) bool {
	return form == nil || form.State != huh.StateNormal
}
