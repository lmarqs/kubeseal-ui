package main

import (
	"os"

	"github.com/mattn/go-isatty"
)

// interactive reports whether the wizard can be drawn and driven.
//
// stderr is the deciding output stream, because the wizard renders there so that
// stdout can be redirected to a file. stdin has to be a terminal too, since the
// wizard is answered with keystrokes.
func interactive(explicitlyDisabled bool) bool {
	if explicitlyDisabled || os.Getenv("CI") != "" {
		return false
	}
	return isTerminal(os.Stderr) && isTerminal(os.Stdin)
}

func isTerminal(file *os.File) bool {
	descriptor := file.Fd()
	return isatty.IsTerminal(descriptor) || isatty.IsCygwinTerminal(descriptor)
}
