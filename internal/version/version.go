// Package version exposes the build metadata stamped into the binary at link time.
package version

import "fmt"

// Values replaced via -ldflags -X at release build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Info describes the build currently running.
type Info struct {
	Version string
	Commit  string
	Date    string
}

// Current returns the build metadata of this binary.
func Current() Info {
	return Info{Version: version, Commit: commit, Date: date}
}

// String renders the build metadata as a single human-readable line.
func (i Info) String() string {
	return fmt.Sprintf("ksui %s (commit %s, built %s)", i.Version, i.Commit, i.Date)
}
