package wizard

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// applyPlan is what applying would do to the cluster, worked out before anything
// is sent so the consequences can be shown first.
type applyPlan struct {
	// supported is false when the cluster has no SealedSecret resource, which means
	// applying cannot work at all.
	supported bool
	// replacing is true when a sealed secret of this name is already there.
	replacing bool
	// added, replaced and removed are the keys this apply would change.
	added    []string
	replaced []string
	removed  []string
	err      error
}

type applyPlannedMsg struct {
	plan applyPlan
}

type appliedMsg struct {
	err error
}

// planApply asks the cluster what is already there and works out the difference.
func planApply(state *state) tea.Cmd {
	applier := state.connection.Applier
	namespace := state.draft.Namespace
	name := state.draft.Name.String()
	wanted := keysOf(state.draft.Entries)

	return func() tea.Msg {
		if applier == nil {
			return applyPlannedMsg{plan: applyPlan{err: errors.New("no cluster to apply to")}}
		}

		supported, err := applier.Supported(context.Background())
		if err != nil {
			return applyPlannedMsg{plan: applyPlan{err: err}}
		}
		if !supported {
			return applyPlannedMsg{plan: applyPlan{}}
		}

		found, existing, err := applier.Existing(context.Background(), namespace, name)
		if err != nil {
			return applyPlannedMsg{plan: applyPlan{supported: true, err: err}}
		}

		plan := difference(existing, wanted)
		plan.supported = true
		plan.replacing = found

		return applyPlannedMsg{plan: plan}
	}
}

// applyNow sends the sealed secret to the cluster.
func applyNow(state *state, force bool) tea.Cmd {
	applier := state.connection.Applier
	sealed := state.sealed

	return func() tea.Msg {
		return appliedMsg{err: applier.Apply(context.Background(), sealed, force)}
	}
}

func keysOf(entries secret.Entries) []string {
	keys := make([]string, 0, entries.Len())
	for _, entry := range entries.All() {
		keys = append(keys, entry.Key.String())
	}
	sort.Strings(keys)
	return keys
}

// difference works out which keys an apply would add, replace and remove.
func difference(existing, wanted []string) applyPlan {
	present := make(map[string]bool, len(existing))
	for _, key := range existing {
		present[key] = true
	}

	keeping := make(map[string]bool, len(wanted))
	plan := applyPlan{}

	for _, key := range wanted {
		keeping[key] = true
		if present[key] {
			plan.replaced = append(plan.replaced, key)
		} else {
			plan.added = append(plan.added, key)
		}
	}

	for _, key := range existing {
		if !keeping[key] {
			plan.removed = append(plan.removed, key)
		}
	}

	return plan
}

// describe says in words what applying would do, so an overwrite is never a
// surprise. Only key names appear; no value is involved.
func (p applyPlan) describe(namespace, name string) string {
	if !p.replacing {
		return fmt.Sprintf("This creates %s in %s with %d %s.",
			name, namespace, len(p.added), pluralise(len(p.added), "key", "keys"))
	}

	lines := []string{fmt.Sprintf("%s %s already exists in %s and will be updated:",
		markWarning, name, namespace)}

	if len(p.added) > 0 {
		lines = append(lines, "  adding    "+strings.Join(p.added, ", "))
	}
	if len(p.replaced) > 0 {
		lines = append(lines, "  replacing "+strings.Join(p.replaced, ", "))
	}
	if len(p.removed) > 0 {
		lines = append(lines, "  removing  "+strings.Join(p.removed, ", "))
	}

	return strings.Join(lines, "\n")
}

// applyFailureHint suggests what to do about a failure to apply.
func applyFailureHint(err error) string {
	switch {
	case errors.Is(err, kube.ErrConflict):
		return "another tool manages this sealed secret; applying again with force takes it over"
	case errors.Is(err, kube.ErrForbidden):
		return "you are not allowed to write sealed secrets in this namespace"
	case errors.Is(err, kube.ErrNotSupported):
		return "the sealed-secrets controller does not appear to be installed here"
	default:
		return ""
	}
}
