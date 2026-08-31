package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/lmarqs/kubeseal-ui/internal/wizard"
)

// TestExitCodesFollowTheDocumentedContract pins the mapping scripts branch on
// (docs/reference/cli-io-contract.md).
func TestExitCodesFollowTheDocumentedContract(t *testing.T) {
	cases := map[string]struct {
		err  error
		want int
	}{
		"nothing went wrong": {nil, exitOK},
		"runtime failure":    {errors.New("the controller is unreachable"), exitError},
		"wrapped failure":    {fmt.Errorf("sealing: %w", errors.New("no route")), exitError},
		"usage":              {usageErrorf("pass --name", "no name given"), exitUsage},
		"validation":         {validationError(errors.New("cannot decrypt"), "check the scope"), exitValidationFailed},
		"signal":             {fmt.Errorf("fetching: %w", context.Canceled), exitInterrupted},
		"wizard interrupted": {fmt.Errorf("running the wizard: %w", wizard.ErrInterrupted), exitInterrupted},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			if got := exitCodeOf(want.err); got != want.want {
				t.Errorf("exitCodeOf(%v) = %d, want %d", want.err, got, want.want)
			}
		})
	}
}
