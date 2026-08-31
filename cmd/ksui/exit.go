package main

import (
	"errors"
	"fmt"
)

// Exit codes form part of the documented CLI contract (docs/reference/cli-io-contract.md).
const (
	exitOK               = 0
	exitError            = 1
	exitUsage            = 2
	exitValidationFailed = 3
	exitInterrupted      = 130
)

// codedError carries the exit code and recovery hint for a failure, so the
// top-level handler reports both without having to interpret error text.
type codedError struct {
	code int
	hint string
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

// usageError reports invalid or missing input, which is never worth prompting
// about because the caller has to change the command line either way.
func usageError(err error, hint string) error {
	return &codedError{code: exitUsage, hint: hint, err: err}
}

// usageErrorf is usageError for errors built on the spot.
func usageErrorf(hint, format string, args ...any) error {
	return usageError(fmt.Errorf(format, args...), hint)
}

// validationError reports that the controller could not decrypt the sealed secret.
func validationError(err error, hint string) error {
	return &codedError{code: exitValidationFailed, hint: hint, err: err}
}

// runtimeError attaches a hint to an otherwise ordinary failure.
func runtimeError(err error, hint string) error {
	return &codedError{code: exitError, hint: hint, err: err}
}

// exitCodeOf maps an error to its documented exit code.
func exitCodeOf(err error) int {
	if err == nil {
		return exitOK
	}

	var coded *codedError
	if errors.As(err, &coded) {
		return coded.code
	}

	return exitError
}

// hintOf returns the recovery hint carried by err, if it has one.
func hintOf(err error) string {
	var coded *codedError
	if errors.As(err, &coded) {
		return coded.hint
	}
	return ""
}
