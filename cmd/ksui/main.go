// Command ksui is a friendly terminal wizard for creating Bitnami SealedSecrets.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := newRootCommand().ExecuteContext(ctx)
	if err == nil {
		return exitOK
	}
	if errors.Is(err, context.Canceled) {
		return exitInterrupted
	}

	// Diagnostics go to stderr so stdout carries only sealed-secret data.
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	if hint := hintOf(err); hint != "" {
		fmt.Fprintf(os.Stderr, "hint: %s\n", hint)
	}
	return exitCodeOf(err)
}
