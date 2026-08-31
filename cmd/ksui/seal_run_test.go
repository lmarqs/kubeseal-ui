package main

import (
	"bytes"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bitnami/sealed-secrets/pkg/crypto"
)

// certificateFile writes a controller-style certificate for the CLI to seal with.
func certificateFile(t *testing.T) string {
	t.Helper()
	_, certificate, err := crypto.GeneratePrivateKeyAndCert(2048, time.Hour, "ksui-test")
	if err != nil {
		t.Fatalf("generating certificate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "cert.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}

	return path
}

// result captures everything a single command run produced.
type result struct {
	stdout   string
	stderr   string
	exitCode int
}

// runCommand executes ksui with args, isolated from the real terminal.
func runCommand(t *testing.T, stdin io.Reader, args ...string) result {
	t.Helper()

	var stdout, stderr bytes.Buffer
	command := newRootCommand()
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetIn(stdin)
	command.SetArgs(args)

	err := command.Execute()

	return result{stdout: stdout.String(), stderr: stderr.String(), exitCode: exitCodeOf(err)}
}

func TestSealingWritesTheSealedSecretToStdoutAndNothingElse(t *testing.T) {
	got := runCommand(t, nil,
		"--cert", certificateFile(t),
		"--namespace", "payments",
		"--name", "db-creds",
		"--from-literal", "DB_PASSWORD=hunter2",
	)

	if got.exitCode != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", got.exitCode, exitOK, got.stderr)
	}
	if !strings.Contains(got.stdout, "kind: SealedSecret") {
		t.Errorf("stdout is not a SealedSecret:\n%s", got.stdout)
	}
	if strings.Contains(got.stdout, "hunter2") {
		t.Errorf("stdout leaks the plaintext value:\n%s", got.stdout)
	}
	if got.stderr != "" {
		t.Errorf("stderr = %q, want nothing when the seal succeeds", got.stderr)
	}
}

func TestSealingReadsAValueFromStdin(t *testing.T) {
	got := runCommand(t, strings.NewReader("piped-secret"),
		"--cert", certificateFile(t),
		"--namespace", "payments",
		"--name", "db-creds",
		"--from-file", "password=-",
	)

	if got.exitCode != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", got.exitCode, exitOK, got.stderr)
	}
	if !strings.Contains(got.stdout, "password:") {
		t.Errorf("the piped value did not become an entry:\n%s", got.stdout)
	}
	if strings.Contains(got.stdout, "piped-secret") {
		t.Errorf("stdout leaks the piped value:\n%s", got.stdout)
	}
}

func TestSealingWritesToAFileWhenAsked(t *testing.T) {
	output := filepath.Join(t.TempDir(), "sealed.yaml")

	got := runCommand(t, nil,
		"--cert", certificateFile(t),
		"--namespace", "payments",
		"--name", "db-creds",
		"--from-literal", "a=1",
		"--sealed-secret-file", output,
	)

	if got.exitCode != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", got.exitCode, exitOK, got.stderr)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want nothing when writing to a file", got.stdout)
	}
	written, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("reading %s: %v", output, err)
	}
	if !bytes.Contains(written, []byte("kind: SealedSecret")) {
		t.Errorf("file is not a SealedSecret:\n%s", written)
	}
}

func TestJSONOutputIsRequestedWithFormat(t *testing.T) {
	got := runCommand(t, nil,
		"--cert", certificateFile(t),
		"--namespace", "payments",
		"--name", "db-creds",
		"--from-literal", "a=1",
		"--format", "json",
	)

	if got.exitCode != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", got.exitCode, exitOK, got.stderr)
	}
	if !strings.HasPrefix(strings.TrimSpace(got.stdout), "{") {
		t.Errorf("stdout is not JSON:\n%s", got.stdout)
	}
}

func TestClusterWideScopeIsRecordedAsAnAnnotation(t *testing.T) {
	got := runCommand(t, nil,
		"--cert", certificateFile(t),
		"--namespace", "payments",
		"--name", "db-creds",
		"--from-literal", "a=1",
		"--scope", "cluster-wide",
	)

	if got.exitCode != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", got.exitCode, exitOK, got.stderr)
	}
	if !strings.Contains(got.stdout, "sealedsecrets.bitnami.com/cluster-wide") {
		t.Errorf("the cluster-wide annotation is missing:\n%s", got.stdout)
	}
}

func TestFetchCertPrintsTheCertificate(t *testing.T) {
	got := runCommand(t, nil, "--cert", certificateFile(t), "--fetch-cert")

	if got.exitCode != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", got.exitCode, exitOK, got.stderr)
	}
	if !strings.HasPrefix(got.stdout, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("stdout is not a certificate:\n%s", got.stdout)
	}
}

func TestMissingOrInvalidInputExitsWithTheUsageCode(t *testing.T) {
	certificate := certificateFile(t)

	cases := map[string][]string{
		"no name":           {"--cert", certificate, "--namespace", "p", "--from-literal", "a=1"},
		"no entries":        {"--cert", certificate, "--namespace", "p", "--name", "x"},
		"unknown format":    {"--cert", certificate, "-n", "p", "--name", "x", "--from-literal", "a=1", "-o", "xml"},
		"invalid key":       {"--cert", certificate, "-n", "p", "--name", "x", "--from-literal", "bad key=1"},
		"invalid name":      {"--cert", certificate, "-n", "p", "--name", "UPPER", "--from-literal", "a=1"},
		"malformed literal": {"--cert", certificate, "-n", "p", "--name", "x", "--from-literal", "novalue"},
		"missing file":      {"--cert", certificate, "-n", "p", "--name", "x", "--from-file", "a=/nope/missing"},
		"unknown scope":     {"--cert", certificate, "-n", "p", "--name", "x", "--from-literal", "a=1", "--scope", "wat"},
		"unknown flag":      {"--nope"},
		"stray argument":    {"extra"},
	}

	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			got := runCommand(t, nil, args...)

			if got.exitCode != exitUsage {
				t.Errorf("exit code = %d, want %d\nstderr: %s", got.exitCode, exitUsage, got.stderr)
			}
			if got.stdout != "" {
				t.Errorf("stdout = %q, want nothing on failure", got.stdout)
			}
		})
	}
}

func TestAllowEmptyDataSealsASecretWithNoEntries(t *testing.T) {
	got := runCommand(t, nil,
		"--cert", certificateFile(t),
		"--namespace", "payments",
		"--name", "db-creds",
		"--allow-empty-data",
	)

	if got.exitCode != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", got.exitCode, exitOK, got.stderr)
	}
	if !strings.Contains(got.stdout, "kind: SealedSecret") {
		t.Errorf("stdout is not a SealedSecret:\n%s", got.stdout)
	}
}

func TestVersionIsPrintedToStdout(t *testing.T) {
	got := runCommand(t, nil, "version")

	if got.exitCode != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", got.exitCode, exitOK, got.stderr)
	}
	if !strings.HasPrefix(got.stdout, "ksui ") {
		t.Errorf("stdout = %q, want build information", got.stdout)
	}
}
