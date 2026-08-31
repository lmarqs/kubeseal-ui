package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/bitnami/sealed-secrets/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/yaml"
)

// certificateFile writes a controller-style certificate for the CLI to seal with.
func certificateFile(t *testing.T) string {
	t.Helper()
	path, _ := certificateAndKey(t)
	return path
}

// certificateAndKey writes a certificate and hands back the private key that goes
// with it, so a test can decrypt what the CLI sealed and check the value that
// actually reached the controller.
func certificateAndKey(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, certificate, err := crypto.GeneratePrivateKeyAndCert(2048, time.Hour, "ksui-test")
	if err != nil {
		t.Fatalf("generating certificate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "cert.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}

	return path, key
}

// unsealed decrypts a sealed secret the way the controller would.
func unsealed(t *testing.T, rendered []byte, key *rsa.PrivateKey) *corev1.Secret {
	t.Helper()

	var sealed ssv1alpha1.SealedSecret
	if err := yaml.Unmarshal(rendered, &sealed); err != nil {
		t.Fatalf("parsing the sealed secret: %v\n%s", err, rendered)
	}

	secret, err := sealed.Unseal(scheme.Codecs, map[string]*rsa.PrivateKey{"controller": key})
	if err != nil {
		t.Fatalf("the controller could not decrypt the sealed secret: %v", err)
	}

	return secret
}

// result captures everything a single command run produced.
type result struct {
	stdout   string
	stderr   string
	exitCode int
	hint     string
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

	return result{
		stdout:   stdout.String(),
		stderr:   stderr.String(),
		exitCode: exitCodeOf(err),
		hint:     hintOf(err),
	}
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

func TestSealingEncryptsTheValueThatWasGiven(t *testing.T) {
	certificate, key := certificateAndKey(t)

	got := runCommand(t, nil,
		"--cert", certificate,
		"--namespace", "payments",
		"--name", "db-creds",
		"--from-literal", "DB_PASSWORD=hunter2",
	)

	if got.exitCode != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", got.exitCode, exitOK, got.stderr)
	}
	if value := string(unsealed(t, []byte(got.stdout), key).Data["DB_PASSWORD"]); value != "hunter2" {
		t.Errorf("DB_PASSWORD decrypts to %q, want the value that was given", value)
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
		"no name":                   {"--cert", certificate, "--namespace", "p", "--from-literal", "a=1"},
		"no entries":                {"--cert", certificate, "--namespace", "p", "--name", "x"},
		"unknown format":            {"--cert", certificate, "-n", "p", "--name", "x", "--from-literal", "a=1", "-o", "xml"},
		"invalid key":               {"--cert", certificate, "-n", "p", "--name", "x", "--from-literal", "bad key=1"},
		"invalid name":              {"--cert", certificate, "-n", "p", "--name", "UPPER", "--from-literal", "a=1"},
		"malformed literal":         {"--cert", certificate, "-n", "p", "--name", "x", "--from-literal", "novalue"},
		"missing file":              {"--cert", certificate, "-n", "p", "--name", "x", "--from-file", "a=/nope/missing"},
		"unknown scope":             {"--cert", certificate, "-n", "p", "--name", "x", "--from-literal", "a=1", "--scope", "wat"},
		"unknown flag":              {"--nope"},
		"stray argument":            {"extra"},
		"stray argument to version": {"version", "extra"},
		"unknown flag on version":   {"version", "--nope"},
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
			if got.hint == "" {
				t.Errorf("no hint given; a usage error has to say what to change")
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

// TestOnlyOneValueCanComeFromStdin guards the case a second "-" would otherwise
// seal as an empty value, stdin having already been drained.
func TestOnlyOneValueCanComeFromStdin(t *testing.T) {
	got := runCommand(t, strings.NewReader("piped-secret"),
		"--cert", certificateFile(t),
		"--namespace", "payments",
		"--name", "db-creds",
		"--from-file", "first=-",
		"--from-file", "second=-",
	)

	if got.exitCode != exitUsage {
		t.Errorf("exit code = %d, want %d; the second value would silently be empty",
			got.exitCode, exitUsage)
	}
}
