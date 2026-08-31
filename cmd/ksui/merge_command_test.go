package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sealedFileFor creates a sealed secret file holding the given literals.
func sealedFileFor(t *testing.T, certificate string, literals ...string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "db-creds-sealed.yaml")
	args := []string{"--cert", certificate, "--namespace", "payments", "--name", "db-creds",
		"--sealed-secret-file", path}
	for _, literal := range literals {
		args = append(args, "--from-literal", literal)
	}

	if got := runCommand(t, nil, args...); got.exitCode != exitOK {
		t.Fatalf("creating the starting file failed: %s", got.stderr)
	}

	return path
}

func contentsOf(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(contents)
}

func TestMergingAddsReplacesAndRemovesKeysInPlace(t *testing.T) {
	certificate := certificateFile(t)
	path := sealedFileFor(t, certificate, "DB_PASSWORD=hunter2", "OLD_TOKEN=stale")

	got := runCommand(t, nil, "merge", path,
		"--cert", certificate,
		"--from-literal", "API_TOKEN=new",
		"--from-literal", "DB_PASSWORD=rotated",
		"--remove", "OLD_TOKEN",
	)

	if got.exitCode != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", got.exitCode, exitOK, got.stderr)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want nothing; the file is updated in place", got.stdout)
	}
	for _, want := range []string{"added API_TOKEN", "replaced DB_PASSWORD", "removed OLD_TOKEN"} {
		if !strings.Contains(got.stderr, want) {
			t.Errorf("the report is missing %q:\n%s", want, got.stderr)
		}
	}

	updated := contentsOf(t, path)
	if !strings.Contains(updated, "API_TOKEN") || strings.Contains(updated, "OLD_TOKEN") {
		t.Errorf("the file does not reflect the changes:\n%s", updated)
	}
	for _, plaintext := range []string{"hunter2", "rotated", "new"} {
		if strings.Contains(updated, plaintext) {
			t.Errorf("the file leaks %q:\n%s", plaintext, updated)
		}
	}
}

func TestMergingKeepsTheFilesNameNamespaceAndScope(t *testing.T) {
	certificate := certificateFile(t)
	path := sealedFileFor(t, certificate, "DB_PASSWORD=hunter2")
	before := contentsOf(t, path)

	got := runCommand(t, nil, "merge", path, "--cert", certificate, "--from-literal", "API_TOKEN=new")

	if got.exitCode != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", got.exitCode, exitOK, got.stderr)
	}
	updated := contentsOf(t, path)
	for _, want := range []string{"name: db-creds", "namespace: payments"} {
		if !strings.Contains(updated, want) {
			t.Errorf("the file lost %q:\n%s", want, updated)
		}
	}
	if !strings.Contains(before, "kind: SealedSecret") || !strings.Contains(updated, "kind: SealedSecret") {
		t.Error("the file stopped being a SealedSecret")
	}
}

func TestMergingRefusalsExitWithTheUsageCode(t *testing.T) {
	certificate := certificateFile(t)
	path := sealedFileFor(t, certificate, "ONLY=value")

	plain := filepath.Join(t.TempDir(), "plain.yaml")
	if err := os.WriteFile(plain, []byte("apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n"), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	cases := map[string][]string{
		"nothing to change":  {"merge", path, "--cert", certificate},
		"removing every key": {"merge", path, "--cert", certificate, "--remove", "ONLY"},
		"not a sealed secret": {"merge", plain, "--cert", certificate,
			"--from-literal", "a=b"},
		"missing file":  {"merge", filepath.Join(t.TempDir(), "absent.yaml"), "--cert", certificate},
		"no file given": {"merge"},
		"two files":     {"merge", path, path},
	}

	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			got := runCommand(t, nil, args...)

			if got.exitCode != exitUsage {
				t.Errorf("exit code = %d, want %d\nstderr: %s", got.exitCode, exitUsage, got.stderr)
			}
		})
	}
}

func TestMergingLeavesTheFileUntouchedWhenItFails(t *testing.T) {
	certificate := certificateFile(t)
	path := sealedFileFor(t, certificate, "ONLY=value")
	before := contentsOf(t, path)

	runCommand(t, nil, "merge", path, "--cert", certificate, "--remove", "ONLY")

	if contentsOf(t, path) != before {
		t.Error("a refused merge changed the file anyway")
	}
}
