package secret_test

import (
	"testing"

	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

func literal(t *testing.T, key, value string) secret.Entry {
	t.Helper()
	parsed, err := secret.NewKey(key)
	if err != nil {
		t.Fatalf("NewKey(%q) returned error: %v", key, err)
	}
	return secret.Entry{Key: parsed, Value: []byte(value), Source: secret.SourceLiteral}
}

func keysOf(entries secret.Entries) []string {
	keys := make([]string, 0, entries.Len())
	for _, entry := range entries.All() {
		keys = append(keys, entry.Key.String())
	}
	return keys
}

func assertKeys(t *testing.T, entries secret.Entries, want ...string) {
	t.Helper()
	got := keysOf(entries)
	if len(got) != len(want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("key %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSetKeepsEntriesInInsertionOrder(t *testing.T) {
	var entries secret.Entries

	entries.Set(literal(t, "b", "1"))
	entries.Set(literal(t, "a", "2"))
	entries.Set(literal(t, "c", "3"))

	assertKeys(t, entries, "b", "a", "c")
}

func TestSetReplacesAnExistingKeyInPlace(t *testing.T) {
	var entries secret.Entries
	entries.Set(literal(t, "a", "old"))
	entries.Set(literal(t, "b", "other"))

	entries.Set(literal(t, "a", "new"))

	assertKeys(t, entries, "a", "b")
	replaced, ok := entries.Get(secret.Key("a"))
	if !ok {
		t.Fatal("Get(a) reported the key as missing")
	}
	if string(replaced.Value) != "new" {
		t.Errorf("value = %q, want %q", replaced.Value, "new")
	}
}

func TestHasDistinguishesPresentFromAbsentKeys(t *testing.T) {
	var entries secret.Entries
	entries.Set(literal(t, "present", "x"))

	if !entries.Has(secret.Key("present")) {
		t.Error("Has(present) = false, want true")
	}
	if entries.Has(secret.Key("absent")) {
		t.Error("Has(absent) = true, want false")
	}
}

func TestRemoveDropsTheKeyAndReportsWhetherItExisted(t *testing.T) {
	var entries secret.Entries
	entries.Set(literal(t, "a", "1"))
	entries.Set(literal(t, "b", "2"))

	if !entries.Remove(secret.Key("a")) {
		t.Error("Remove(a) = false, want true")
	}
	if entries.Remove(secret.Key("a")) {
		t.Error("Remove(a) on a missing key = true, want false")
	}

	assertKeys(t, entries, "b")
}

func TestScrubZeroesValuesSoPlaintextDoesNotLingerInMemory(t *testing.T) {
	var entries secret.Entries
	entry := literal(t, "secret", "hunter2")
	entries.Set(entry)

	entries.Scrub()

	for _, byteValue := range entry.Value {
		if byteValue != 0 {
			t.Fatalf("value still holds plaintext: %q", entry.Value)
		}
	}
	if entries.Len() != 0 {
		t.Errorf("Len() = %d after Scrub(), want 0", entries.Len())
	}
}
