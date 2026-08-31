package seal

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// ErrNotASealedSecret reports a file that is not a sealed secret manifest.
var ErrNotASealedSecret = errors.New("not a SealedSecret manifest")

// ErrWouldEmpty reports that a merge would leave the sealed secret with no keys.
var ErrWouldEmpty = errors.New("this would remove every key")

// Existing is what a sealed secret file already holds.
//
// The values are not part of it: sealed values cannot be read back without the
// controller's private key, so a key can only be replaced, never inspected.
type Existing struct {
	Path      string
	Name      string
	Namespace string
	Scope     ssv1alpha1.SealingScope
	Type      corev1.SecretType
	// Keys are the keys currently sealed, sorted.
	Keys []string

	sealed *ssv1alpha1.SealedSecret
	raw    []byte
}

// Raw is the file's contents as they were read, which tells the caller which
// shape to write back in.
func (e Existing) Raw() []byte { return e.raw }

// ReadExisting reads what a sealed secret file already holds.
func ReadExisting(path string) (Existing, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return Existing{}, fmt.Errorf("reading %s: %w", path, err)
	}

	sealed := &ssv1alpha1.SealedSecret{}
	if err := yaml.Unmarshal(contents, sealed); err != nil {
		return Existing{}, fmt.Errorf("reading %s: %w: %w", path, ErrNotASealedSecret, err)
	}
	if sealed.Kind != "SealedSecret" {
		return Existing{}, fmt.Errorf("reading %s: %w: it is %q", path, ErrNotASealedSecret, sealed.Kind)
	}
	if sealed.Name == "" {
		return Existing{}, fmt.Errorf("reading %s: %w: it has no name", path, ErrNotASealedSecret)
	}

	keys := make([]string, 0, len(sealed.Spec.EncryptedData))
	for key := range sealed.Spec.EncryptedData {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return Existing{
		Path:      path,
		Name:      sealed.Name,
		Namespace: sealed.Namespace,
		Scope:     sealed.Scope(),
		Type:      sealed.Spec.Template.Type,
		Keys:      keys,
		sealed:    sealed,
		raw:       contents,
	}, nil
}

// Has reports whether a key is already sealed in the file.
func (e Existing) Has(key string) bool {
	for _, existing := range e.Keys {
		if existing == key {
			return true
		}
	}
	return false
}

// MergeResult is the new contents of a sealed secret file and what changed.
type MergeResult struct {
	Sealed   []byte
	Added    []string
	Replaced []string
	Removed  []string
}

// Merge produces the new contents of a sealed secret file: the values in built are
// encrypted and merged over what is there, and the named keys are dropped.
//
// The file's own name, namespace and scope are used, because those three decide
// the encryption label and so must match what is already sealed in it.
func (s *Sealer) Merge(
	existing Existing,
	built *corev1.Secret,
	remove []string,
	format Format,
) (MergeResult, error) {
	if s.publicKey == nil {
		return MergeResult{}, errors.New("no certificate loaded to seal with")
	}
	if existing.sealed == nil {
		return MergeResult{}, ErrNotASealedSecret
	}

	merged := existing.sealed.DeepCopy()
	if merged.Spec.EncryptedData == nil {
		merged.Spec.EncryptedData = map[string]string{}
	}

	result := MergeResult{}

	if built != nil && len(built.Data) > 0 {
		incoming, err := s.sealObject(alignedWith(existing, built), existing.Scope)
		if err != nil {
			return MergeResult{}, err
		}

		for _, key := range sortedKeys(incoming.Spec.EncryptedData) {
			if _, found := merged.Spec.EncryptedData[key]; found {
				result.Replaced = append(result.Replaced, key)
			} else {
				result.Added = append(result.Added, key)
			}
			merged.Spec.EncryptedData[key] = incoming.Spec.EncryptedData[key]
		}
	}

	for _, key := range remove {
		if _, found := merged.Spec.EncryptedData[key]; !found {
			continue
		}
		delete(merged.Spec.EncryptedData, key)
		delete(merged.Spec.Template.Data, key)
		result.Removed = append(result.Removed, key)
	}
	sort.Strings(result.Removed)

	if len(merged.Spec.EncryptedData) == 0 {
		return MergeResult{}, ErrWouldEmpty
	}

	rendered, err := encode(merged, format)
	if err != nil {
		return MergeResult{}, err
	}
	result.Sealed = rendered

	return result, nil
}

// alignedWith gives the incoming secret the identity of the file being merged
// into, so the encryption label matches the values already sealed there.
func alignedWith(existing Existing, built *corev1.Secret) *corev1.Secret {
	aligned := built.DeepCopy()
	aligned.Name = existing.Name
	aligned.Namespace = existing.Namespace
	return aligned
}

func sortedKeys(data map[string]string) []string {
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// WriteFile replaces a file's contents in one step, so an interrupted write cannot
// leave a half-written sealed secret behind.
func WriteFile(path string, contents []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", path, err)
	}

	temporary, err := os.CreateTemp(directory, ".sealed-*")
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	defer func() { _ = os.Remove(temporary.Name()) }()

	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := os.Chmod(temporary.Name(), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	if err := os.Rename(temporary.Name(), path); err != nil {
		return fmt.Errorf("replacing %s: %w", path, err)
	}

	return nil
}
