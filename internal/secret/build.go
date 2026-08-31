package secret

import (
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ErrNoEntries reports a draft that would seal an empty Secret.
var ErrNoEntries = errors.New("secret has no entries")

// Type is the Kubernetes Secret type being built.
type Type = corev1.SecretType

// Types the wizard can produce.
const (
	TypeOpaque         = corev1.SecretTypeOpaque
	TypeDockerRegistry = corev1.SecretTypeDockerConfigJson
	TypeTLS            = corev1.SecretTypeTLS
)

// Draft is the secret being assembled by the wizard.
type Draft struct {
	Namespace string
	Name      Name
	Type      Type
	Entries   Entries
}

// Build renders the draft as a Kubernetes Secret. Sealing scope is applied later
// by the sealer, not here.
func Build(draft Draft) (*corev1.Secret, error) {
	if draft.Name == "" {
		return nil, errors.New("secret name is required")
	}
	if _, err := NewName(draft.Name.String()); err != nil {
		return nil, err
	}
	if draft.Namespace == "" {
		return nil, errors.New("namespace is required")
	}
	if draft.Entries.Len() == 0 {
		return nil, ErrNoEntries
	}

	secretType := draft.Type
	if secretType == "" {
		secretType = TypeOpaque
	}

	data := make(map[string][]byte, draft.Entries.Len())
	for _, entry := range draft.Entries.All() {
		if entry.Source == SourceExisting {
			return nil, fmt.Errorf("entry %q has no readable value and cannot be sealed", entry.Key)
		}
		data[entry.Key.String()] = entry.Value
	}

	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      draft.Name.String(),
			Namespace: draft.Namespace,
		},
		Type: secretType,
		Data: data,
	}, nil
}
