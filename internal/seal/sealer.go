// Package seal encrypts Kubernetes Secrets into SealedSecrets using a
// sealed-secrets controller's public key.
package seal

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"strings"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes/scheme"
)

// Format is the serialization of the sealed output.
type Format string

// Formats a sealed secret can be rendered in, matching kubeseal's --format.
const (
	FormatYAML Format = "yaml"
	FormatJSON Format = "json"
)

// ParseFormat validates an output format name.
func ParseFormat(value string) (Format, error) {
	switch Format(strings.ToLower(value)) {
	case FormatYAML:
		return FormatYAML, nil
	case FormatJSON:
		return FormatJSON, nil
	default:
		return "", fmt.Errorf("unsupported output format %q: want yaml or json", value)
	}
}

// Sealer encrypts secrets with one controller's public key.
type Sealer struct {
	publicKey *rsa.PublicKey
}

// NewSealer returns a Sealer that encrypts with publicKey.
func NewSealer(publicKey *rsa.PublicKey) *Sealer {
	return &Sealer{publicKey: publicKey}
}

// Seal encrypts every value of built and renders the resulting SealedSecret.
//
// The scope is recorded as annotations on the Secret before encrypting, because
// it determines the RSA-OAEP label and therefore what the controller will accept
// when decrypting.
func (s *Sealer) Seal(built *corev1.Secret, scope ssv1alpha1.SealingScope, format Format) ([]byte, error) {
	if s.publicKey == nil {
		return nil, errors.New("no certificate loaded to seal with")
	}
	if built == nil {
		return nil, errors.New("no secret to seal")
	}

	sealed, err := s.sealObject(built, scope)
	if err != nil {
		return nil, err
	}

	return encode(sealed, format)
}

// sealObject encrypts a secret into a SealedSecret, before it is rendered.
func (s *Sealer) sealObject(
	built *corev1.Secret,
	scope ssv1alpha1.SealingScope,
) (*ssv1alpha1.SealedSecret, error) {
	scoped := built.DeepCopy()
	scoped.Annotations = ssv1alpha1.UpdateScopeAnnotations(scoped.Annotations, scope)

	sealed, err := ssv1alpha1.NewSealedSecret(scheme.Codecs, s.publicKey, scoped)
	if err != nil {
		return nil, fmt.Errorf("sealing secret: %w", err)
	}

	return sealed, nil
}

// encode renders a SealedSecret the way kubeseal does, so output is
// interchangeable with it.
func encode(sealed *ssv1alpha1.SealedSecret, format Format) ([]byte, error) {
	options := json.SerializerOptions{Yaml: format == FormatYAML, Pretty: format == FormatJSON}
	serializer := json.NewSerializerWithOptions(json.DefaultMetaFactory, scheme.Scheme, scheme.Scheme, options)
	encoder := scheme.Codecs.EncoderForVersion(serializer, ssv1alpha1.SchemeGroupVersion)

	rendered, err := runtime.Encode(encoder, sealed)
	if err != nil {
		return nil, fmt.Errorf("rendering sealed secret as %s: %w", format, err)
	}

	return rendered, nil
}

// WriteTo renders the sealed secret to out.
func WriteTo(out io.Writer, sealed []byte) error {
	if _, err := out.Write(sealed); err != nil {
		return fmt.Errorf("writing sealed secret: %w", err)
	}
	return nil
}
