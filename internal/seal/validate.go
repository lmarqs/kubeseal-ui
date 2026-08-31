package seal

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/bitnami/sealed-secrets/pkg/kubeseal"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
)

// ErrNotValidated reports that the controller rejected the sealed secret, meaning
// it would not be able to decrypt it once applied.
var ErrNotValidated = errors.New("controller cannot decrypt this sealed secret")

// Validate asks the controller to decrypt the sealed secret without storing it,
// which catches a mismatched certificate or scope before anything is applied.
func Validate(
	ctx context.Context,
	clientConfig kubeseal.ClientConfig,
	controller kube.Controller,
	sealed []byte,
) error {
	if clientConfig == nil {
		return errors.New("validation needs a cluster connection")
	}

	err := kubeseal.ValidateSealedSecret(
		ctx, clientConfig, controller.Namespace, controller.Name, bytes.NewReader(sealed))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotValidated, err)
	}

	return nil
}
