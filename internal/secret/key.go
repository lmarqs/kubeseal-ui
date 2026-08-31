// Package secret turns the values collected by the wizard into a Kubernetes
// Secret ready for sealing.
package secret

import (
	"errors"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// Key is a Secret data key that Kubernetes will accept.
type Key string

// NewKey validates a Secret data key.
func NewKey(value string) (Key, error) {
	if value == "" {
		return "", errors.New("key must not be empty")
	}
	if problems := validation.IsConfigMapKey(value); len(problems) > 0 {
		return "", fmt.Errorf("invalid key %q: %s", value, strings.Join(problems, "; "))
	}
	return Key(value), nil
}

// String returns the key as written.
func (k Key) String() string { return string(k) }

// Name is a Secret name that Kubernetes will accept.
type Name string

// NewName validates a Secret name.
func NewName(value string) (Name, error) {
	if value == "" {
		return "", errors.New("name must not be empty")
	}
	if problems := validation.IsDNS1123Subdomain(value); len(problems) > 0 {
		return "", fmt.Errorf("invalid name %q: %s", value, strings.Join(problems, "; "))
	}
	return Name(value), nil
}

// String returns the name as written.
func (n Name) String() string { return string(n) }
