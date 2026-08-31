package secret

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// DockerConfigKey is the only key a docker-registry secret holds.
const DockerConfigKey = ".dockerconfigjson"

// DefaultRegistry is Docker Hub, which is what an unqualified image name means.
const DefaultRegistry = "https://index.docker.io/v1/"

// DockerAuth is the credentials for pulling images from one registry.
type DockerAuth struct {
	Server   string
	Username string
	Password string
	// Email is optional; registries that ignore it are the norm now.
	Email string
}

// registryEntry is one registry's credentials as a kubelet expects to find them.
type registryEntry struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email,omitempty"`
	// Auth repeats the credentials base64-encoded, which is the field older
	// clients read.
	Auth string `json:"auth"`
}

type dockerConfig struct {
	Auths map[string]registryEntry `json:"auths"`
}

// DockerConfigJSON renders registry credentials the way "kubectl create secret
// docker-registry" does, so the result works as an image pull secret.
func DockerConfigJSON(auth DockerAuth) ([]byte, error) {
	if auth.Server == "" {
		return nil, errors.New("registry server is required")
	}
	if auth.Username == "" {
		return nil, errors.New("username is required")
	}
	if auth.Password == "" {
		return nil, errors.New("password is required")
	}

	config := dockerConfig{Auths: map[string]registryEntry{
		auth.Server: {
			Username: auth.Username,
			Password: auth.Password,
			Email:    auth.Email,
			Auth:     base64.StdEncoding.EncodeToString([]byte(auth.Username + ":" + auth.Password)),
		},
	}}

	rendered, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("building the registry credentials: %w", err)
	}

	return rendered, nil
}

// DockerEntry turns registry credentials into the single entry the secret holds.
func DockerEntry(auth DockerAuth) (Entry, error) {
	rendered, err := DockerConfigJSON(auth)
	if err != nil {
		return Entry{}, err
	}

	return Entry{Key: DockerConfigKey, Value: rendered, Source: SourceGenerated}, nil
}
