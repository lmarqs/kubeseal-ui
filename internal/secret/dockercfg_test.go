package secret_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

func dockerAuth() secret.DockerAuth {
	return secret.DockerAuth{
		Server:   secret.DefaultRegistry,
		Username: "robot",
		Password: "s3cret",
		Email:    "robot@example.com",
	}
}

// decodeDockerConfig reads back the rendered credentials for inspection.
func decodeDockerConfig(t *testing.T, rendered []byte) map[string]map[string]map[string]string {
	t.Helper()
	var config map[string]map[string]map[string]string
	if err := json.Unmarshal(rendered, &config); err != nil {
		t.Fatalf("the credentials are not valid JSON: %v\n%s", err, rendered)
	}
	return config
}

func TestDockerConfigJSONMatchesWhatAKubeletExpects(t *testing.T) {
	rendered, err := secret.DockerConfigJSON(dockerAuth())
	if err != nil {
		t.Fatalf("DockerConfigJSON() returned error: %v", err)
	}

	entry := decodeDockerConfig(t, rendered)["auths"][secret.DefaultRegistry]
	if entry["username"] != "robot" || entry["password"] != "s3cret" {
		t.Errorf("credentials = %v, want the given username and password", entry)
	}
	if entry["email"] != "robot@example.com" {
		t.Errorf("email = %q, want the given address", entry["email"])
	}

	decoded, err := base64.StdEncoding.DecodeString(entry["auth"])
	if err != nil {
		t.Fatalf("the auth field is not base64: %v", err)
	}
	if string(decoded) != "robot:s3cret" {
		t.Errorf("auth = %q, want %q", decoded, "robot:s3cret")
	}
}

func TestDockerConfigJSONOmitsAnEmptyEmail(t *testing.T) {
	auth := dockerAuth()
	auth.Email = ""

	rendered, err := secret.DockerConfigJSON(auth)
	if err != nil {
		t.Fatalf("DockerConfigJSON() returned error: %v", err)
	}

	if strings.Contains(string(rendered), "email") {
		t.Errorf("an empty email was included:\n%s", rendered)
	}
}

func TestDockerConfigJSONRequiresTheEssentialFields(t *testing.T) {
	cases := map[string]func(*secret.DockerAuth){
		"no server":   func(a *secret.DockerAuth) { a.Server = "" },
		"no username": func(a *secret.DockerAuth) { a.Username = "" },
		"no password": func(a *secret.DockerAuth) { a.Password = "" },
	}

	for name, remove := range cases {
		t.Run(name, func(t *testing.T) {
			auth := dockerAuth()
			remove(&auth)

			if _, err := secret.DockerConfigJSON(auth); err == nil {
				t.Error("DockerConfigJSON() accepted incomplete credentials")
			}
		})
	}
}

func TestDockerEntryHoldsEverythingUnderTheOneExpectedKey(t *testing.T) {
	entry, err := secret.DockerEntry(dockerAuth())
	if err != nil {
		t.Fatalf("DockerEntry() returned error: %v", err)
	}

	if entry.Key.String() != ".dockerconfigjson" {
		t.Errorf("key = %q, want .dockerconfigjson", entry.Key)
	}
	if entry.Source != secret.SourceGenerated {
		t.Errorf("source = %v, want generated", entry.Source)
	}
}

func TestADockerRegistrySecretCarriesTheRightType(t *testing.T) {
	name, err := secret.NewName("pull-secret")
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}
	entry, err := secret.DockerEntry(dockerAuth())
	if err != nil {
		t.Fatalf("DockerEntry: %v", err)
	}
	draft := secret.Draft{Namespace: "apps", Name: name, Type: secret.TypeDockerRegistry}
	draft.Entries.Set(entry)

	built, err := secret.Build(draft)
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}

	if string(built.Type) != "kubernetes.io/dockerconfigjson" {
		t.Errorf("type = %q, want kubernetes.io/dockerconfigjson", built.Type)
	}
	if len(built.Data[".dockerconfigjson"]) == 0 {
		t.Error("the credentials did not reach the secret")
	}
}
