package seal

// Defaults matching the kubeseal CLI, so a stock installation needs no flags.
const (
	DefaultControllerName      = "sealed-secrets-controller"
	DefaultControllerNamespace = "kube-system"
)

// Controller identifies the sealed-secrets controller a secret is sealed for.
//
// Which controller is used is a decision about the secret itself, not a detail of
// talking to Kubernetes: each controller holds its own key pair, so a secret
// sealed for one cannot be decrypted by another. A cluster may run several.
type Controller struct {
	Namespace string
	Name      string
}

// String renders the controller as "namespace/name".
func (c Controller) String() string {
	return c.Namespace + "/" + c.Name
}

// DefaultController is the controller kubeseal assumes when none is named.
func DefaultController() Controller {
	return Controller{Namespace: DefaultControllerNamespace, Name: DefaultControllerName}
}
