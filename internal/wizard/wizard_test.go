package wizard

import (
	"context"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/bitnami/sealed-secrets/pkg/crypto"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
	"github.com/lmarqs/kubeseal-ui/internal/seal"
	"github.com/lmarqs/kubeseal-ui/internal/secret"
)

// fakeCluster answers cluster queries from canned data.
type fakeCluster struct {
	namespaces      []string
	namespacesErr   error
	controllers     []seal.Controller
	controllersErr  error
	namespacesCalls int
}

func (f *fakeCluster) Namespaces(context.Context) ([]string, error) {
	f.namespacesCalls++
	return f.namespaces, f.namespacesErr
}

func (f *fakeCluster) DiscoverControllers(context.Context) ([]seal.Controller, error) {
	return f.controllers, f.controllersErr
}

// fakeCertificates serves a certificate generated in the test.
type fakeCertificates struct {
	certificate seal.Certificate
	err         error
}

func (f fakeCertificates) Resolve(context.Context, seal.Controller) (seal.Certificate, error) {
	return f.certificate, f.err
}

// fakeValidator records what it was asked to validate.
type fakeValidator struct {
	err    error
	sealed []byte
}

func (f *fakeValidator) Validate(_ context.Context, _ seal.Controller, sealed []byte) error {
	f.sealed = sealed
	return f.err
}

// fakeWriter records where a sealed secret was written.
type fakeWriter struct {
	path   string
	sealed []byte
	err    error
}

func (f *fakeWriter) Write(path string, sealed []byte) error {
	f.path, f.sealed = path, sealed
	return f.err
}

// fakeClusters stands in for the local kubeconfig.
type fakeClusters struct {
	contexts   []kube.Context
	current    string
	err        error
	connection Connection
	openErr    error
}

func (f fakeClusters) Contexts() ([]kube.Context, string, error) {
	return f.contexts, f.current, f.err
}

func (f fakeClusters) Open(string) (Connection, error) {
	return f.connection, f.openErr
}

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, _, err := crypto.GeneratePrivateKeyAndCert(2048, time.Hour, "wizard-test")
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

// testState builds a wizard already past the questions, ready to seal.
func testState(t *testing.T, key *rsa.PrivateKey) *state {
	t.Helper()

	name, err := secret.NewName("db-creds")
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}

	wizardState := &state{
		options: Options{
			DefaultOutputPath: func(name string) string { return "./" + name + "-sealed.yaml" },
		},
		contextName: "prod",
		connection: Connection{
			Cluster:      &fakeCluster{},
			Certificates: fakeCertificates{certificate: certificateFor(key)},
			Server:       "https://prod.example",
		},
		controller: seal.DefaultController(),
	}
	wizardState.draft.Namespace = "payments"
	wizardState.draft.Name = name
	wizardState.draft.Type = secret.TypeOpaque
	wizardState.draft.Entries.Set(entry(t, "DB_PASSWORD", "hunter2"))

	return wizardState
}

func certificateFor(key *rsa.PrivateKey) seal.Certificate {
	return seal.Certificate{
		PublicKey:   &key.PublicKey,
		Origin:      seal.OriginController,
		Source:      "kube-system/sealed-secrets-controller",
		RetrievedAt: time.Now(),
	}
}

func entry(t *testing.T, key, value string) secret.Entry {
	t.Helper()
	parsed, err := secret.NewKey(key)
	if err != nil {
		t.Fatalf("NewKey(%q): %v", key, err)
	}
	return secret.Entry{Key: parsed, Value: []byte(value), Source: secret.SourceLiteral}
}

func press(key string) tea.KeyMsg {
	if key == "enter" {
		return tea.KeyMsg{Type: tea.KeyEnter}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
}

func TestEntriesScreenListsKeysAndProvenanceButNeverValues(t *testing.T) {
	key := testKey(t)
	wizardState := testState(t, key)
	wizardState.draft.Entries.Set(secret.Entry{
		Key: "ca.crt", Value: []byte("PEM DATA"), Source: secret.SourceFile, Path: "./ca.crt",
	})
	step := newEntriesStep(wizardState)

	view := step.View()

	if !strings.Contains(view, "DB_PASSWORD") || !strings.Contains(view, "ca.crt") {
		t.Errorf("the entry keys are not listed:\n%s", view)
	}
	if !strings.Contains(view, "./ca.crt") {
		t.Errorf("the file a value came from is not shown:\n%s", view)
	}
	if strings.Contains(view, "hunter2") || strings.Contains(view, "PEM DATA") {
		t.Errorf("the screen reveals a secret value:\n%s", view)
	}
	if !strings.Contains(view, mask) {
		t.Errorf("values are not masked:\n%s", view)
	}
}

func TestRemovingAnEntryNeedsASecondKeypress(t *testing.T) {
	wizardState := testState(t, testKey(t))
	step := newEntriesStep(wizardState)

	if _, cmd := step.Update(press("d")); cmd != nil {
		t.Error("the first d should only ask for confirmation")
	}
	if wizardState.draft.Entries.Len() != 1 {
		t.Fatal("the entry was removed without confirmation")
	}

	step.Update(press("d"))

	if wizardState.draft.Entries.Len() != 0 {
		t.Error("the entry was not removed after confirming")
	}
}

func TestPressingAnotherKeyCancelsARemoval(t *testing.T) {
	wizardState := testState(t, testKey(t))
	step := newEntriesStep(wizardState)

	step.Update(press("d"))
	step.Update(press("j"))
	step.Update(press("d"))

	if wizardState.draft.Entries.Len() != 1 {
		t.Error("the entry was removed even though the confirmation was interrupted")
	}
}

func TestEntriesScreenRefusesToContinueWithNothingToSeal(t *testing.T) {
	wizardState := testState(t, testKey(t))
	wizardState.draft.Entries.Remove("DB_PASSWORD")
	step := newEntriesStep(wizardState)

	next, _ := step.Update(press("enter"))

	if next != step {
		t.Error("the wizard moved on with no entries")
	}
	if !strings.Contains(step.View(), "add at least one entry") {
		t.Errorf("no explanation was shown:\n%s", step.View())
	}
}

func TestAddingAnEntryOpensTheEntryScreen(t *testing.T) {
	wizardState := testState(t, testKey(t))
	step := newEntriesStep(wizardState)

	next, _ := step.Update(press("a"))

	if _, ok := next.(*entryStep); !ok {
		t.Errorf("pressing a led to %T, want the entry screen", next)
	}
}

func TestGoingBackKeepsTheEntriesAlreadyCollected(t *testing.T) {
	wizardState := testState(t, testKey(t))
	application := &app{state: wizardState, width: 100, height: 40}
	application.stack = []step{newScopeStep(wizardState), newEntriesStep(wizardState)}

	application.Update(tea.KeyMsg{Type: tea.KeyEsc})

	if _, ok := application.current().(*scopeStep); !ok {
		t.Fatalf("esc led to %T, want the previous screen", application.current())
	}
	if wizardState.draft.Entries.Len() != 1 {
		t.Error("going back discarded the entries")
	}
}

func TestEscapeOnTheFirstScreenDoesNotLeaveTheWizard(t *testing.T) {
	wizardState := testState(t, testKey(t))
	application := &app{state: wizardState, width: 100, height: 40}
	application.stack = []step{newEntriesStep(wizardState)}

	application.Update(tea.KeyMsg{Type: tea.KeyEsc})

	if len(application.stack) != 1 {
		t.Error("esc emptied the screen stack")
	}
}

func TestInterruptingScrubsTheValuesHeldInMemory(t *testing.T) {
	wizardState := testState(t, testKey(t))
	held := wizardState.draft.Entries.All()[0].Value
	application := &app{state: wizardState, width: 100, height: 40}
	application.stack = []step{newEntriesStep(wizardState)}

	application.Update(tea.KeyMsg{Type: tea.KeyCtrlC})

	for _, value := range held {
		if value != 0 {
			t.Fatalf("a plaintext value survived the interrupt: %q", held)
		}
	}
}

func TestTheBreadcrumbShowsWhatHasBeenChosen(t *testing.T) {
	wizardState := testState(t, testKey(t))
	application := &app{state: wizardState, width: 100, height: 40}
	application.stack = []step{newEntriesStep(wizardState)}

	breadcrumb := application.breadcrumb()

	for _, want := range []string{"prod", "payments", "db-creds", "strict", "1 entry"} {
		if !strings.Contains(breadcrumb, want) {
			t.Errorf("the breadcrumb is missing %q:\n%s", want, breadcrumb)
		}
	}
}

func TestATerminalTooSmallAsksToBeResized(t *testing.T) {
	wizardState := testState(t, testKey(t))
	application := &app{state: wizardState, width: 40, height: 10}
	application.stack = []step{newEntriesStep(wizardState)}

	view := application.View()

	if !strings.Contains(view, "Resize") {
		t.Errorf("no resize notice was shown:\n%s", view)
	}
}

func TestNotBeingAllowedToListNamespacesOffersTypingOneInstead(t *testing.T) {
	wizardState := testState(t, testKey(t))
	step := newNamespaceStep(wizardState)

	step.Update(namespacesLoadedMsg{err: kube.ErrForbidden})

	if step.form == nil {
		t.Fatal("no way to enter a namespace was offered")
	}
	if !strings.Contains(step.View(), "not allowed to list namespaces") {
		t.Errorf("the reason was not explained:\n%s", step.View())
	}
}

func TestDiscoveringNoControllerFallsBackToTheStockLocation(t *testing.T) {
	wizardState := testState(t, testKey(t))
	wizardState.controller = seal.Controller{}
	step := newNamespaceStep(wizardState)

	step.Update(controllersDiscoveredMsg{})

	if wizardState.controller != seal.DefaultController() {
		t.Errorf("controller = %v, want the default", wizardState.controller)
	}
}

func TestTheFirstDiscoveredControllerIsUsed(t *testing.T) {
	wizardState := testState(t, testKey(t))
	found := []seal.Controller{{Namespace: "infra", Name: "sealed-secrets"}}
	step := newNamespaceStep(wizardState)

	step.Update(controllersDiscoveredMsg{controllers: found})

	if wizardState.controller != found[0] {
		t.Errorf("controller = %v, want %v", wizardState.controller, found[0])
	}
}

func TestReviewSealsTheDraftWithTheResolvedCertificate(t *testing.T) {
	key := testKey(t)
	wizardState := testState(t, key)
	step := newReviewStep(wizardState)

	message, ok := step.sealNow()().(sealedMsg)
	if !ok {
		t.Fatal("sealing did not report a result")
	}
	if message.err != nil {
		t.Fatalf("sealing failed: %v", message.err)
	}

	if !strings.Contains(string(message.sealed), "kind: SealedSecret") {
		t.Errorf("the result is not a SealedSecret:\n%s", message.sealed)
	}
	if strings.Contains(string(message.sealed), "hunter2") {
		t.Errorf("the sealed secret leaks the plaintext:\n%s", message.sealed)
	}
}

func TestReviewReportsThatNoCertificateCouldBeObtained(t *testing.T) {
	wizardState := testState(t, testKey(t))
	unreachable := errors.New("dial tcp: connection refused")
	wizardState.connection.Certificates = fakeCertificates{err: unreachable}
	step := newReviewStep(wizardState)

	step.Update(step.sealNow()())

	if step.failure == nil {
		t.Fatal("the failure was not reported")
	}
	if !strings.Contains(step.View(), "connection refused") {
		t.Errorf("the reason is not on screen:\n%s", step.View())
	}
}

func TestReviewSaysWhenTheCertificateCameFromTheCacheAfterAFailedFetch(t *testing.T) {
	key := testKey(t)
	wizardState := testState(t, key)
	stale := certificateFor(key)
	stale.Origin = seal.OriginCache
	stale.FetchError = errors.New("dial tcp: connection refused")
	wizardState.certificate = stale
	wizardState.sealed = []byte("kind: SealedSecret\n")
	step := newReviewStep(wizardState)
	step.Init()

	if !strings.Contains(step.certificateLine(), "controller unreachable") {
		t.Errorf("the stale certificate is not flagged:\n%s", step.certificateLine())
	}
}

func TestSealingIsRedoneAfterAnAnswerChanges(t *testing.T) {
	wizardState := testState(t, testKey(t))
	wizardState.sealed = []byte("stale")

	wizardState.invalidate()

	if wizardState.sealed != nil {
		t.Error("the previous sealed secret was kept after a change")
	}
}

func TestValidatingReportsThatTheControllerCanDecryptIt(t *testing.T) {
	wizardState := testState(t, testKey(t))
	validator := &fakeValidator{}
	wizardState.connection.Validator = validator
	wizardState.sealed = []byte("kind: SealedSecret\n")
	step := newActionsStep(wizardState)

	step.Update(step.validateCmd()())

	if string(validator.sealed) != "kind: SealedSecret\n" {
		t.Error("the sealed secret was not the thing validated")
	}
	if !strings.Contains(step.View(), "can decrypt") {
		t.Errorf("success was not reported:\n%s", step.View())
	}
}

func TestValidationFailureIsShownWithoutLeavingTheScreen(t *testing.T) {
	wizardState := testState(t, testKey(t))
	wizardState.connection.Validator = &fakeValidator{err: errors.New("no key could decrypt secret")}
	wizardState.sealed = []byte("kind: SealedSecret\n")
	step := newActionsStep(wizardState)

	next, _ := step.Update(step.validateCmd()())

	if next != step {
		t.Error("a failed validation left the screen")
	}
	if !strings.Contains(step.View(), "no key could decrypt") {
		t.Errorf("the reason was not shown:\n%s", step.View())
	}
}

func TestValidationIsNotOfferedWhenSealingOfflineWithACertificateFile(t *testing.T) {
	key := testKey(t)
	wizardState := testState(t, key)
	offline := certificateFor(key)
	offline.Origin = seal.OriginFile
	wizardState.certificate = offline
	wizardState.connection.Validator = &fakeValidator{}
	step := newActionsStep(wizardState)

	if step.canValidate() {
		t.Error("validation was offered although the controller was never contacted")
	}
}

func TestSavingWritesTheSealedSecretThroughTheWriter(t *testing.T) {
	wizardState := testState(t, testKey(t))
	writer := &fakeWriter{}
	wizardState.options.Writer = writer
	wizardState.sealed = []byte("kind: SealedSecret\n")
	step := newActionsStep(wizardState)
	step.askWhereToSave()

	step.Update(step.saveCmd()())

	if writer.path != "./db-creds-sealed.yaml" {
		t.Errorf("path = %q, want the default derived from the secret name", writer.path)
	}
	if string(writer.sealed) != "kind: SealedSecret\n" {
		t.Error("the sealed secret was not what got written")
	}
}

func TestFinishingReportsWhatWasDone(t *testing.T) {
	wizardState := testState(t, testKey(t))
	application := &app{state: wizardState, width: 100, height: 40}
	application.stack = []step{newActionsStep(wizardState)}

	application.Update(finishedMsg{outcome: "wrote ./db-creds-sealed.yaml"})

	if wizardState.outcome != "wrote ./db-creds-sealed.yaml" {
		t.Errorf("outcome = %q, want what was done", wizardState.outcome)
	}
}

func TestChoosingToPrintHandsTheSecretBackForStdout(t *testing.T) {
	wizardState := testState(t, testKey(t))
	application := &app{state: wizardState, width: 100, height: 40}
	application.stack = []step{newActionsStep(wizardState)}

	application.Update(finishPrinting()())

	if !wizardState.printToStdout {
		t.Error("the caller was not asked to print the sealed secret")
	}
}

func TestScopeChoicesNameTheSecretAndNamespaceTheyAffect(t *testing.T) {
	wizardState := testState(t, testKey(t))
	step := newScopeStep(wizardState)

	choices := step.choices()

	if !strings.Contains(choices[0].Key, "db-creds") || !strings.Contains(choices[0].Key, "payments") {
		t.Errorf("strict scope does not say what it binds to: %q", choices[0].Key)
	}
	if choices[0].Value != ssv1alpha1.StrictScope {
		t.Error("strict is not the first choice")
	}
}

func TestTheContextScreenOffersEveryKubeconfigContext(t *testing.T) {
	wizardState := testState(t, testKey(t))
	wizardState.options.Clusters = fakeClusters{
		contexts: []kube.Context{
			{Name: "prod", Cluster: "prod-cluster", Namespace: "payments"},
			{Name: "staging", Cluster: "staging-cluster"},
		},
		current: "staging",
	}
	step := newContextStep(wizardState)

	step.Update(step.Init()())

	view := step.View()
	for _, want := range []string{"prod", "staging", "(current)"} {
		if !strings.Contains(view, want) {
			t.Errorf("the context list is missing %q:\n%s", want, view)
		}
	}
	if step.chosen != "staging" {
		t.Errorf("preselected %q, want the current context", step.chosen)
	}
}

func TestAnUnreadableKubeconfigIsExplainedRatherThanHidden(t *testing.T) {
	wizardState := testState(t, testKey(t))
	wizardState.options.Clusters = fakeClusters{err: kube.ErrNoContexts}
	step := newContextStep(wizardState)

	step.Update(step.Init()())

	if !strings.Contains(step.View(), "no contexts") {
		t.Errorf("the reason is not on screen:\n%s", step.View())
	}
}

func TestOpeningAContextLeadsToTheNamespaceQuestion(t *testing.T) {
	wizardState := testState(t, testKey(t))
	connection := Connection{Cluster: &fakeCluster{}, Server: "https://prod.example"}
	step := newContextStep(wizardState)
	step.chosen = "prod"

	next, _ := step.Update(clusterOpenedMsg{connection: connection})

	if _, ok := next.(*namespaceStep); !ok {
		t.Fatalf("opening a context led to %T, want the namespace question", next)
	}
	if wizardState.contextName != "prod" || wizardState.connection.Server != "https://prod.example" {
		t.Error("the chosen cluster was not recorded")
	}
}

func TestFailingToReachTheChosenClusterIsReported(t *testing.T) {
	wizardState := testState(t, testKey(t))
	step := newContextStep(wizardState)

	next, _ := step.Update(clusterOpenedMsg{err: errors.New("i/o timeout")})

	if next != step {
		t.Error("the wizard moved on despite failing to connect")
	}
	if !strings.Contains(step.View(), "i/o timeout") {
		t.Errorf("the reason is not on screen:\n%s", step.View())
	}
}

func TestTheNamespaceQuestionAsksTheClusterForItsNamespaces(t *testing.T) {
	cluster := &fakeCluster{namespaces: []string{"default", "payments"}}

	message, ok := listNamespaces(cluster)().(namespacesLoadedMsg)

	if !ok {
		t.Fatal("listing namespaces reported no result")
	}
	if cluster.namespacesCalls != 1 {
		t.Errorf("the cluster was asked %d times, want once", cluster.namespacesCalls)
	}
	if len(message.namespaces) != 2 {
		t.Errorf("namespaces = %v, want both", message.namespaces)
	}
}

func TestNamespacesThatCannotBeListedAreReportedAsSuch(t *testing.T) {
	cluster := &fakeCluster{namespacesErr: kube.ErrForbidden}

	message, ok := listNamespaces(cluster)().(namespacesLoadedMsg)

	if !ok {
		t.Fatal("listing namespaces reported no result")
	}
	if !errors.Is(message.err, kube.ErrForbidden) {
		t.Errorf("err = %v, want ErrForbidden", message.err)
	}
}

func TestDiscoveryFailureLeavesTheDefaultControllerInPlace(t *testing.T) {
	cluster := &fakeCluster{controllersErr: kube.ErrForbidden}
	wizardState := testState(t, testKey(t))
	step := newNamespaceStep(wizardState)

	step.Update(discoverControllers(cluster)())

	if wizardState.controller != seal.DefaultController() {
		t.Errorf("controller = %v, want the default after discovery failed", wizardState.controller)
	}
}
