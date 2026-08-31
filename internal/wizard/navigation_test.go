package wizard

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/lmarqs/kubeseal-ui/internal/kube"
)

// settle runs the commands a step produced, and the commands those produce, the
// way the program itself would, so a screen is examined in the state a user would
// actually see.
func settle(application *app, cmd tea.Cmd) {
	pending := []tea.Cmd{cmd}

	for round := 0; round < 8 && len(pending) > 0; round++ {
		var next []tea.Cmd

		for _, command := range pending {
			if command == nil {
				continue
			}
			message := command()
			if message == nil {
				continue
			}
			if batch, ok := message.(tea.BatchMsg); ok {
				next = append(next, batch...)
				continue
			}
			if _, ok := message.(spinnerTickMsg); ok {
				continue
			}
			_, produced := application.Update(message)
			next = append(next, produced)
		}

		pending = next
	}
}

// testApp starts a wizard on the cluster question with a cluster that answers.
func testApp(t *testing.T, namespaces []string) *app {
	t.Helper()

	wizardState := &state{options: Options{
		Clusters: fakeClusters{
			contexts:   []kube.Context{{Name: "prod"}, {Name: "staging"}},
			current:    "prod",
			connection: Connection{Cluster: &fakeCluster{namespaces: namespaces}},
		},
	}}

	application := &app{state: wizardState, width: 100, height: 40}
	application.stack = []step{newContextStep(wizardState)}
	settle(application, application.Init())

	return application
}

func send(application *app, message tea.Msg) {
	_, cmd := application.Update(message)
	settle(application, cmd)
}

func confirm(application *app) {
	send(application, tea.KeyMsg{Type: tea.KeyEnter})
}

func goBack(application *app) {
	send(application, tea.KeyMsg{Type: tea.KeyEsc})
}

func TestGoingBackToAnAnsweredScreenShowsItAgain(t *testing.T) {
	application := testApp(t, []string{"default", "payments"})
	confirm(application) // cluster
	confirm(application) // namespace

	if _, ok := application.current().(*typeStep); !ok {
		t.Fatalf("answering both questions led to %T, want the kind of secret", application.current())
	}

	goBack(application)

	current, ok := application.current().(*namespaceStep)
	if !ok {
		t.Fatalf("esc led to %T, want the namespace question", application.current())
	}
	if body := current.View(); !strings.Contains(body, "payments") {
		t.Fatalf("the namespace screen came back empty:\n%q", body)
	}
}

func TestGoingBackLetsTheAnswerBeChanged(t *testing.T) {
	application := testApp(t, []string{"default", "payments"})
	confirm(application) // cluster
	confirm(application) // namespace

	goBack(application)
	send(application, tea.KeyMsg{Type: tea.KeyDown})

	if _, ok := application.current().(*namespaceStep); !ok {
		t.Fatalf("moving the selection left the screen for %T", application.current())
	}

	confirm(application)

	if application.state.draft.Namespace != "payments" {
		t.Errorf("the namespace stayed %q; the new answer was not taken",
			application.state.draft.Namespace)
	}
}

func TestGoingBackToTheClusterScreenShowsTheClustersAgain(t *testing.T) {
	application := testApp(t, []string{"default"})
	confirm(application) // cluster

	goBack(application)

	current, ok := application.current().(*contextStep)
	if !ok {
		t.Fatalf("esc led to %T, want the cluster question", application.current())
	}
	if body := current.View(); !strings.Contains(body, "staging") {
		t.Fatalf("the cluster screen came back empty:\n%q", body)
	}
}

func TestGoingBackDoesNotSkipStraightForwardAgain(t *testing.T) {
	application := testApp(t, []string{"default"})
	confirm(application) // cluster
	confirm(application) // namespace
	confirm(application) // kind of secret

	goBack(application)
	goBack(application)

	if _, ok := application.current().(*namespaceStep); !ok {
		t.Fatalf("two escapes led to %T, want the namespace question", application.current())
	}

	send(application, tea.KeyMsg{Type: tea.KeyDown})

	if _, ok := application.current().(*namespaceStep); !ok {
		t.Fatalf("a keypress jumped forward to %T on its own", application.current())
	}
}

// spentForms are the ones a screen keeps after it has been left, which huh cannot
// draw or drive any more.
func TestNoScreenKeepsASubmittedForm(t *testing.T) {
	application := testApp(t, []string{"default"})
	confirm(application) // cluster
	confirm(application) // namespace
	confirm(application) // kind of secret

	for len(application.stack) > 1 {
		goBack(application)

		current := application.current()
		if form := formOf(current); form != nil && form.State != huh.StateNormal {
			t.Errorf("%T came back with a submitted form", current)
		}
		if body := strings.TrimSpace(current.View()); body == "" {
			t.Errorf("%T came back with nothing on screen", current)
		}
	}
}

func formOf(current step) *huh.Form {
	switch typed := current.(type) {
	case *contextStep:
		return typed.form
	case *namespaceStep:
		return typed.form
	case *typeStep:
		return typed.form
	case *nameStep:
		return typed.form
	case *scopeStep:
		return typed.form
	default:
		return nil
	}
}

// actionsApp puts a sealed secret on the "what now?" screen with a controller
// that answers, so the menu can be used more than once.
func actionsApp(t *testing.T) *app {
	t.Helper()

	wizardState := testState(t, testKey(t))
	wizardState.sealed = []byte("kind: SealedSecret\n")
	wizardState.certificate = certificateFor(testKey(t))
	wizardState.connection.Validator = &fakeValidator{}

	application := &app{state: wizardState, width: 100, height: 40}
	application.stack = []step{newReviewStep(wizardState), newActionsStep(wizardState)}
	settle(application, application.current().Init())

	return application
}

func TestTheMenuStillWorksAfterAnActionThatStaysOnTheScreen(t *testing.T) {
	application := actionsApp(t)

	confirm(application) // check the controller can decrypt it
	settle(application, nil)

	current, ok := application.current().(*actionsStep)
	if !ok {
		t.Fatalf("checking led to %T, want the same screen", application.current())
	}
	if !strings.Contains(current.View(), "print it and quit") {
		t.Fatalf("the menu is gone after checking:\n%q", current.View())
	}
	if current.form.State != huh.StateNormal {
		t.Fatal("the menu kept the submitted form")
	}
}

func TestEscapeLeavesTheTypedNamespaceForTheList(t *testing.T) {
	application := testApp(t, []string{"default", "payments"})
	confirm(application) // cluster

	current, ok := application.current().(*namespaceStep)
	if !ok {
		t.Fatalf("choosing a cluster led to %T, want the namespace question", application.current())
	}

	send(application, tea.KeyMsg{Type: tea.KeyDown})
	send(application, tea.KeyMsg{Type: tea.KeyDown})
	confirm(application) // ✎ type a namespace…

	if !current.typing {
		t.Fatal("choosing to type a namespace did not open the text field")
	}

	goBack(application)

	if application.current() != step(current) {
		t.Fatalf("esc left the screen for %T instead of returning to the list",
			application.current())
	}
	if current.typing {
		t.Fatal("esc did not return to the list of namespaces")
	}
	if body := current.View(); !strings.Contains(body, "payments") {
		t.Fatalf("the list of namespaces did not come back:\n%q", body)
	}
}

func TestEscapeLeavesTheValueForTheQuestionOfWhereItComesFrom(t *testing.T) {
	wizardState := testState(t, testKey(t))
	current := newEntryStep(wizardState, "")
	application := &app{state: wizardState, width: 100, height: 40}
	application.stack = []step{newEntriesStep(wizardState), current}
	settle(application, current.Init())

	confirm(application) // type it in

	if current.valueForm == nil {
		t.Fatal("choosing a source did not ask for the value")
	}

	goBack(application)

	if application.current() != step(current) {
		t.Fatalf("esc left the screen for %T instead of returning to the source",
			application.current())
	}
	if current.valueForm != nil {
		t.Fatal("esc did not return to the question of where the value comes from")
	}
	if body := current.View(); !strings.Contains(body, "read it from a file") {
		t.Fatalf("the source question did not come back:\n%q", body)
	}
}

func TestEscapeAbandonsTheQuestionOfWhereToSave(t *testing.T) {
	application := actionsApp(t)
	current := application.current().(*actionsStep)

	send(application, tea.KeyMsg{Type: tea.KeyDown})
	confirm(application) // save it to a file

	if current.saveForm == nil {
		t.Fatalf("choosing to save did not ask where:\n%q", current.View())
	}

	goBack(application)

	if application.current() != step(current) {
		t.Fatalf("esc left the screen for %T instead of returning to the menu",
			application.current())
	}
	if current.saveForm != nil {
		t.Fatal("esc did not abandon the question of where to save")
	}
	if body := current.View(); !strings.Contains(body, "print it and quit") {
		t.Fatalf("the menu did not come back:\n%q", body)
	}
}

func TestAddingAnEntryLeavesNoDeadScreenBehind(t *testing.T) {
	wizardState := testState(t, testKey(t))
	wizardState.draft.Entries.Scrub()
	entries := newEntriesStep(wizardState)
	scope := newScopeStep(wizardState)
	application := &app{state: wizardState, width: 100, height: 40}
	application.stack = []step{scope, entries}

	for _, key := range []string{"FIRST", "SECOND"} {
		send(application, press("a"))

		adding, ok := application.current().(*entryStep)
		if !ok {
			t.Fatalf("pressing a led to %T, want the entry screen", application.current())
		}
		adding.key = key
		adding.typed = "value"
		confirm(application) // type it in
		confirm(application) // key
		confirm(application) // value
	}

	if wizardState.draft.Entries.Len() != 2 {
		t.Fatalf("entries = %d, want the two that were added", wizardState.draft.Entries.Len())
	}
	if _, ok := application.current().(*entriesStep); !ok {
		t.Fatalf("adding entries left %T on screen, want the list", application.current())
	}
	if len(application.stack) != 2 {
		t.Errorf("the screen stack grew to %d; every entry left a screen behind",
			len(application.stack))
	}

	goBack(application)

	if _, ok := application.current().(*scopeStep); !ok {
		t.Fatalf("esc led to %T, want the question before the list", application.current())
	}
}
