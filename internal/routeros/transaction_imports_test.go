package routeros

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type importGuardREST struct {
	fakeTransactionREST
	guardError  error
	armError    error
	armHook     func()
	prepareHook func(string) error
}

func (fake *importGuardREST) ensureNoPendingRollbackGuard(ctx context.Context) error {
	if err := fake.fakeTransactionREST.ensureNoPendingRollbackGuard(ctx); err != nil {
		return err
	}
	return fake.guardError
}

func (fake *importGuardREST) PrepareImportScript(ctx context.Context, role, name string) (string, error) {
	prepared, err := fake.fakeTransactionREST.PrepareImportScript(ctx, role, name)
	if err == nil && fake.prepareHook != nil {
		err = fake.prepareHook(role)
	}
	return prepared, err
}

func (fake *importGuardREST) ArmRollback(ctx context.Context, name string, options RollbackOptions) (string, error) {
	if fake.armHook != nil {
		fake.armHook()
	}
	if fake.armError != nil {
		fake.events = append(fake.events, "arm:"+name)
		return "", fake.armError
	}
	return fake.fakeTransactionREST.ArmRollback(ctx, name, options)
}

type importTransactionFixture struct {
	rest                    *importGuardREST
	transaction             *Transaction
	files                   map[string]string
	uploads, cleanups, runs int
	uploadHook              func(string) error
	runError                error
}

func newImportTransactionFixture() *importTransactionFixture {
	fixture := &importTransactionFixture{
		rest:  &importGuardREST{fakeTransactionREST: fakeTransactionREST{trackPendingGuard: true}},
		files: map[string]string{},
	}
	fixture.transaction = &Transaction{
		rest: fixture.rest,
		upload: func(_ context.Context, role, source string) (string, error) {
			fixture.uploads++
			if fixture.uploadHook != nil {
				if err := fixture.uploadHook(role); err != nil {
					return "", err
				}
			}
			name, err := managedImportName(role, source)
			if err != nil {
				return "", err
			}
			fixture.files[name] = source
			return name, nil
		},
		cleanup: func(_ context.Context, names ...string) error {
			fixture.cleanups++
			for _, name := range names {
				delete(fixture.files, name)
			}
			return nil
		},
		run: func(context.Context, string) error {
			fixture.runs++
			return fixture.runError
		},
	}
	return fixture
}

func importTransactionOptions() TransactionOptions {
	return TransactionOptions{
		SchedulerGuardOnly: true,
		HealthCheck:        func(context.Context) error { return nil },
	}
}

func TestFullCandidateRejectsUnconfirmedGuardBeforePreparingImports(t *testing.T) {
	for _, pending := range []bool{true, false} {
		name := "inventory unavailable"
		if pending {
			name = "pending guard"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newImportTransactionFixture()
			fixture.rest.pendingGuard = pending
			if !pending {
				fixture.rest.guardError = errors.New("REST inventory unavailable")
			}
			rollbackName, err := managedImportName("rollback", "rollback")
			if err != nil {
				t.Fatal(err)
			}
			fixture.files[rollbackName] = "rollback"
			_, err = fixture.transaction.ApplyCandidate(context.Background(), "apply", "rollback", importTransactionOptions())
			state, ok := TransactionFailureStateOf(err)
			if !ok || state != TransactionRecoveryPending {
				t.Fatalf("state=%q ok=%t err=%v", state, ok, err)
			}
			if fixture.uploads != 0 || fixture.cleanups != 0 || fixture.runs != 0 || !sameStrings(fixture.rest.events, []string{"guard-check"}) {
				t.Fatalf("guarded files were touched: uploads=%d cleanups=%d runs=%d events=%v", fixture.uploads, fixture.cleanups, fixture.runs, fixture.rest.events)
			}
			if len(fixture.files) != 1 || fixture.files[rollbackName] != "rollback" {
				t.Fatalf("previous rollback import changed: %v", fixture.files)
			}
		})
	}
}

func TestFullCandidateRetryKeepsArmedRollbackImport(t *testing.T) {
	fixture := newImportTransactionFixture()
	fixture.runError = context.DeadlineExceeded
	_, err := fixture.transaction.ApplyCandidate(context.Background(), "apply", "rollback", importTransactionOptions())
	state, ok := TransactionFailureStateOf(err)
	if !ok || state != TransactionRecoveryPending || !fixture.rest.pendingGuard || fixture.runs != 2 {
		t.Fatalf("first attempt state=%q pending=%t runs=%d err=%v", state, fixture.rest.pendingGuard, fixture.runs, err)
	}
	rollbackName, err := managedImportName("rollback", "rollback")
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		_, err := fixture.transaction.ApplyCandidate(context.Background(), "apply", "rollback", importTransactionOptions())
		if !errors.Is(err, ErrRollbackGuardPending) {
			t.Fatalf("retry %d err=%v", attempt, err)
		}
		if fixture.uploads != 2 || fixture.cleanups != 0 || fixture.runs != 2 || fixture.files[rollbackName] != "rollback" {
			t.Fatalf("retry %d destroyed guard payload: uploads=%d cleanups=%d runs=%d files=%v", attempt, fixture.uploads, fixture.cleanups, fixture.runs, fixture.files)
		}
	}
}

func TestFullCandidatePreservesImportsAfterArmFailure(t *testing.T) {
	for _, test := range []struct {
		name    string
		err     error
		pending bool
	}{
		{name: "guard appeared after preflight", err: ErrRollbackGuardPending, pending: true},
		{name: "creation response lost", err: errors.Join(ErrRollbackGuardUnconfirmed, context.DeadlineExceeded), pending: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newImportTransactionFixture()
			fixture.rest.armError = test.err
			_, err := fixture.transaction.ApplyCandidate(context.Background(), "apply", "rollback", importTransactionOptions())
			state, classified := TransactionFailureStateOf(err)
			if !errors.Is(err, test.err) || classified != test.pending || (classified && state != TransactionRecoveryPending) {
				t.Fatalf("state=%q classified=%t err=%v", state, classified, err)
			}
			if fixture.uploads != 2 || fixture.cleanups != 0 || fixture.runs != 0 || len(fixture.files) != 2 {
				t.Fatalf("uncertain arm lost imports: uploads=%d cleanups=%d runs=%d files=%v", fixture.uploads, fixture.cleanups, fixture.runs, fixture.files)
			}
		})
	}
}

func TestFullCandidateDefinitiveArmFailureCleansOnlyWithClearGuard(t *testing.T) {
	for _, guard := range []string{"clear", "pending", "unknown"} {
		t.Run(guard, func(t *testing.T) {
			fixture := newImportTransactionFixture()
			fixture.rest.armError = HTTPError{StatusCode: http.StatusForbidden}
			fixture.rest.armHook = func() {
				fixture.rest.pendingGuard = guard == "pending"
				if guard == "unknown" {
					fixture.rest.guardError = errors.New("guard inventory unavailable")
				}
			}
			_, err := fixture.transaction.ApplyCandidate(context.Background(), "apply", "rollback", importTransactionOptions())
			state, classified := TransactionFailureStateOf(err)
			if !errors.Is(err, fixture.rest.armError) || classified != (guard != "clear") || (classified && state != TransactionRecoveryPending) {
				t.Fatalf("state=%q classified=%t err=%v", state, classified, err)
			}
			if fixture.runs != 0 || fixture.rest.events[len(fixture.rest.events)-1] != "guard-check" {
				t.Fatalf("unsafe arm rejection sequence: runs=%d events=%v", fixture.runs, fixture.rest.events)
			}
			if guard == "clear" {
				if fixture.cleanups != 1 || len(fixture.files) != 0 {
					t.Fatalf("rejected imports retained: cleanups=%d files=%v", fixture.cleanups, fixture.files)
				}
			} else if fixture.cleanups != 0 || len(fixture.files) != 2 {
				t.Fatalf("guarded imports removed: cleanups=%d files=%v", fixture.cleanups, fixture.files)
			}
		})
	}
}

func TestFullCandidateEarlyFailureRechecksGuardBeforeCleanup(t *testing.T) {
	for _, phase := range []string{"apply upload", "rollback preparation", "apply preparation"} {
		for _, guard := range []string{"clear", "pending", "unknown"} {
			t.Run(phase+"/"+guard, func(t *testing.T) {
				fixture := newImportTransactionFixture()
				failure := errors.New("preparation failed")
				fail := func() error {
					fixture.rest.pendingGuard = guard == "pending"
					if guard == "unknown" {
						fixture.rest.guardError = errors.New("guard inventory unavailable")
					}
					return failure
				}
				fixture.uploadHook = func(role string) error {
					if phase == "apply upload" && role == "apply" {
						return fail()
					}
					return nil
				}
				fixture.rest.prepareHook = func(role string) error {
					if phase == role+" preparation" {
						return fail()
					}
					return nil
				}
				_, err := fixture.transaction.ApplyCandidate(context.Background(), "apply", "rollback", importTransactionOptions())
				state, classified := TransactionFailureStateOf(err)
				if !errors.Is(err, failure) || classified != (guard != "clear") || (classified && state != TransactionRecoveryPending) {
					t.Fatalf("state=%q classified=%t err=%v", state, classified, err)
				}
				if fixture.runs != 0 || fixture.rest.events[len(fixture.rest.events)-1] != "guard-check" {
					t.Fatalf("unsafe preparation sequence: runs=%d events=%v", fixture.runs, fixture.rest.events)
				}
				if guard == "clear" {
					if fixture.cleanups != 1 || len(fixture.files) != 0 {
						t.Fatalf("inert imports were not cleaned: cleanups=%d files=%v", fixture.cleanups, fixture.files)
					}
				} else if fixture.cleanups != 0 || len(fixture.files) == 0 {
					t.Fatalf("guarded imports were removed: cleanups=%d files=%v", fixture.cleanups, fixture.files)
				}
			})
		}
	}
}
