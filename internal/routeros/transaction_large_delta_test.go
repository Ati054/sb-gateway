package routeros

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestLargeDeltaUsesGuardedImportsWithoutLargeRESTSources(t *testing.T) {
	fixture := newImportTransactionFixture()
	apply := "# SB-GATEWAY generated minimal delta; complete managed sections\n# SB-GATEWAY delta sections: watchdog\n#" + strings.Repeat("a", 17<<10) + "\n"
	rollback := strings.Replace(apply, "aaaa", "bbbb", 1)
	finalized := false
	options := importTransactionOptions()
	options.Finalize = func(context.Context) error { finalized = true; return nil }
	result, err := fixture.transaction.ApplyDelta(context.Background(), apply, rollback, options)
	if err != nil || fixture.uploads != 2 || fixture.runs != 1 || !finalized || len(fixture.files) != 0 || result.GuardMode != "rollback_scheduler" {
		t.Fatalf("large delta: uploads=%d runs=%d finalized=%t files=%v result=%#v err=%v", fixture.uploads, fixture.runs, finalized, fixture.files, result, err)
	}
	for _, event := range fixture.rest.events {
		if strings.HasPrefix(event, "prepare:") {
			t.Fatal("large source was sent to direct REST preparation")
		}
	}
}

func TestLargeDeltaCannotOverwriteImportsUnderPendingRollback(t *testing.T) {
	fixture := newImportTransactionFixture()
	fixture.rest.pendingGuard = true
	source := "# SB-GATEWAY generated minimal delta; complete managed sections\n#" + strings.Repeat("a", 17<<10)
	_, err := fixture.transaction.ApplyDelta(context.Background(), source, source, importTransactionOptions())
	if err == nil || fixture.uploads != 0 || fixture.runs != 0 {
		t.Fatalf("pending rollback accepted: uploads=%d runs=%d err=%v", fixture.uploads, fixture.runs, err)
	}
}

func TestLargeDeltaRejectsInvalidRollbackBeforeAnyNetworkChange(t *testing.T) {
	good := "# SB-GATEWAY generated minimal delta; complete managed sections\n#" + strings.Repeat("a", 17<<10)
	for _, bad := range []string{"# foreign\n", good + "\n/system/reboot\n", good + "\x00", good + strings.Repeat("b", 2<<20)} {
		fixture := newImportTransactionFixture()
		_, err := fixture.transaction.ApplyDelta(context.Background(), good, bad, importTransactionOptions())
		if err == nil || fixture.uploads != 0 || len(fixture.rest.events) != 0 {
			t.Fatalf("invalid rollback reached network: uploads=%d events=%v err=%v", fixture.uploads, fixture.rest.events, err)
		}
	}
}

func TestDeltaCommandGuardsCoverBothRouterOSSyntaxes(t *testing.T) {
	for _, command := range []string{"/system reboot", "/system/reboot", "/system package update", "/system/package/update", "/system/reset-configuration"} {
		source := "# SB-GATEWAY generated minimal delta; complete managed sections\n" + command + "\n"
		if validateDirectDelta(source) == nil || validateImportedDelta(source) == nil {
			t.Fatalf("prohibited command accepted: %q", command)
		}
	}
}

func TestLargeDeltaUsesExistingRollbackOnFailedHealth(t *testing.T) {
	fixture := newImportTransactionFixture()
	source := "# SB-GATEWAY generated minimal delta; complete managed sections\n#" + strings.Repeat("a", 17<<10)
	options := importTransactionOptions()
	options.HealthCheck = func(context.Context) error { return errors.New("test runtime unavailable") }
	_, err := fixture.transaction.ApplyDelta(context.Background(), source, source, options)
	state, ok := TransactionFailureStateOf(err)
	if !ok || state != TransactionRolledBack || fixture.runs != 2 || len(fixture.files) != 0 {
		t.Fatalf("health failure did not restore imports: state=%s runs=%d files=%v err=%v", state, fixture.runs, fixture.files, err)
	}
}
