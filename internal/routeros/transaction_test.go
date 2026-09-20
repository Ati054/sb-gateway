package routeros

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

type fakeTransactionREST struct {
	events      []string
	settleError error
	runError    error
	disarmError error
}

func (fake *fakeTransactionREST) PrepareDirectDelta(_ context.Context, role, _ string) (string, error) {
	name := "SB-GATEWAY-" + role + "-0123456789ab"
	fake.events = append(fake.events, "prepare:"+role)
	return name, nil
}

func (fake *fakeTransactionREST) PrepareImportScript(_ context.Context, role, name string) (string, error) {
	fake.events = append(fake.events, "prepare-import:"+role+":"+name)
	return "SB-GATEWAY-" + role + "-0123456789ab", nil
}

func (fake *fakeTransactionREST) ArmRollback(_ context.Context, name string, _ RollbackOptions) (string, error) {
	fake.events = append(fake.events, "arm:"+name)
	return "SB-GATEWAY-safe-rollback-1234abcd", nil
}

func (fake *fakeTransactionREST) DisarmRollback(_ context.Context, name string) error {
	fake.events = append(fake.events, "disarm:"+name)
	return fake.disarmError
}

func (fake *fakeTransactionREST) runSSHScript(_ context.Context, name string) error {
	fake.events = append(fake.events, "run:"+name)
	return fake.runError
}

func (fake *fakeTransactionREST) WaitSafeModeSettled(_ context.Context, _ time.Duration) error {
	fake.events = append(fake.events, "settled")
	return fake.settleError
}

func TestTransactionDisarmsRollbackBeforeFinalize(t *testing.T) {
	rest := &fakeTransactionREST{}
	channel := &fakeSafeModeChannel{input: bytes.NewReader([]byte("Safe Mode released"))}
	transaction := &Transaction{
		rest: rest, run: rest.runSSHScript,
		begin: func(_ context.Context, name string) (*SafeModeSession, error) {
			rest.events = append(rest.events, "begin:"+name)
			return &SafeModeSession{channel: channel, active: true}, nil
		},
	}
	result, err := transaction.ApplyDelta(context.Background(), "apply", "rollback", TransactionOptions{
		HealthCheck: func(context.Context) error {
			rest.events = append(rest.events, "health")
			return nil
		},
		Finalize: func(context.Context) error {
			rest.events = append(rest.events, "finalize")
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"prepare:rollback", "prepare:apply", "arm:SB-GATEWAY-rollback-0123456789ab",
		"begin:SB-GATEWAY-apply-0123456789ab", "health", "settled",
		"disarm:SB-GATEWAY-safe-rollback-1234abcd",
		"finalize",
	}
	if !sameStrings(rest.events, want) {
		t.Fatalf("events = %#v, want %#v", rest.events, want)
	}
	if result.HistoryCapReached || !channel.closed {
		t.Fatalf("result=%#v closed=%t", result, channel.closed)
	}
}

func TestTransactionUsesRouterLocalSchedulerGuardWhenRequested(t *testing.T) {
	rest := &fakeTransactionREST{}
	transaction := &Transaction{
		rest: rest, run: rest.runSSHScript,
		begin: func(context.Context, string) (*SafeModeSession, error) {
			t.Fatal("interactive Safe Mode must not be opened")
			return nil, nil
		},
	}
	result, err := transaction.ApplyDelta(context.Background(), "apply", "rollback", TransactionOptions{
		SchedulerGuardOnly: true,
		HealthCheck: func(context.Context) error {
			rest.events = append(rest.events, "health")
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"prepare:rollback", "prepare:apply", "arm:SB-GATEWAY-rollback-0123456789ab",
		"run:SB-GATEWAY-apply-0123456789ab", "health",
		"disarm:SB-GATEWAY-safe-rollback-1234abcd",
	}
	if !sameStrings(rest.events, want) || result.GuardMode != "rollback_scheduler" {
		t.Fatalf("events=%#v result=%#v", rest.events, result)
	}
}

func TestTransactionFallsBackAfterSafeModeConsoleDisconnect(t *testing.T) {
	rest := &fakeTransactionREST{}
	transaction := &Transaction{
		rest: rest, run: rest.runSSHScript,
		begin: func(context.Context, string) (*SafeModeSession, error) {
			return nil, errors.New("console disconnected")
		},
	}
	result, err := transaction.ApplyDelta(context.Background(), "apply", "rollback", TransactionOptions{
		HealthCheck: func(context.Context) error {
			rest.events = append(rest.events, "health")
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantTail := []string{
		"settled", "run:SB-GATEWAY-apply-0123456789ab", "health",
		"disarm:SB-GATEWAY-safe-rollback-1234abcd",
	}
	if len(rest.events) < len(wantTail) || !sameStrings(rest.events[len(rest.events)-len(wantTail):], wantTail) || result.GuardMode != "rollback_scheduler_fallback" {
		t.Fatalf("events=%#v result=%#v", rest.events, result)
	}
}

func TestSchedulerGuardHealthFailureRunsRollbackBeforeDisarm(t *testing.T) {
	rest := &fakeTransactionREST{}
	transaction := &Transaction{rest: rest, run: rest.runSSHScript}
	_, err := transaction.ApplyDelta(context.Background(), "apply", "rollback", TransactionOptions{
		SchedulerGuardOnly: true,
		HealthCheck:        func(context.Context) error { return errors.New("probe failed") },
	})
	if err == nil {
		t.Fatal("failed health check was accepted")
	}
	wantTail := []string{
		"run:SB-GATEWAY-apply-0123456789ab", "run:SB-GATEWAY-rollback-0123456789ab",
		"settled", "disarm:SB-GATEWAY-safe-rollback-1234abcd",
	}
	if len(rest.events) < len(wantTail) || !sameStrings(rest.events[len(rest.events)-len(wantTail):], wantTail) {
		t.Fatalf("events = %#v", rest.events)
	}
}

func TestTransactionHealthFailureAbortsBeforeDisarm(t *testing.T) {
	rest := &fakeTransactionREST{}
	channel := &fakeSafeModeChannel{}
	transaction := &Transaction{
		rest: rest, run: rest.runSSHScript,
		begin: func(context.Context, string) (*SafeModeSession, error) {
			return &SafeModeSession{channel: channel, active: true}, nil
		},
	}
	_, err := transaction.ApplyDelta(context.Background(), "apply", "rollback", TransactionOptions{
		HealthCheck: func(context.Context) error { return errors.New("probe failed") },
	})
	if err == nil {
		t.Fatal("failed health check was accepted")
	}
	if !channel.closed || len(channel.output.Bytes()) != 1 || channel.output.Bytes()[0] != 0x04 {
		t.Fatalf("Safe Mode was not aborted: %q", channel.output.Bytes())
	}
	wantTail := []string{"settled", "disarm:SB-GATEWAY-safe-rollback-1234abcd"}
	if len(rest.events) < 2 || !sameStrings(rest.events[len(rest.events)-2:], wantTail) {
		t.Fatalf("events = %#v", rest.events)
	}
}

func TestTransactionAutoReleaseFailureRunsLKGBeforeDisarm(t *testing.T) {
	rest := &fakeTransactionREST{}
	channel := &fakeSafeModeChannel{}
	transaction := &Transaction{
		rest: rest, run: rest.runSSHScript,
		begin: func(context.Context, string) (*SafeModeSession, error) {
			return &SafeModeSession{channel: channel, autoReleased: true}, nil
		},
	}
	result, err := transaction.ApplyDelta(context.Background(), "apply", "rollback", TransactionOptions{
		HealthCheck: func(context.Context) error { return errors.New("probe failed") },
	})
	if err == nil || !result.HistoryCapReached {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	wantTail := []string{
		"run:SB-GATEWAY-rollback-0123456789ab", "settled",
		"disarm:SB-GATEWAY-safe-rollback-1234abcd",
	}
	if len(rest.events) < 3 || !sameStrings(rest.events[len(rest.events)-3:], wantTail) {
		t.Fatalf("events = %#v", rest.events)
	}
}

func TestTransactionLeavesSchedulerArmedWhenSettlementIsUncertain(t *testing.T) {
	rest := &fakeTransactionREST{settleError: errors.New("REST unavailable")}
	channel := &fakeSafeModeChannel{}
	transaction := &Transaction{
		rest: rest, run: rest.runSSHScript,
		begin: func(context.Context, string) (*SafeModeSession, error) {
			return &SafeModeSession{channel: channel, active: true}, nil
		},
	}
	_, err := transaction.ApplyDelta(context.Background(), "apply", "rollback", TransactionOptions{
		HealthCheck: func(context.Context) error { return errors.New("probe failed") },
	})
	if err == nil {
		t.Fatal("uncertain rollback was accepted")
	}
	for _, event := range rest.events {
		if len(event) >= 7 && event[:7] == "disarm:" {
			t.Fatalf("scheduler was disarmed during uncertainty: %#v", rest.events)
		}
	}
}

func TestFullCandidateStreamsBeforeArmingAndCleansImportsAfterCommit(t *testing.T) {
	rest := &fakeTransactionREST{}
	channel := &fakeSafeModeChannel{input: bytes.NewReader([]byte("Safe Mode released"))}
	transaction := &Transaction{
		rest: rest, run: rest.runSSHScript,
		begin: func(_ context.Context, name string) (*SafeModeSession, error) {
			rest.events = append(rest.events, "begin:"+name)
			return &SafeModeSession{channel: channel, active: true}, nil
		},
		upload: func(_ context.Context, role, _ string) (string, error) {
			name := "SB-GATEWAY-" + role + "-aaaaaaaaaaaa.rsc"
			rest.events = append(rest.events, "upload:"+role)
			return name, nil
		},
		cleanup: func(_ context.Context, names ...string) error {
			rest.events = append(rest.events, "cleanup:"+names[0]+","+names[1])
			return nil
		},
	}
	_, err := transaction.ApplyCandidate(context.Background(), "apply", "rollback", TransactionOptions{
		HealthCheck: func(context.Context) error {
			rest.events = append(rest.events, "health")
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"upload:rollback", "upload:apply",
		"prepare-import:rollback:SB-GATEWAY-rollback-aaaaaaaaaaaa.rsc",
		"prepare-import:apply:SB-GATEWAY-apply-aaaaaaaaaaaa.rsc",
		"arm:SB-GATEWAY-rollback-0123456789ab",
		"begin:SB-GATEWAY-apply-0123456789ab", "health", "settled",
		"disarm:SB-GATEWAY-safe-rollback-1234abcd",
		"cleanup:SB-GATEWAY-apply-aaaaaaaaaaaa.rsc,SB-GATEWAY-rollback-aaaaaaaaaaaa.rsc",
	}
	if !sameStrings(rest.events, want) {
		t.Fatalf("events = %#v, want %#v", rest.events, want)
	}
}

func TestTransactionRollsBackCommittedRouterOSWhenFinalizeFails(t *testing.T) {
	rest := &fakeTransactionREST{}
	channel := &fakeSafeModeChannel{input: bytes.NewReader([]byte("Safe Mode released"))}
	transaction := &Transaction{
		rest: rest, run: rest.runSSHScript,
		begin: func(context.Context, string) (*SafeModeSession, error) {
			return &SafeModeSession{channel: channel, active: true}, nil
		},
	}
	wantFailure := errors.New("state commit failed")
	_, err := transaction.ApplyDelta(context.Background(), "apply", "rollback", TransactionOptions{
		HealthCheck: func(context.Context) error { return nil },
		Finalize:    func(context.Context) error { return wantFailure },
	})
	if !errors.Is(err, wantFailure) {
		t.Fatalf("finalize error = %v", err)
	}
	wantTail := []string{
		"settled", "disarm:SB-GATEWAY-safe-rollback-1234abcd",
		"run:SB-GATEWAY-rollback-0123456789ab", "settled",
	}
	if len(rest.events) < len(wantTail) || !sameStrings(rest.events[len(rest.events)-len(wantTail):], wantTail) {
		t.Fatalf("transaction tail = %#v", rest.events)
	}
}

func TestTransactionReportsUnconfirmedStateWhenFinalizeRollbackFails(t *testing.T) {
	rest := &fakeTransactionREST{runError: errors.New("connection lost")}
	channel := &fakeSafeModeChannel{input: bytes.NewReader([]byte("Safe Mode released"))}
	transaction := &Transaction{
		rest: rest, run: rest.runSSHScript,
		begin: func(context.Context, string) (*SafeModeSession, error) {
			return &SafeModeSession{channel: channel, active: true}, nil
		},
	}
	_, err := transaction.ApplyDelta(context.Background(), "apply", "rollback", TransactionOptions{
		HealthCheck: func(context.Context) error { return nil },
		Finalize:    func(context.Context) error { return errors.New("state commit failed") },
	})
	if err == nil {
		t.Fatal("uncertain finalize rollback was accepted")
	}
	state, ok := TransactionFailureStateOf(err)
	if !ok || state != TransactionStateUnconfirmed {
		t.Fatalf("failure state = %q, %t; err=%v", state, ok, err)
	}
	wantTail := []string{
		"settled", "disarm:SB-GATEWAY-safe-rollback-1234abcd",
		"run:SB-GATEWAY-rollback-0123456789ab",
	}
	if len(rest.events) < len(wantTail) || !sameStrings(rest.events[len(rest.events)-len(wantTail):], wantTail) {
		t.Fatalf("transaction tail = %#v", rest.events)
	}
}

func TestTransactionDoesNotFinalizeWhenRollbackGuardCannotBeDisarmed(t *testing.T) {
	for _, schedulerOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "safe_mode", true: "scheduler_guard"}[schedulerOnly], func(t *testing.T) {
			rest := &fakeTransactionREST{disarmError: errors.New("REST delete failed")}
			channel := &fakeSafeModeChannel{input: bytes.NewReader([]byte("Safe Mode released"))}
			transaction := &Transaction{
				rest: rest, run: rest.runSSHScript,
				begin: func(context.Context, string) (*SafeModeSession, error) {
					return &SafeModeSession{channel: channel, active: true}, nil
				},
			}
			finalized := false
			_, err := transaction.ApplyDelta(context.Background(), "apply", "rollback", TransactionOptions{
				SchedulerGuardOnly: schedulerOnly,
				HealthCheck:        func(context.Context) error { return nil },
				Finalize: func(context.Context) error {
					finalized = true
					return nil
				},
			})
			if err == nil || finalized {
				t.Fatalf("err=%v finalized=%t", err, finalized)
			}
			state, ok := TransactionFailureStateOf(err)
			if !ok || state != TransactionRolledBack {
				t.Fatalf("failure state = %q, %t; err=%v", state, ok, err)
			}
			wantTail := []string{
				"disarm:SB-GATEWAY-safe-rollback-1234abcd",
				"run:SB-GATEWAY-rollback-0123456789ab", "settled",
			}
			if len(rest.events) < len(wantTail) || !sameStrings(rest.events[len(rest.events)-len(wantTail):], wantTail) {
				t.Fatalf("transaction tail = %#v", rest.events)
			}
		})
	}
}

func TestTransactionReportsPendingRecoveryWhenGuardAndImmediateRollbackFail(t *testing.T) {
	rest := &fakeTransactionREST{
		disarmError: errors.New("REST delete failed"),
	}
	transaction := &Transaction{rest: rest, run: func(ctx context.Context, name string) error {
		if err := rest.runSSHScript(ctx, name); err != nil {
			return err
		}
		if name == "SB-GATEWAY-rollback-0123456789ab" {
			return errors.New("SSH rollback failed")
		}
		return nil
	}}
	_, err := transaction.ApplyDelta(context.Background(), "apply", "rollback", TransactionOptions{
		SchedulerGuardOnly: true,
		HealthCheck:        func(context.Context) error { return nil },
	})
	state, ok := TransactionFailureStateOf(err)
	if !ok || state != TransactionRecoveryPending {
		t.Fatalf("failure state = %q, %t; err=%v", state, ok, err)
	}
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
