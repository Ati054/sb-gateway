package routeros

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type TransactionFailureState string

const (
	TransactionRolledBack       TransactionFailureState = "rolled_back"
	TransactionRecoveryPending  TransactionFailureState = "recovery_pending"
	TransactionStateUnconfirmed TransactionFailureState = "state_unconfirmed"
)

type TransactionFailure struct {
	State TransactionFailureState
	Err   error
}

func (failure *TransactionFailure) Error() string {
	return fmt.Sprintf("RouterOS transaction %s: %v", failure.State, failure.Err)
}

func (failure *TransactionFailure) Unwrap() error { return failure.Err }

func TransactionFailureStateOf(err error) (TransactionFailureState, bool) {
	var failure *TransactionFailure
	if !errors.As(err, &failure) {
		return "", false
	}
	return failure.State, true
}

func transactionFailure(state TransactionFailureState, values ...error) error {
	return &TransactionFailure{State: state, Err: errors.Join(values...)}
}

type transactionREST interface {
	PrepareDirectDelta(context.Context, string, string) (string, error)
	PrepareImportScript(context.Context, string, string) (string, error)
	ArmRollback(context.Context, string, RollbackOptions) (string, error)
	DisarmRollback(context.Context, string) error
	WaitSafeModeSettled(context.Context, time.Duration) error
}

type TransactionOptions struct {
	RollbackDelay time.Duration
	SettleTimeout time.Duration
	HealthCheck   func(context.Context) error
	// Runs after rollback is armed, before any candidate RouterOS rule executes.
	BeforeApply func(context.Context) error
	Finalize    func(context.Context) error
	// SchedulerGuardOnly avoids the interactive SSH Safe Mode owner on
	// RouterOS releases where that console path is unstable. The independently
	// armed, RouterOS-local rollback scheduler remains the transaction owner.
	SchedulerGuardOnly bool
}

type TransactionResult struct {
	ApplyScript       string
	RollbackScript    string
	HistoryCapReached bool
	CleanupPending    bool
	GuardMode         string
}

// Transaction coordinates a RouterOS delta or full candidate under two
// independent rollback mechanisms. It contains no background goroutine and
// retains no candidate cache after Apply returns.
type Transaction struct {
	rest    transactionREST
	run     func(context.Context, string) error
	begin   func(context.Context, string) (*SafeModeSession, error)
	upload  func(context.Context, string, string) (string, error)
	cleanup func(context.Context, ...string) error
}

func NewTransaction(rest *Client, sshTransport *SSHTransport) (*Transaction, error) {
	if rest == nil || sshTransport == nil {
		return nil, errors.New("RouterOS REST and SSH transports are required")
	}
	return &Transaction{
		rest: rest, begin: sshTransport.BeginSafeMode, run: sshTransport.RunManagedScript,
		upload: sshTransport.uploadCandidate, cleanup: sshTransport.RemoveManagedImports,
	}, nil
}

func (transaction *Transaction) ApplyDelta(ctx context.Context, applySource, rollbackSource string, options TransactionOptions) (TransactionResult, error) {
	var result TransactionResult
	if options.HealthCheck == nil {
		return result, errors.New("RouterOS post-apply health check is required")
	}
	if options.SettleTimeout <= 0 {
		options.SettleTimeout = 30 * time.Second
	}

	rollbackName, err := transaction.rest.PrepareDirectDelta(ctx, "rollback", rollbackSource)
	if err != nil {
		return result, err
	}
	result.RollbackScript = rollbackName
	applyName, err := transaction.rest.PrepareDirectDelta(ctx, "apply", applySource)
	if err != nil {
		return result, err
	}
	result.ApplyScript = applyName
	scheduler, err := transaction.rest.ArmRollback(ctx, rollbackName, RollbackOptions{Delay: options.RollbackDelay})
	if err != nil {
		return result, err
	}
	return transaction.applyPrepared(ctx, result, scheduler, options, nil)
}

// ApplyCandidate streams complete generated RSC files once through SCP and
// executes only small import wrappers through the same guarded transaction.
func (transaction *Transaction) ApplyCandidate(ctx context.Context, applySource, rollbackSource string, options TransactionOptions) (TransactionResult, error) {
	var result TransactionResult
	if options.HealthCheck == nil {
		return result, errors.New("RouterOS post-apply health check is required")
	}
	if transaction.upload == nil || transaction.cleanup == nil {
		return result, errors.New("RouterOS candidate upload transport is unavailable")
	}
	if options.SettleTimeout <= 0 {
		options.SettleTimeout = 30 * time.Second
	}
	rollbackImport, err := transaction.upload(ctx, "rollback", rollbackSource)
	if err != nil {
		return result, err
	}
	applyImport, err := transaction.upload(ctx, "apply", applySource)
	if err != nil {
		cleanupContext, cancel := context.WithTimeout(context.Background(), options.SettleTimeout)
		defer cancel()
		return result, errors.Join(err, transaction.cleanup(cleanupContext, rollbackImport))
	}
	imports := []string{applyImport, rollbackImport}
	rollbackName, err := transaction.rest.PrepareImportScript(ctx, "rollback", rollbackImport)
	if err != nil {
		return result, errors.Join(err, transaction.cleanupImports(imports, options.SettleTimeout))
	}
	result.RollbackScript = rollbackName
	applyName, err := transaction.rest.PrepareImportScript(ctx, "apply", applyImport)
	if err != nil {
		return result, errors.Join(err, transaction.cleanupImports(imports, options.SettleTimeout))
	}
	result.ApplyScript = applyName
	scheduler, err := transaction.rest.ArmRollback(ctx, rollbackName, RollbackOptions{
		Delay: options.RollbackDelay, ManagedImport: rollbackImport,
	})
	if err != nil {
		return result, errors.Join(err, transaction.cleanupImports(imports, options.SettleTimeout))
	}
	return transaction.applyPrepared(ctx, result, scheduler, options, imports)
}

func (transaction *Transaction) applyPrepared(ctx context.Context, result TransactionResult, scheduler string, options TransactionOptions, imports []string) (TransactionResult, error) {
	if options.BeforeApply != nil {
		if err := options.BeforeApply(ctx); err != nil {
			rollbackErr := transaction.rollbackPrepared(result.RollbackScript, scheduler, imports, options.SettleTimeout)
			return result, guardedFailure("RouterOS pre-apply runtime guard failed", err, rollbackErr)
		}
	}
	if options.SchedulerGuardOnly {
		result.GuardMode = "rollback_scheduler"
		return transaction.applyWithSchedulerGuard(ctx, result, scheduler, options, imports)
	}

	session, err := transaction.begin(ctx, result.ApplyScript)
	if err != nil {
		// Some RouterOS builds acknowledge Safe Mode and then terminate the SSH
		// console. Once floating history has settled, the already-armed local
		// rollback scheduler can safely own the same idempotent candidate.
		settleContext, cancel := context.WithTimeout(context.Background(), options.SettleTimeout)
		settleErr := transaction.rest.WaitSafeModeSettled(settleContext, options.SettleTimeout)
		cancel()
		if settleErr != nil {
			return result, transactionFailure(TransactionRecoveryPending, err, settleErr)
		}
		result.GuardMode = "rollback_scheduler_fallback"
		return transaction.applyWithSchedulerGuard(ctx, result, scheduler, options, imports)
	}
	result.GuardMode = "ssh_safe_mode"
	result.HistoryCapReached = session.HistoryCapReached()
	if err := options.HealthCheck(ctx); err != nil {
		cleanupErr := transaction.cleanupAfterAbort(scheduler, result.RollbackScript, session, options.SettleTimeout, imports)
		return result, guardedFailure("RouterOS candidate failed post-apply health check", err, cleanupErr)
	}
	if err := session.Commit(ctx, options.SettleTimeout); err != nil {
		// Commit uncertainty keeps the independent scheduler armed.
		return result, transactionFailure(TransactionRecoveryPending, err)
	}
	cleanupContext, cancel := context.WithTimeout(context.Background(), options.SettleTimeout)
	defer cancel()
	if err := transaction.rest.WaitSafeModeSettled(cleanupContext, options.SettleTimeout); err != nil {
		return result, transactionFailure(TransactionRecoveryPending, err)
	}
	if err := transaction.rest.DisarmRollback(cleanupContext, scheduler); err != nil {
		rollbackErr := transaction.restoreWhileGuardArmed(result.RollbackScript, options.SettleTimeout)
		state := TransactionRolledBack
		if rollbackErr != nil {
			state = TransactionRecoveryPending
		}
		return result, transactionFailure(state, errors.New("RouterOS rollback guard could not be disarmed"), err, rollbackErr)
	}
	if options.Finalize != nil {
		if err := options.Finalize(cleanupContext); err != nil {
			rollbackErr := transaction.restoreAfterGuardDisarmed(result.RollbackScript, imports, options.SettleTimeout)
			state := TransactionRolledBack
			if rollbackErr != nil {
				state = TransactionStateUnconfirmed
			}
			return result, transactionFailure(state, errors.New("RouterOS candidate finalization failed"), err, rollbackErr)
		}
	}
	if len(imports) > 0 {
		if err := transaction.cleanup(cleanupContext, imports...); err != nil {
			// Imported candidates are inert after their wrapper has completed.
			// Do not misreport a committed healthy Apply as failed only because
			// optional file cleanup could not finish.
			result.CleanupPending = true
		}
	}
	return result, nil
}

func (transaction *Transaction) applyWithSchedulerGuard(ctx context.Context, result TransactionResult, scheduler string, options TransactionOptions, imports []string) (TransactionResult, error) {
	if err := transaction.run(ctx, result.ApplyScript); err != nil {
		rollbackErr := transaction.rollbackPrepared(result.RollbackScript, scheduler, imports, options.SettleTimeout)
		return result, guardedFailure("RouterOS guarded candidate failed", err, rollbackErr)
	}
	if err := options.HealthCheck(ctx); err != nil {
		rollbackErr := transaction.rollbackPrepared(result.RollbackScript, scheduler, imports, options.SettleTimeout)
		return result, guardedFailure("RouterOS candidate failed post-apply health check", err, rollbackErr)
	}
	cleanupContext, cancel := context.WithTimeout(context.Background(), options.SettleTimeout)
	defer cancel()
	if err := transaction.rest.DisarmRollback(cleanupContext, scheduler); err != nil {
		rollbackErr := transaction.restoreWhileGuardArmed(result.RollbackScript, options.SettleTimeout)
		state := TransactionRolledBack
		if rollbackErr != nil {
			state = TransactionRecoveryPending
		}
		return result, transactionFailure(state, errors.New("RouterOS rollback guard could not be disarmed"), err, rollbackErr)
	}
	if options.Finalize != nil {
		if err := options.Finalize(cleanupContext); err != nil {
			rollbackErr := transaction.restoreAfterGuardDisarmed(result.RollbackScript, imports, options.SettleTimeout)
			state := TransactionRolledBack
			if rollbackErr != nil {
				state = TransactionStateUnconfirmed
			}
			return result, transactionFailure(state, errors.New("RouterOS candidate finalization failed"), err, rollbackErr)
		}
	}
	if len(imports) > 0 {
		if err := transaction.cleanup(cleanupContext, imports...); err != nil {
			result.CleanupPending = true
		}
	}
	return result, nil
}

func (transaction *Transaction) rollbackPrepared(rollbackName, scheduler string, imports []string, settleTimeout time.Duration) error {
	rollbackContext, cancel := context.WithTimeout(context.Background(), settleTimeout)
	defer cancel()
	return transaction.rollbackCommitted(rollbackContext, rollbackName, scheduler, imports, settleTimeout)
}

func guardedFailure(message string, cause, rollbackErr error) error {
	state := TransactionRolledBack
	if rollbackErr != nil {
		state = TransactionRecoveryPending
	}
	return transactionFailure(state, errors.New(message), cause, rollbackErr)
}

func (transaction *Transaction) rollbackCommitted(ctx context.Context, rollbackName, scheduler string, imports []string, settleTimeout time.Duration) error {
	if err := transaction.run(ctx, rollbackName); err != nil {
		// The independent scheduler stays armed when immediate rollback is
		// uncertain. Do not remove an import it may still need.
		return err
	}
	if err := transaction.rest.WaitSafeModeSettled(ctx, settleTimeout); err != nil {
		return err
	}
	if err := transaction.rest.DisarmRollback(ctx, scheduler); err != nil {
		return err
	}
	if len(imports) > 0 {
		return transaction.cleanup(ctx, imports...)
	}
	return nil
}

// restoreWhileGuardArmed returns RouterOS to the previous candidate without
// touching the scheduler that failed to disarm. The one-shot scheduler remains
// an idempotent second attempt if the immediate recovery is interrupted.
func (transaction *Transaction) restoreWhileGuardArmed(rollbackName string, settleTimeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), settleTimeout)
	defer cancel()
	if err := transaction.run(ctx, rollbackName); err != nil {
		return err
	}
	return transaction.rest.WaitSafeModeSettled(ctx, settleTimeout)
}

// restoreAfterGuardDisarmed handles the narrow window in which RouterOS is
// committed but the local application commit point could not be published.
// There is no armed fallback in this path, so a failed immediate restore is
// explicitly reported as unconfirmed.
func (transaction *Transaction) restoreAfterGuardDisarmed(rollbackName string, imports []string, settleTimeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), settleTimeout)
	defer cancel()
	if err := transaction.run(ctx, rollbackName); err != nil {
		return err
	}
	if err := transaction.rest.WaitSafeModeSettled(ctx, settleTimeout); err != nil {
		return err
	}
	if len(imports) > 0 {
		return transaction.cleanup(ctx, imports...)
	}
	return nil
}

func (transaction *Transaction) cleanupAfterAbort(scheduler, rollbackName string, session *SafeModeSession, settleTimeout time.Duration, imports []string) error {
	cleanupContext, cancel := context.WithTimeout(context.Background(), settleTimeout)
	defer cancel()
	var rollbackErr error
	if session != nil {
		autoReleased := session.HistoryCapReached()
		abortErr := session.Abort()
		if autoReleased {
			rollbackErr = transaction.run(cleanupContext, rollbackName)
		}
		rollbackErr = errors.Join(abortErr, rollbackErr)
	}
	if err := transaction.rest.WaitSafeModeSettled(cleanupContext, settleTimeout); err != nil {
		// Leave the scheduler armed whenever immediate rollback is uncertain.
		return errors.Join(rollbackErr, err)
	}
	if rollbackErr != nil {
		return rollbackErr
	}
	if err := transaction.rest.DisarmRollback(cleanupContext, scheduler); err != nil {
		return err
	}
	if len(imports) > 0 {
		return transaction.cleanup(cleanupContext, imports...)
	}
	return nil
}

func (transaction *Transaction) cleanupImports(imports []string, timeout time.Duration) error {
	cleanupContext, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return transaction.cleanup(cleanupContext, imports...)
}
