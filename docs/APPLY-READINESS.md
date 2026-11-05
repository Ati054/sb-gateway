# Apply readiness

When Apply changes RouterOS configuration, the transaction activates and checks
the candidate runtime, disarms its rollback guard, and publishes the active
configuration and runtime commit. Only after those steps succeed can the live
Apply operation allow the watchdog to confirm traffic readiness.

This allowance starts in the transaction's finalization callback, before optional
import cleanup and backup retention. The watchdog can therefore restore managed
traffic while that housekeeping is still running. Housekeeping remains synchronous;
the Apply response can take longer than traffic restoration.

The allowance does not bypass the RouterOS readiness lease, persistent-storage
checks, runtime readiness, or the required scoped selector and traffic proofs.
Apply still waits for fresh traffic proof and confirmation of the managed RouterOS
diversion gate before reporting traffic restoration. An unpublished configuration
commit or a failed runtime commit does not enable this allowance. The live flag is
cleared whenever the Apply operation returns, including error paths.

`TestRouterOSApplyReadinessBeforeHousekeeping` holds housekeeping behind a barrier
and checks readiness after a successful commit, rejection without a readiness
lease, rejection after configuration or runtime commit failures, and flag cleanup.
`TestRouterOSApplyWaitsForTrafficAfterTransactionCommits` checks that the Apply
response still requires the final traffic confirmation and preserves the active
commit if that confirmation fails.
