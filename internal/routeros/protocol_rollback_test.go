package routeros

import (
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func TestLegacyProtocolRollbackKeepsFullCandidateTransportContract(t *testing.T) {
	previous := managedCandidateHeader
	for _, section := range managedCandidateSections {
		previous += "# SB-GATEWAY section:" + section + "\n:put ok\n"
	}
	desired := previous + "# SB-GATEWAY section:protocol-policy\n"
	rollback := runtimeconfig.WithLegacyProtocolCleanup(previous, desired)
	if err := validateFullCandidate(rollback); err != nil {
		t.Fatalf("legacy cleanup broke the full-candidate transport contract: %v", err)
	}
	if !strings.Contains(rollback, `comment~"^SB-GATEWAY protocol "`) {
		t.Fatal("legacy owned-rule cleanup missing")
	}
	if rollback == previous {
		t.Fatal("legacy cleanup was not added")
	}
	if got := runtimeconfig.WithLegacyProtocolCleanup(desired, desired); got != desired {
		t.Fatal("current candidate changed")
	}
}
