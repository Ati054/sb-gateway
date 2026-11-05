package routeros

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestCatalogImageWorkersKeepMountQueryVariablesDistinctFromProperties(t *testing.T) {
	// RouterOS find predicates resolve property names in their own scope.
	// A same-named variable can turn the intended comparison into a tautology.
	predicate := regexp.MustCompile(`\bwhere\s+([A-Za-z][A-Za-z0-9-]*)=\$([A-Za-z][A-Za-z0-9-]*)\b`)
	for _, schema := range []int{0, 1} {
		for _, offline := range []bool{false, true} {
			for _, keepPrevious := range []bool{false, true} {
				t.Run(fmt.Sprintf("schema-%d/offline-%t/retain-%t", schema, offline, keepPrevious), func(t *testing.T) {
					spec := ImageUpdateSpec{Version: "2.0.0", StorageRoot: "disk/sb-gateway", CandidateRoot: "disk/sb-gateway/root-2.0.0", CandidateSource: "local-file", CandidateReference: "disk/sb-gateway/data/lifecycle-uploads/image.tar", ContainerAddress: "192.0.2.2", CatalogSchema: schema, StoppedPredecessor: offline, KeepPrevious: keepPrevious}
					worker := renderImageUpdateWorker(spec)
					for _, match := range predicate.FindAllStringSubmatch(worker, -1) {
						if match[1] == match[2] {
							t.Fatalf("rendered find predicate shadows its property: %s", match[0])
						}
					}
					for _, contract := range []string{
						`:local sbCatalogMountlist [:tostr ($contract->"mountlist")]`,
						`:local mounts [/container/mounts/find where list=$sbCatalogMountlist]`,
						`:if ([:len $mounts] != 4) do={ :error "SB-GATEWAY rollback compatibility mounts are incomplete" }`,
						`:return [:toarray $sbCatalogMountlist]`,
						`:foreach sbTransferMountlist in=$savedMountlists do={ :if (([:typeof $sbTransferMountlist] != "str") || ([:len $sbTransferMountlist] = 0) || ([:len [/container/mounts/find where list=$sbTransferMountlist]] = 0)) do={ :error "SB-GATEWAY image transfer mountlist is missing" } }`,
						`savedMountlists [$catalogTargetMountlists $oldRoot`,
						`failedMountlists [$catalogTargetMountlists`,
					} {
						if !strings.Contains(worker, contract) {
							t.Fatalf("mount selection or rollback guard is missing: %s", contract)
						}
					}
				})
			}
		}
	}
}
