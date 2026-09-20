package controlplane

import (
	"reflect"
	"strings"
	"testing"
)

func TestPersistentMountsWritableFromRejectsReadOnlyOrMissingMount(t *testing.T) {
	required := []string{"/config", "/data", "/logs", "/state"}
	healthy := `/dev/vdb /config ext4 rw,nosuid,nodev 0 0
/dev/vdb /data ext4 rw,nosuid,nodev 0 0
/dev/vdb /logs ext4 rw,nosuid,nodev 0 0
/dev/vdb /state ext4 rw,nosuid,nodev 0 0
`
	if ok, blocked := persistentMountsWritableFrom(strings.NewReader(healthy), required); !ok || len(blocked) != 0 {
		t.Fatalf("healthy mounts rejected: ok=%v blocked=%v", ok, blocked)
	}

	unhealthy := `/dev/vdb /config ext4 ro,nosuid,nodev 0 0
/dev/vdb /data ext4 rw,nosuid,nodev 0 0
/dev/vdb /state ext4 rw,nosuid,nodev 0 0
`
	ok, blocked := persistentMountsWritableFrom(strings.NewReader(unhealthy), required)
	if ok || !reflect.DeepEqual(blocked, []string{"/config", "/logs"}) {
		t.Fatalf("unsafe mounts accepted: ok=%v blocked=%v", ok, blocked)
	}
}
