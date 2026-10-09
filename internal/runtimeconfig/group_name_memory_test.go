package runtimeconfig

import (
	"strings"
	"testing"
)

func TestGroupNameNormalizationSharedReplacer(t *testing.T) {
	for _, name := range []string{"Node", " Node ", "\u26a1\ufe0f NODE \u2b50\ufe0e", "", "\ufe0f"} {
		want := strings.ToLower(strings.TrimSpace(strings.NewReplacer("\ufe0e", "", "\ufe0f", "").Replace(name)))
		if got := normalizedGroupName(name); got != want {
			t.Fatalf("name=%q got=%q want=%q", name, got, want)
		}
	}
	group := map[string]any{"subscription_ids": []any{"*"}}
	if !subscriptionNodeGroupMatches(group, map[string]any{"subscription_id": "provider", "label": "\u26a1\ufe0f Node"}) {
		t.Fatal("empty name filter changed membership")
	}
	if subscriptionNodeGroupMatches(map[string]any{}, map[string]any{"label": "Node"}) {
		t.Fatal("empty group claimed all nodes")
	}
}

func BenchmarkGroupNameNormalization(b *testing.B) {
	for _, legacy := range []bool{true, false} {
		name := "shared"
		if legacy {
			name = "per-call"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if legacy {
					_ = strings.ToLower(strings.TrimSpace(strings.NewReplacer("\ufe0e", "", "\ufe0f", "").Replace("\u26a1\ufe0f NODE \u2b50\ufe0f")))
				} else {
					_ = normalizedGroupName("\u26a1\ufe0f NODE \u2b50\ufe0f")
				}
			}
		})
	}
}
