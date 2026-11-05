package controlplane

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func subscriptionWalkTestOptions() subscriptionWalkOptions {
	return subscriptionWalkOptions{MaxBytes: 8 << 20, MaxLineBytes: 64 << 10, MaxIndexBytes: 64 << 20}
}

// The pre-streaming ID disambiguator is an independent compatibility oracle for
// the new fixed-hash registry. Keep these fixtures small and synthetic.
func legacySubscriptionWalkFixture(t *testing.T, links []string) []map[string]any {
	t.Helper()
	var nodes []map[string]any
	for index, link := range links {
		node, err := parseSubscriptionLine(link, index+1)
		if err == nil {
			nodes = append(nodes, node)
		}
	}
	deduplicateSubscriptionNodeIDs(nodes)
	return nodes
}

func TestSubscriptionWalkPreservesLegacyIdentityOrderAndCredentials(t *testing.T) {
	links := []string{
		"hy2://account-a@same.example.test:443#Same",
		"hy2://account-b@same.example.test:443#Same",
		"hy2://account-a@same.example.test:443#Same",
		"vless://bad@invalid.example.test:443",
		"vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@same.example.test:443?security=tls&type=ws#Same",
		"vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@same.example.test:443?security=tls&type=tcp#Same",
		"hy2://account-a@same.example.test:443#Different-label",
	}
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint(reverse), func(t *testing.T) {
			ordered := append([]string(nil), links...)
			if reverse {
				for first, last := 0, len(ordered)-1; first < last; first, last = first+1, last-1 {
					ordered[first], ordered[last] = ordered[last], ordered[first]
				}
			}
			want := legacySubscriptionWalkFixture(t, ordered)
			var got []map[string]any
			stats, err := walkProxySubscription(context.Background(), []byte(strings.Join(ordered, "\r\n")), subscriptionWalkTestOptions(), func(node map[string]any) error {
				got = append(got, node)
				return nil
			})
			if err != nil || !reflect.DeepEqual(want, got) {
				t.Fatalf("stream changed normalized IDs/order/credential distinction: err=%v", err)
			}
			if stats.SupportedLines != len(ordered) || stats.SkippedNodes != 1 || stats.ValidNodes != len(want) || stats.EmittedNodes != len(want) {
				t.Fatalf("invalid-line accounting: %+v", stats)
			}
		})
	}
}

func TestSubscriptionWalkSupportsEveryLegacyBase64EncodingAndWhitespace(t *testing.T) {
	body := []byte(strings.Repeat("x", 16383) + "Жx\uffff\uffff\rhy2://password@one.example.test:443#One\n" + "hy2://other@two.example.test:443#Two")
	var expected []map[string]any
	if _, err := walkProxySubscription(context.Background(), body, subscriptionWalkTestOptions(), func(node map[string]any) error { expected = append(expected, node); return nil }); err != nil {
		t.Fatal(err)
	}
	for index, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			encoded := encoding.EncodeToString(body)
			var spaced strings.Builder
			for index, value := range encoded {
				spaced.WriteRune(value)
				if index%29 == 0 {
					spaced.WriteString(" \t\r\n")
				}
			}
			var got []map[string]any
			stats, err := walkProxySubscription(context.Background(), []byte(spaced.String()), subscriptionWalkTestOptions(), func(node map[string]any) error { got = append(got, node); return nil })
			if err != nil || stats.DecodedBytes != len(body) || !reflect.DeepEqual(expected, got) {
				t.Fatalf("base64 compatibility: stats=%+v err=%v", stats, err)
			}
		})
	}
}

func TestSubscriptionWalkRejectsMalformedTailBeforeCallbacks(t *testing.T) {
	valid := "hy2://password@one.example.test:443"
	for _, body := range [][]byte{
		append([]byte(valid+"\n"), 0xff),
		[]byte(base64.StdEncoding.EncodeToString([]byte(valid)) + "!"),
		[]byte(base64.StdEncoding.EncodeToString(append([]byte(valid+"\n"), 0xff))),
	} {
		calls := 0
		_, err := walkProxySubscription(context.Background(), body, subscriptionWalkTestOptions(), func(map[string]any) error { calls++; return nil })
		var failure *subscriptionParseError
		if !errors.As(err, &failure) || failure.code != "invalid_content" || calls != 0 {
			t.Fatalf("malformed tail published callback: calls=%d err=%v", calls, err)
		}
	}
}

func TestSubscriptionWalkQuotaCountsInvalidSupportedLinesLikeLegacy(t *testing.T) {
	body := []byte("vless://bad@invalid.example.test:443\rhy2://password@one.example.test:443")
	options := subscriptionWalkTestOptions()
	options.MaxNodes = 1
	calls := 0
	_, err := walkProxySubscription(context.Background(), body, options, func(map[string]any) error { calls++; return nil })
	var failure *subscriptionParseError
	if !errors.As(err, &failure) || failure.code != "too_many_nodes" || calls != 0 {
		t.Fatalf("legacy supported-line quota changed: calls=%d err=%v", calls, err)
	}
	options.MaxNodes = 0
	stats, err := walkProxySubscription(context.Background(), body, options, func(map[string]any) error { calls++; return nil })
	if err != nil || calls != 1 || stats.SupportedLines != 2 || stats.SkippedNodes != 1 {
		t.Fatalf("explicit no-quota stream: stats=%+v calls=%d err=%v", stats, calls, err)
	}
}

func TestSubscriptionWalkPreservesFirstInvalidSupportedError(t *testing.T) {
	first := "hy2://password@unsafe.example.test:443?insecure=1"
	_, expected := parseSubscriptionHysteria2Link(first, 1)
	var wanted *subscriptionParseError
	if !errors.As(expected, &wanted) {
		t.Fatal("fixture must have a typed first invalid-node error")
	}
	calls := 0
	stats, err := walkProxySubscription(context.Background(), []byte(first+"\nvless://bad@invalid.example.test:443"), subscriptionWalkTestOptions(), func(map[string]any) error { calls++; return nil })
	var got *subscriptionParseError
	if !errors.As(err, &got) || got.code != wanted.code || calls != 0 || stats.SkippedNodes != 2 {
		t.Fatalf("first invalid-node outcome changed: stats=%+v calls=%d err=%v", stats, calls, err)
	}
}

func TestSubscriptionWalkResourceLimitsAreNotNodeQuotas(t *testing.T) {
	body := []byte("hy2://password@one.example.test:443")
	for _, field := range []string{"raw", "line", "index"} {
		t.Run(field, func(t *testing.T) {
			options := subscriptionWalkTestOptions()
			switch field {
			case "raw":
				options.MaxBytes = len(body) - 1
				options.MaxLineBytes = options.MaxBytes
			case "line":
				options.MaxLineBytes = len(body) - 1
			case "index":
				options.MaxIndexBytes = 1
			}
			calls := 0
			_, err := walkProxySubscription(context.Background(), body, options, func(map[string]any) error { calls++; return nil })
			var failure *subscriptionParseError
			if !errors.As(err, &failure) || failure.code != "too_large" || calls != 0 {
				t.Fatalf("resource limit became quota/partial output: calls=%d err=%v", calls, err)
			}
		})
	}
	options := subscriptionWalkTestOptions()
	options.MaxLineBytes = len(body)
	if _, err := walkProxySubscription(context.Background(), body, options, func(map[string]any) error { return nil }); err != nil {
		t.Fatalf("exact line limit rejected: %v", err)
	}
}

func TestSubscriptionWalkCancellationAndCallbackFailureRequireAbort(t *testing.T) {
	body := []byte("hy2://password@one.example.test:443\nhy2://other@two.example.test:443")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	if _, err := walkProxySubscription(ctx, body, subscriptionWalkTestOptions(), func(map[string]any) error { calls++; return nil }); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("cancelled input: calls=%d err=%v", calls, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	stats, err := walkProxySubscription(ctx, body, subscriptionWalkTestOptions(), func(map[string]any) error { calls++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || calls != 1 || stats.EmittedNodes != 1 {
		t.Fatalf("cancelled partial staging must not succeed: stats=%+v calls=%d err=%v", stats, calls, err)
	}
	want := errors.New("synthetic staging failure")
	stats, err = walkProxySubscription(context.Background(), body, subscriptionWalkTestOptions(), func(map[string]any) error { return want })
	if !errors.Is(err, want) || stats.EmittedNodes != 0 {
		t.Fatalf("callback failure hidden: stats=%+v err=%v", stats, err)
	}
}

func TestSubscriptionWalkNoImplicitQuotaAndDuplicateSuffixes(t *testing.T) {
	const count = 1005
	link := "hy2://password@one.example.test:443#Same"
	body := []byte(strings.Repeat(link+"\n", count))
	// The old duplicate-group rule applies credential identity even to the
	// group's first member; obtain that unchanged rule from the legacy oracle.
	baseID := legacySubscriptionWalkFixture(t, []string{link, link})[0]["id"].(string)
	lastID := ""
	stats, err := walkProxySubscription(context.Background(), body, subscriptionWalkTestOptions(), func(node map[string]any) error { lastID = node["id"].(string); return nil })
	if err != nil || stats.EmittedNodes != count || lastID != fmt.Sprintf("%s-%d", baseID, count) {
		t.Fatalf("implicit quota or suffix drift: stats=%+v err=%v", stats, err)
	}
}

func TestSubscriptionWalkRegistryBackingSizeMatchesBudget(t *testing.T) {
	if reflect.TypeOf(subscriptionIdentityKey{}).Size() != 12 || reflect.TypeOf(subscriptionIDSlot{}).Size() != 36 {
		t.Fatal("update pointer-free index byte accounting for this architecture")
	}
}
