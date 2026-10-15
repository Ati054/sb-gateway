package policydns

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/domainset"
)

func TestLegacyInlineConfigSharesMembershipAfterStreamingDecode(t *testing.T) {
	domains := make([]string, 1000)
	for n := range domains {
		domains[n] = fmt.Sprintf("host-%d.example.test", n)
	}
	raw := rawConfig{Version: 1, Lanes: []laneConfig{
		{ID: "a", Host: "127.0.0.1", Port: 31001, Final: "wan", Rules: []ruleConfig{{DomainSuffix: domains, Server: "vpn"}}},
		{ID: "b", Host: "127.0.0.1", Port: 31002, Final: "wan", Rules: []ruleConfig{{DomainSuffix: domains, Action: "reject"}}},
	}}
	body, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeRuntimeConfig(strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.DomainSets) != 1 {
		t.Fatal("inline membership was not interned")
	}
	index, ids, err := domainset.Compile(decoded.DomainSets)
	if err != nil {
		t.Fatal(err)
	}
	for n, rawLane := range decoded.Lanes {
		if len(rawLane.Rules[0].DomainSuffix) != 0 {
			t.Fatal("duplicate membership retained")
		}
		lane, err := compileLaneWithSets(rawLane, index, ids)
		if err != nil {
			t.Fatal(err)
		}
		server, reject := lane.target("sub.host-999.example.test")
		if reject != (n == 1) || (n == 0 && server != "vpn") {
			t.Fatal("lane decision changed")
		}
	}
}

func TestStreamingConfigRejectsInvalidDocuments(t *testing.T) {
	for _, body := range []string{`[]`, `{"lanes":{}}`, `{"lanes":[}`, `{"version":1,"version":2}`, `{} {}`, `{"lanes":[]} garbage`} {
		if _, err := decodeRuntimeConfig(strings.NewReader(body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	if _, err := decodeRuntimeConfig(strings.NewReader(`{"ignored":"` + strings.Repeat("x", maxRuntimeConfigBytes) + `"}`)); err == nil {
		t.Fatal("oversize document accepted")
	}
}

func TestStreamingConfigAcceptsSharedDefinitionsAfterLanes(t *testing.T) {
	set := domainset.Set{DomainSuffix: []string{"example.test"}}
	body := fmt.Sprintf(`{"lanes":[{"id":"a","host":"127.0.0.1","port":31000,"rules":[{"domain_set":%q,"server":"wan"}]}],"domain_sets":{%q:{"domain":null,"domain_suffix":["example.test"]}},"version":2}`, set.ID(), set.ID())
	raw, err := decodeRuntimeConfig(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	index, ids, err := domainset.Compile(raw.DomainSets)
	if err != nil {
		t.Fatal(err)
	}
	lane, err := compileLaneWithSets(raw.Lanes[0], index, ids)
	if err != nil {
		t.Fatal(err)
	}
	if server, reject := lane.target("sub.example.test"); server != "wan" || reject {
		t.Fatal("forward definition lost")
	}
}
