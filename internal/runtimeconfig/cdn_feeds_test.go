package runtimeconfig

import (
	"reflect"
	"strings"
	"testing"
)

func TestAutomaticOriginFeedsFollowEnabledListenersAndSubscription(t *testing.T) {
	config := routerOSModelConfig()
	config["ingress"] = map[string]any{"subscription_hostname": "sub.example.test", "subscription_origin_server_name": "origin.example.test", "subscription_endpoint_mode": "separate", "subscription_cdn_provider": "timeweb", "subscription_origin_protection_mode": "auto-cidr", "subscription_listen_port": 18443}
	config["transports"] = []any{map[string]any{"id": "cdn", "kind": "ws", "enabled": true, "cdn_deployments": []any{
		map[string]any{"id": "g", "cdn_provider": "gcore", "origin_protection_mode": "auto-cidr", "origin_port": 8443},
		map[string]any{"id": "e", "cdn_provider": "edgecenter", "origin_protection_mode": "auto-cidr", "origin_port": 8444},
		map[string]any{"id": "y", "cdn_provider": "yandex", "origin_protection_mode": "auto-cidr", "origin_port": 8445},
		map[string]any{"id": "b", "cdn_provider": "beeline", "origin_protection_mode": "auto-cidr", "origin_port": 8446},
		map[string]any{"id": "off", "cdn_provider": "gcore", "origin_protection_mode": "auto-cidr", "origin_port": 8447, "enabled": false},
	}}}
	got, err := RequiredCDNFeeds(config)
	if err != nil || !reflect.DeepEqual(got, []string{"beeline", "edgecenter", "gcore", "timeweb", "yandex"}) {
		t.Fatalf("%v %v", got, err)
	}
	source, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range got {
		list := "SB_CDN_" + strings.ToUpper(id) + "_V4"
		if !strings.Contains(source, `src-address-list="`+list+`"`) || !strings.Contains(source, "trusted-cdn-"+list) {
			t.Fatal("missing source filter/guard exemption:", id)
		}
	}
	if strings.Contains(source, "dst-port=8447") {
		t.Fatal("disabled listener")
	}
	config["transports"].([]any)[0].(map[string]any)["enabled"] = false
	got, err = RequiredCDNFeeds(config)
	if err != nil || !reflect.DeepEqual(got, []string{"timeweb"}) {
		t.Fatalf("disabled transport still selected: %v %v", got, err)
	}
	config["ingress"].(map[string]any)["subscription_endpoint_mode"] = "reuse-cdn"
	got, err = RequiredCDNFeeds(config)
	if err != nil || len(got) != 0 {
		t.Fatalf("inactive separate endpoint selected: %v %v", got, err)
	}
}

func TestAutomaticOriginProvidersCannotShareDifferentTrustBoundaries(t *testing.T) {
	config := routerOSModelConfig()
	config["ingress"] = map[string]any{}
	config["transports"] = []any{map[string]any{"id": "cdn", "kind": "ws", "cdn_deployments": []any{
		map[string]any{"id": "g", "cdn_provider": "gcore", "origin_protection_mode": "auto-cidr", "origin_port": 443},
		map[string]any{"id": "y", "cdn_provider": "yandex", "origin_protection_mode": "auto-cidr", "origin_port": 443},
	}}}
	if _, err := RequiredCDNFeeds(config); err == nil {
		t.Fatal("different providers shared a RouterOS trust boundary")
	}
}
