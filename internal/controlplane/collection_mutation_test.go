package controlplane

import (
	"net/http"
	"testing"
)

func TestNativeReverseVLESSCollectionCRUDProvisionsAndRetainsUUID(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range collectionArray(config["transports"]) {
		transport, ok := raw.(map[string]any)
		if ok && (transport["id"] == "direct-reality" || transport["id"] == "grpc-reality") {
			transport["enabled"] = true
		}
	}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	setDraftReadinessForTest(t, server, true)
	create := performRequest(t, server, http.MethodPost, apiPrefix+"/reverse-vless-exits", map[string]any{
		"item": map[string]any{
			"id": "reverse-test", "display_name": "Reverse test", "enabled": true,
			"transport_ids": []any{"direct-reality"},
		},
	}, map[string]string{csrfHeader: csrf}, cookie)
	if create.Code != http.StatusOK {
		t.Fatalf("create failed: %d %s", create.Code, create.Body.String())
	}
	requireDraftUnreadyForTest(t, server, "create")
	created := decodeResponse(t, create)["item"].(map[string]any)
	if created["uuid_secret_ref"] != "reverse-vless-exits/reverse-test.uuid" {
		t.Fatalf("created item = %#v", created)
	}
	uuidValue, err := server.secrets.read("reverse-vless-exits/reverse-test.uuid", true)
	if err != nil || !uuidValuePattern.MatchString(uuidValue) {
		t.Fatalf("generated UUID = %q, err=%v", uuidValue, err)
	}

	setDraftReadinessForTest(t, server, true)
	update := performRequest(t, server, http.MethodPut, apiPrefix+"/reverse-vless-exits/reverse-test", map[string]any{
		"id": "ignored", "display_name": "Updated", "enabled": true,
		"transport_ids": []any{"grpc-reality"}, "uuid": "2f1c08fc-3f43-4e95-8f57-f8bded750a1a",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if update.Code != http.StatusOK {
		t.Fatalf("update failed: %d %s", update.Code, update.Body.String())
	}
	requireDraftUnreadyForTest(t, server, "update")
	updatedUUID, err := server.secrets.read("reverse-vless-exits/reverse-test.uuid", true)
	if err != nil || updatedUUID != "2f1c08fc-3f43-4e95-8f57-f8bded750a1a" {
		t.Fatalf("updated UUID = %q, err=%v", updatedUUID, err)
	}

	setDraftReadinessForTest(t, server, true)
	deleted := performRequest(t, server, http.MethodDelete, apiPrefix+"/reverse-vless-exits/reverse-test", nil, map[string]string{csrfHeader: csrf}, cookie)
	if deleted.Code != http.StatusOK || decodeResponse(t, deleted)["deleted"] != true {
		t.Fatalf("delete failed: %d %s", deleted.Code, deleted.Body.String())
	}
	requireDraftUnreadyForTest(t, server, "delete")
	if !server.secrets.exists("reverse-vless-exits/reverse-test.uuid") {
		t.Fatal("delete removed recovery secret")
	}
}

func setDraftReadinessForTest(t *testing.T, server *Server, ready bool) {
	t.Helper()
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	objectAt(config, "system")["deployment_ready"] = ready
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
}

func requireDraftUnreadyForTest(t *testing.T, server *Server, action string) {
	t.Helper()
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	if objectAt(config, "system")["deployment_ready"] != false {
		t.Fatalf("%s did not invalidate deployment readiness", action)
	}
}

func TestNativeCollectionValidationDoesNotWritePendingSecrets(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/reverse-vless-exits", map[string]any{
		"id": "invalid-reverse", "enabled": true, "transport_ids": []any{"missing"},
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid reverse returned %d: %s", response.Code, response.Body.String())
	}
	if server.secrets.exists("reverse-vless-exits/invalid-reverse.uuid") {
		t.Fatal("validation failure left an orphan UUID")
	}
}

func TestNativeSubscriptionMutationStoresURLOnlyAsSecret(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions", map[string]any{
		"item": map[string]any{
			"id": "native", "name": "Native", "enabled": true,
			"url": "https://example.test/private-token", "update_interval_minutes": 360,
		},
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("subscription create failed: %d %s", response.Code, response.Body.String())
	}
	item := decodeResponse(t, response)["item"].(map[string]any)
	if _, leaked := item["url"]; leaked || item["url_secret_ref"] != "subscriptions/native.url" {
		t.Fatalf("subscription response leaked URL: %#v", item)
	}
	stored, err := server.secrets.read("subscriptions/native.url", true)
	if err != nil || stored != "https://example.test/private-token" {
		t.Fatalf("stored URL = %q, err=%v", stored, err)
	}
}

func TestSubscriptionURLChangePreservesAppliedSecret(t *testing.T) {
	s := newTestServer(t)
	const oldRef = "subscriptions/native.url"
	const oldURL = "https://old.example.test/sub"
	if err := s.secrets.write(oldRef, oldURL, false); err != nil {
		t.Fatal(err)
	}
	item, pending, err := s.prepareEntitySecrets("subscriptions", map[string]any{"id": "native", "url_secret_ref": oldRef, "url": "https://new.example.test/sub"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if item["url_secret_ref"] == oldRef {
		t.Fatal("URL update overwrites applied source")
	}
	if _, err = s.writeEntitySecrets(pending); err != nil {
		t.Fatal(err)
	}
	if old, err := s.secrets.read(oldRef, true); err != nil || old != oldURL {
		t.Fatal("applied source changed")
	}
	if updated, err := s.secrets.read(subscriptionText(item["url_secret_ref"]), true); err != nil || updated != "https://new.example.test/sub" {
		t.Fatal("new source missing")
	}
}

func TestNativeSubscriptionReserveCRUDNormalizesLinkAndKeepsUUIDSecret(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	const uuid = "2f1c08fc-3f43-4e95-8f57-f8bded750a1a"
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/subscription-reserves", map[string]any{
		"item": map[string]any{
			"id": "reserve-de", "display_name": "Germany reserve", "enabled": true,
			"link": "vless://" + uuid + "@reserve.example.test:443?security=reality&sni=front.example.test&pbk=public-key&sid=0123456789abcdef&fp=chrome&type=xhttp&mode=packet-up&path=%2Freserve&x_padding_bytes=120-900&country=DE&city=Berlin#Reserve%20DE",
		},
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("reserve create failed: %d %s", response.Code, response.Body.String())
	}
	item := decodeResponse(t, response)["item"].(map[string]any)
	if _, leaked := item["link"]; leaked {
		t.Fatalf("reserve response leaked link: %#v", item)
	}
	node, ok := item["node"].(map[string]any)
	if !ok || node["protocol"] != "vless" || node["server"] != "reserve.example.test" || node["country"] != "DE" || node["label"] != "Reserve DE" {
		t.Fatalf("normalized reserve node = %#v", item["node"])
	}
	if node["uuid_secret_ref"] != "subscription-reserves/reserve-de.uuid" || node["subscription_reserve_id"] != "reserve-de" {
		t.Fatalf("reserve identity = %#v", node)
	}
	transport, ok := node["transport"].(map[string]any)
	if !ok || transport["type"] != "xhttp" || transport["mode"] != "packet-up" || transport["path"] != "/reserve" || transport["x_padding_bytes"] != "120-900" {
		t.Fatalf("normalized reserve transport = %#v", node["transport"])
	}
	stored, err := server.secrets.read("subscription-reserves/reserve-de.uuid", true)
	if err != nil || stored != uuid {
		t.Fatalf("stored reserve UUID = %q, err=%v", stored, err)
	}

	item["display_name"] = "Updated reserve"
	update := performRequest(t, server, http.MethodPut, apiPrefix+"/subscription-reserves/reserve-de", map[string]any{"item": item}, map[string]string{csrfHeader: csrf}, cookie)
	if update.Code != http.StatusOK {
		t.Fatalf("reserve update without link failed: %d %s", update.Code, update.Body.String())
	}
	retained, err := server.secrets.read("subscription-reserves/reserve-de.uuid", true)
	if err != nil || retained != uuid {
		t.Fatalf("updated reserve UUID = %q, err=%v", retained, err)
	}
}

func TestNativeSubscriptionReserveRejectsUnsafeLinkAndFourthReserveWithoutSecretWrites(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	unsafe := performRequest(t, server, http.MethodPost, apiPrefix+"/subscription-reserves", map[string]any{
		"id": "unsafe", "enabled": true,
		"link": "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@reserve.example.test:443?security=tls&allowInsecure=1",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if unsafe.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unsafe reserve returned %d: %s", unsafe.Code, unsafe.Body.String())
	}
	if server.secrets.exists("subscription-reserves/unsafe.uuid") {
		t.Fatal("unsafe reserve left an orphan UUID")
	}
	unsafeAlias := performRequest(t, server, http.MethodPost, apiPrefix+"/subscription-reserves", map[string]any{
		"id": "unsafe-alias", "enabled": true,
		"link": "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@reserve.example.test:443?security=tls&insecure=1",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if unsafeAlias.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unsafe reserve alias returned %d: %s", unsafeAlias.Code, unsafeAlias.Body.String())
	}

	for index, id := range []string{"reserve-a", "reserve-b", "reserve-c", "reserve-d"} {
		response := performRequest(t, server, http.MethodPost, apiPrefix+"/subscription-reserves", map[string]any{
			"id": id, "enabled": true,
			"link": "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@reserve.example.test:443?security=tls&type=grpc&serviceName=reserve",
		}, map[string]string{csrfHeader: csrf}, cookie)
		if index < 3 && response.Code != http.StatusOK {
			t.Fatalf("reserve %d create failed: %d %s", index+1, response.Code, response.Body.String())
		}
		if index == 3 && response.Code != http.StatusUnprocessableEntity {
			t.Fatalf("fourth reserve returned %d: %s", response.Code, response.Body.String())
		}
	}
	if server.secrets.exists("subscription-reserves/reserve-d.uuid") {
		t.Fatal("rejected fourth reserve left an orphan UUID")
	}
}

func TestNativeCollectionMutationRequiresCSRF(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	withoutCSRF := performRequest(t, server, http.MethodPost, apiPrefix+"/networks", map[string]any{
		"id": "lan", "kind": "internal", "cidrs": []any{"192.168.88.0/24"},
	}, nil, cookie)
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("mutation without CSRF returned %d", withoutCSRF.Code)
	}
}
