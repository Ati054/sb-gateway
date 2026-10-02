package routeros

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Native matcher acceptance is opt-in and pinned to the existing test CHR.
// Only owned temporary rules are changed; no existing logs are cleared.
func TestServiceAccountLogShardsNativeCHR(t *testing.T) {
	if os.Getenv("SB_TEST_ROUTEROS_LOG_FILTER") != "1" {
		t.Skip("requires the dedicated local CHR")
	}
	password, err := os.ReadFile("/root/.sb-gateway-lab/admin.password")
	if err != nil {
		t.Fatal("lab credential unavailable")
	}
	client, err := NewClient(Options{BaseURL: "https://127.0.0.1:18443", Username: "admin", Password: strings.TrimSpace(string(password)), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.http.Transport.(*http.Transport)
	transport.TLSClientConfig.InsecureSkipVerify = true // Dedicated loopback/private CA only.
	defer transport.CloseIdleConnections()
	client.http.Transport = nativeLoggingRoundTripper(func(request *http.Request) (*http.Response, error) {
		response, err := transport.RoundTrip(request)
		if err == nil && response.StatusCode >= 400 {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
			response.Body.Close()
			response.Body = io.NopCloser(bytes.NewReader(body))
			t.Logf("lab rejection at %s: %s", request.URL.Path, body)
		}
		return response, err
	})
	ctx := context.Background()
	identity, err := client.request(ctx, http.MethodGet, "/rest/system/identity", nil)
	if err != nil || text(identity["name"]) != "sb-gateway-lab-chr" {
		t.Fatal("unexpected test CHR")
	}
	before, err := client.List(ctx, "/rest/system/logging")
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("SBGL%d", time.Now().UnixNano())
	ids := []string{}
	t.Cleanup(func() {
		for _, id := range ids {
			if _, err := client.request(ctx, http.MethodDelete, "/rest/system/logging/"+routerOSResourceID(id), nil); err != nil {
				t.Errorf("fixture cleanup: %v", err)
			}
		}
		after, err := client.List(ctx, "/rest/system/logging")
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Error("existing logging rules differ after cleanup")
		}
	})
	for part, pattern := range serviceAccountInfoFilters("sb-gateway-api") {
		rule, err := client.request(ctx, http.MethodPut, "/rest/system/logging", map[string]any{"topics": "info", "action": "memory", "prefix": name + " ", "comment": name, "regex": pattern})
		if id := text(rule[".id"]); id != "" {
			ids = append(ids, id)
		}
		if err != nil {
			t.Fatalf("native shard %d rejected: %v", part, err)
		}
	}
	if len(ids) != len("user sb-gateway-api logged ") {
		t.Fatal("incomplete native fixture")
	}
	cases := []struct {
		message string
		keep    bool
	}{
		{"user sb-gateway-api logged in via api", false},
		{"user sb-gateway-api logged out via api", false},
		{"user sb-gateway-api logged in from 172.30.80.2 via rest-api", false},
		{"login failure for user sb-gateway-api from 172.30.80.2 via api", true},
		{"user lab-operator logged in via api", true},
		{"user sb-gateway-api-other logged in via api", true},
		{"SB-GATEWAY lab unrelated info", true},
	}
	prefix := "user sb-gateway-api logged "
	for index := 1; index < len(prefix); index++ {
		cases = append(cases, struct {
			message string
			keep    bool
		}{prefix[:index], true})
		cases = append(cases, struct {
			message string
			keep    bool
		}{prefix[:index] + "?" + prefix[index+1:], true})
	}
	commands := []string{}
	for _, item := range cases {
		commands = append(commands, ":log info "+strconv.Quote(item.message))
	}
	if _, err := client.request(ctx, http.MethodPost, "/rest/execute", map[string]any{"script": strings.Join(commands, "; ")}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	logs, err := client.List(ctx, "/rest/log")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range cases {
		count := 0
		for _, row := range logs {
			if text(row["message"]) == name+" : "+item.message {
				count++
			}
		}
		want := 0
		if item.keep {
			want = 1
		}
		if count != want {
			t.Errorf("native keep count=%d want=%d for %q", count, want, item.message)
		}
	}
	for _, username := range []string{strings.Repeat("a", 32), strings.Repeat(".", 32)} {
		for part, pattern := range serviceAccountInfoFilters(username) {
			rule, err := client.request(ctx, http.MethodPut, "/rest/system/logging", map[string]any{"topics": "info", "action": "memory", "prefix": name + " ", "comment": name, "regex": pattern, "disabled": "true"})
			if id := text(rule[".id"]); id != "" {
				ids = append(ids, id)
			}
			if err != nil {
				t.Fatalf("maximum-name native shard %d rejected: %v", part, err)
			}
		}
	}
}

type nativeLoggingRoundTripper func(*http.Request) (*http.Response, error)

func (call nativeLoggingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return call(request)
}

func TestServiceAccountReconciliationNativeCHR(t *testing.T) {
	if os.Getenv("SB_TEST_ROUTEROS_LOG_FILTER") != "1" {
		t.Skip("requires the dedicated local CHR")
	}
	password, err := os.ReadFile("/root/.sb-gateway-lab/admin.password")
	if err != nil {
		t.Fatal("lab credential unavailable")
	}
	admin, err := NewClient(Options{BaseURL: "https://127.0.0.1:18443", Username: "admin", Password: strings.TrimSpace(string(password)), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	admin.http.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	defer admin.CloseIdleConnections()
	ctx := context.Background()
	identity, err := admin.request(ctx, http.MethodGet, "/rest/system/identity", nil)
	if err != nil || text(identity["name"]) != "sb-gateway-lab-chr" {
		t.Fatal("unexpected test CHR")
	}
	before, err := admin.List(ctx, "/rest/system/logging")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range before {
		if strings.HasPrefix(text(row["comment"]), serviceLogCommentPrefix) {
			t.Fatal("native fixture requires an unfiltered baseline")
		}
	}
	name := fmt.Sprintf("sbgl%x", time.Now().UnixNano()&0xffffff)
	marker := "SBGLnative" + name
	userID, sourceID := "", ""
	t.Cleanup(func() {
		if _, err := admin.RestoreServiceInfoLogs(ctx); err != nil {
			t.Errorf("restore native fixture logging: %v", err)
			return
		}
		for _, resource := range []struct{ path, id string }{{"/rest/system/logging/", sourceID}, {"/rest/user/", userID}} {
			if resource.id != "" {
				if _, err := admin.request(ctx, http.MethodDelete, resource.path+routerOSResourceID(resource.id), nil); err != nil {
					t.Errorf("fixture cleanup: %v", err)
				}
			}
		}
		after, err := admin.List(ctx, "/rest/system/logging")
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Error("operator logging rules differ after native reconciliation cleanup")
		}
	})
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	user, err := admin.request(ctx, http.MethodPut, "/rest/user", map[string]any{"name": name, "password": hex.EncodeToString(secret), "group": "sb-gateway-api", "address": "10.0.2.0/24,172.30.78.0/30", "comment": "SB-GATEWAY control-plane REST user"})
	userID = text(user[".id"])
	if err != nil || userID == "" {
		t.Fatalf("create scoped temporary service user: %v", err)
	}
	source, err := admin.request(ctx, http.MethodPut, "/rest/system/logging", map[string]any{"topics": "info,!fetch", "action": "memory", "prefix": marker + " ", "comment": marker})
	sourceID = text(source[".id"])
	if err != nil || sourceID == "" {
		t.Fatalf("create owned logging source: %v", err)
	}
	service, err := NewClient(Options{BaseURL: "https://127.0.0.1:18443", Username: name, Password: hex.EncodeToString(secret), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service.http.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	defer service.CloseIdleConnections()
	for attempt := range 2 {
		changed, err := service.SuppressServiceInfoLogs(ctx)
		if err != nil || changed != (attempt == 0) {
			t.Fatalf("native reconciliation attempt=%d changed=%t err=%v", attempt, changed, err)
		}
	}
	rows, err := admin.List(ctx, "/rest/system/logging")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(before)+1+2*(len("user "+name+" logged ")-1) {
		t.Fatal("native clone count differs from two source groups")
	}
	nativeManualLogPreflight(t, strings.TrimSpace(string(password)), true)
	prior, err := admin.List(ctx, "/rest/log")
	if err != nil {
		t.Fatal(err)
	}
	priorIDs := map[string]bool{}
	for _, row := range prior {
		priorIDs[text(row[".id"])] = true
	}
	admin.CloseIdleConnections()
	service.CloseIdleConnections()
	nativeLogSSHProbe(t, name, hex.EncodeToString(secret))
	nativeLogSSHProbe(t, "admin", strings.TrimSpace(string(password)))
	if _, err := service.request(ctx, http.MethodGet, "/rest/system/identity", nil); err != nil {
		t.Fatal(err)
	}
	service.CloseIdleConnections()
	if err := admin.Health(ctx); err != nil {
		t.Fatal(err)
	}
	admin.CloseIdleConnections()
	time.Sleep(time.Second)
	actual, err := admin.List(ctx, "/rest/log")
	if err != nil {
		t.Fatal(err)
	}
	foreignAuth := false
	for _, row := range actual {
		if priorIDs[text(row[".id"])] {
			continue
		}
		message := text(row["message"])
		if strings.HasPrefix(message, "user "+name+" logged ") || strings.HasPrefix(message, marker+" : user "+name+" logged ") {
			t.Error("actual successful service authentication survived native filter")
		}
		if strings.HasPrefix(message, "user admin logged ") {
			foreignAuth = true
		}
	}
	if !foreignAuth {
		t.Error("actual operator authentication disappeared")
	}
	cases := []struct {
		message string
		keep    bool
	}{
		{"user " + name + " logged in native " + marker, false},
		{"user " + name + " logged out native " + marker, false},
		{"login failure for user " + name + " native " + marker, true},
		{"user lab-operator logged in native " + marker, true},
		{"user " + name + "-other logged in native " + marker, true},
		{"unrelated info native " + marker, true},
	}
	commands := []string{}
	for _, item := range cases {
		commands = append(commands, ":log info "+strconv.Quote(item.message))
	}
	if _, err := admin.request(ctx, http.MethodPost, "/rest/execute", map[string]any{"script": strings.Join(commands, "; ")}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	logs, err := admin.List(ctx, "/rest/log")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range cases {
		count := 0
		for _, row := range logs {
			if text(row["message"]) == marker+" : "+item.message {
				count++
			}
		}
		want := 0
		if item.keep {
			want = 1
		}
		if count != want {
			t.Errorf("native reconciled keep count=%d want=%d for %q", count, want, item.message)
		}
	}
	if changed, err := service.RestoreServiceInfoLogs(ctx); err != nil || !changed {
		t.Fatalf("native restore changed=%t err=%v", changed, err)
	}
	if changed, err := service.RestoreServiceInfoLogs(ctx); err != nil || changed {
		t.Fatalf("native restore idempotency changed=%t err=%v", changed, err)
	}
	nativeManualLogPreflight(t, strings.TrimSpace(string(password)), false)
	func() {
		if _, err := admin.request(ctx, http.MethodPatch, "/rest/system/logging/"+routerOSResourceID(sourceID), map[string]any{"regex": serviceLogSourceFilter}); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := admin.request(ctx, http.MethodPatch, "/rest/system/logging/"+routerOSResourceID(sourceID), map[string]any{"regex": ""}); err != nil {
				t.Errorf("restore owned orphan fixture: %v", err)
			}
		}()
		nativeManualLogPreflight(t, strings.TrimSpace(string(password)), true)
	}()
}

func nativeLogSSHProbe(t *testing.T, username, password string) {
	t.Helper()
	if nativeLoggingSSHCommand(t, username, password, ":put [/system/identity/get name]") != "sb-gateway-lab-chr" {
		t.Fatal("unexpected authenticated CHR identity")
	}
}

func nativeManualLogPreflight(t *testing.T, password string, blocked bool) {
	t.Helper()
	for _, filename := range []string{"uninstall.rsc", "rollback.rsc"} {
		source, err := os.ReadFile("../../routeros/" + filename)
		if err != nil {
			t.Fatal(err)
		}
		_, remainder, found := strings.Cut(string(source), "# Service log preflight.")
		guard, _, ended := strings.Cut(remainder, "# End service log preflight.")
		if !found || !ended || strings.Contains(guard, "/remove") || strings.Contains(guard, "/set") {
			t.Fatal("manual logging preflight is not a bounded read-only block")
		}
		// RouterOS SSH processes command line breaks separately, unlike import.
		guard = strings.NewReplacer("\r", "", "\n", " ").Replace(guard)
		command := ":do { " + guard + "; :put \"GUARD-OPEN\" } on-error={ :put \"GUARD-BLOCKED\" }"
		want := "GUARD-OPEN"
		if blocked {
			want = "GUARD-BLOCKED"
		}
		if got := nativeLoggingSSHCommand(t, "admin", password, command); got != want {
			t.Errorf("%s native preflight=%q want=%q", filename, got, want)
		}
	}
}

func nativeLoggingSSHCommand(t *testing.T, username, password, command string) string {
	t.Helper()
	hostKey, err := knownhosts.New("/root/.sb-gateway-lab/known_hosts")
	if err != nil {
		t.Fatal("lab host key unavailable")
	}
	connection, err := ssh.Dial("tcp", "127.0.0.1:18022", &ssh.ClientConfig{User: username, Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback: hostKey, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("native authentication probe: %v", err)
	}
	defer connection.Close()
	session, err := connection.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	output, err := session.CombinedOutput(command)
	if err != nil {
		t.Fatal("native logging command failed")
	}
	return strings.TrimSpace(string(output))
}
