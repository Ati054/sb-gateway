package routeros

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestServiceAccountInfoFiltersExactPartition(t *testing.T) {
	for _, username := range []string{"sb-gateway-api", "service.name@router", "x", "api_user"} {
		filters := serviceAccountInfoFilters(username)
		prefix := "user " + username + " logged "
		if len(filters) != len(prefix) {
			t.Fatalf("got %d filters for %q", len(filters), username)
		}
		compiled := make([]*regexp.Regexp, len(filters))
		for index, filter := range filters {
			var err error
			compiled[index], err = regexp.CompilePOSIX(filter)
			if err != nil {
				t.Fatalf("compile shard %d: %v", index, err)
			}
		}
		messages := []string{prefix, prefix + "in from 192.0.2.1 via rest-api", prefix + "out via api", "login failure for user " + username, "user operator logged in", "ordinary info"}
		for index := range prefix {
			messages = append(messages, prefix[:index])
			for replacement := byte(' '); replacement < 127; replacement++ {
				if replacement != prefix[index] {
					messages = append(messages, prefix[:index]+string(replacement)+prefix[index+1:]+"in")
				}
			}
		}
		for _, message := range messages {
			count := 0
			for _, filter := range compiled {
				if filter.MatchString(message) {
					count++
				}
			}
			want := 1
			if strings.HasPrefix(message, prefix) {
				want = 0
			}
			if count != want {
				t.Fatalf("%q matched %d shards, want %d", message, count, want)
			}
		}
	}
	for _, username := range []string{"", "name with spaces", "name[meta]", "line\nfeed", strings.Repeat("a", 33)} {
		if filters := serviceAccountInfoFilters(username); len(filters) != 0 {
			t.Fatalf("unsupported name %q got filters", username)
		}
	}
}

func TestRecordsAccountInfoRequiresOrdinaryExplicitInfo(t *testing.T) {
	for topics, want := range map[string]bool{
		"info": true, "info,!fetch,!wireguard": true, "system,info": true, "system,account,info": true,
		"warning": false, "error": false, "account": false, "info,!account": false,
		"system,info,!system": false, "info,!info": false, "info,script": false, "info,fetch": false,
	} {
		if got := recordsAccountInfo(topics); got != want {
			t.Fatalf("topics %q: got %t want %t", topics, got, want)
		}
	}
}

type serviceLogFixture struct {
	mu            sync.Mutex
	rules         map[string]map[string]any
	users         []map[string]any
	schedulers    []map[string]any
	ops           []string
	writes        int
	nextID        int
	failWrite     int
	failStatus    int
	failAfter     bool
	userStatus    int
	checkCoverage bool
	t             *testing.T
}

func newServiceLogFixture(t *testing.T) (*serviceLogFixture, *Client) {
	t.Helper()
	fixture := &serviceLogFixture{
		t: t, nextID: 16, checkCoverage: true,
		rules: map[string]map[string]any{
			"*1": {".id": "*1", "topics": "info,!fetch", "action": "memory", "prefix": "original", "regex": "", "comment": "operator comment", "disabled": "false"},
		},
		users: []map[string]any{{"name": "sb-gateway-api", "group": "sb-gateway-api", "comment": "SB-GATEWAY control-plane REST user"}},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "sb-gateway-api", Password: "test-only-secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return fixture, client
}

func (fixture *serviceLogFixture) serveHTTP(response http.ResponseWriter, request *http.Request) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	response.Header().Set("Content-Type", "application/json")
	fixture.ops = append(fixture.ops, request.Method+" "+request.URL.Path)
	if request.Method == http.MethodGet {
		switch request.URL.Path {
		case "/rest/user":
			if fixture.userStatus != 0 {
				http.Error(response, "denied", fixture.userStatus)
				return
			}
			_ = json.NewEncoder(response).Encode(fixture.users)
		case "/rest/system/scheduler":
			if fixture.schedulers == nil {
				_, _ = response.Write([]byte(`[]`))
			} else {
				_ = json.NewEncoder(response).Encode(fixture.schedulers)
			}
		case "/rest/system/logging":
			rows := make([]map[string]any, 0, len(fixture.rules))
			ids := make([]string, 0, len(fixture.rules))
			for id := range fixture.rules {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				rows = append(rows, fixture.rules[id])
			}
			_ = json.NewEncoder(response).Encode(rows)
		default:
			http.Error(response, "unexpected GET", http.StatusNotFound)
		}
		return
	}
	fixture.writes++
	if fixture.writes == fixture.failWrite && !fixture.failAfter {
		http.Error(response, "injected rejection", fixture.failStatus)
		return
	}
	var payload map[string]any
	if request.Body != nil && request.Method != http.MethodDelete {
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			http.Error(response, "invalid payload", http.StatusBadRequest)
			return
		}
	}
	id := strings.TrimPrefix(request.URL.Path, "/rest/system/logging/")
	switch {
	case request.Method == http.MethodPut && request.URL.Path == "/rest/system/logging":
		id = fmt.Sprintf("*%X", fixture.nextID)
		fixture.nextID++
		payload[".id"] = id
		fixture.rules[id] = payload
	case request.Method == http.MethodPatch && fixture.rules[id] != nil:
		for key, value := range payload {
			fixture.rules[id][key] = value
		}
	case request.Method == http.MethodDelete && fixture.rules[id] != nil:
		delete(fixture.rules, id)
	default:
		http.Error(response, "unexpected write", http.StatusNotFound)
		return
	}
	if fixture.checkCoverage {
		for _, message := range []string{"ordinary info", "user operator logged in", "login failure for user sb-gateway-api", "user sb-gateway-api logged"} {
			if fixture.matchesLocked(message) == 0 {
				fixture.t.Errorf("audit coverage lost after %s %s for %q", request.Method, request.URL.Path, message)
			}
		}
	}
	if fixture.writes == fixture.failWrite && fixture.failAfter {
		http.Error(response, "response lost after application", fixture.failStatus)
		return
	}
	_ = json.NewEncoder(response).Encode(map[string]any{".id": id})
}

func (fixture *serviceLogFixture) change(update func()) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	update()
}

func (fixture *serviceLogFixture) matchesLocked(message string) int {
	count := 0
	for _, rule := range fixture.rules {
		if text(rule["prefix"]) != "original" || text(rule["disabled"]) == "true" || !recordsAccountInfo(text(rule["topics"])) {
			continue
		}
		pattern := text(rule["regex"])
		if pattern == "" || regexp.MustCompilePOSIX(pattern).MatchString(message) {
			count++
		}
	}
	return count
}

func (fixture *serviceLogFixture) assertSteady(t *testing.T) {
	t.Helper()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.rules) != 27 || text(fixture.rules["*1"]["regex"]) != serviceAccountInfoFilters("sb-gateway-api")[0] {
		t.Fatalf("incomplete installed group: rules=%d source=%v", len(fixture.rules), fixture.rules["*1"])
	}
	for message, want := range map[string]int{"user sb-gateway-api logged in": 0, "user sb-gateway-api logged out": 0, "user operator logged in": 1, "user sb-gateway-api-other logged in": 1, "login failure for user sb-gateway-api": 1, "user sb-gateway-api logged": 1, "ordinary info": 1} {
		if got := fixture.matchesLocked(message); got != want {
			t.Fatalf("%q matched %d rules, want %d", message, got, want)
		}
	}
}

func TestSuppressServiceInfoLogsInstallsAndIsIdempotent(t *testing.T) {
	fixture, client := newServiceLogFixture(t)
	changed, err := client.SuppressServiceInfoLogs(context.Background())
	if err != nil || !changed {
		t.Fatalf("install: changed=%t err=%v", changed, err)
	}
	fixture.assertSteady(t)
	fixture.change(func() {
		for id, rule := range fixture.rules {
			if text(rule["action"]) != "memory" || text(rule["prefix"]) != "original" || text(rule["topics"]) != "info,!fetch" {
				t.Errorf("clone changed source routing fields: %v", rule)
			}
			if id == "*1" && text(rule["comment"]) != "operator comment" {
				t.Error("source comment changed")
			}
		}
	})
	changed, err = client.SuppressServiceInfoLogs(context.Background())
	if err != nil || changed {
		t.Fatalf("repeat: changed=%t err=%v", changed, err)
	}
	fixture.change(func() {
		if fixture.writes != 27 {
			t.Errorf("got %d writes, want 26 clones plus source", fixture.writes)
		}
	})
}

func TestSuppressServiceInfoLogsResumesUnknownWriteOutcome(t *testing.T) {
	for _, failedWrite := range []int{3, 27} {
		t.Run(fmt.Sprint(failedWrite), func(t *testing.T) {
			fixture, client := newServiceLogFixture(t)
			fixture.change(func() { fixture.failWrite, fixture.failStatus, fixture.failAfter = failedWrite, 500, true })
			if _, err := client.SuppressServiceInfoLogs(context.Background()); err == nil {
				t.Fatal("injected uncertain response was accepted")
			}
			if _, err := client.SuppressServiceInfoLogs(context.Background()); err != nil {
				t.Fatal(err)
			}
			fixture.assertSteady(t)
			fixture.change(func() {
				if fixture.writes != 27 {
					t.Errorf("uncertain response caused duplicate writes: %d", fixture.writes)
				}
			})
		})
	}
}

func TestSuppressServiceInfoLogsRejectedShardLeavesSourceUnfiltered(t *testing.T) {
	fixture, client := newServiceLogFixture(t)
	fixture.change(func() { fixture.failWrite, fixture.failStatus = 4, http.StatusBadRequest })
	if _, err := client.SuppressServiceInfoLogs(context.Background()); err == nil {
		t.Fatal("rejected native shard was accepted")
	}
	fixture.change(func() {
		if len(fixture.rules) != 1 || text(fixture.rules["*1"]["regex"]) != "" {
			t.Errorf("rejected installation did not leave original coverage: %v", fixture.rules)
		}
	})
	if _, err := client.SuppressServiceInfoLogs(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.assertSteady(t)
}

func TestSuppressServiceInfoLogsRestoresBeforeRepairingPartialGroup(t *testing.T) {
	for _, change := range []string{"missing", "disabled", "duplicate", "source-topics"} {
		t.Run(change, func(t *testing.T) {
			fixture, client := newServiceLogFixture(t)
			if _, err := client.SuppressServiceInfoLogs(context.Background()); err != nil {
				t.Fatal(err)
			}
			fixture.change(func() {
				switch change {
				case "missing":
					delete(fixture.rules, "*10")
				case "disabled":
					fixture.rules["*10"]["disabled"] = "true"
				case "duplicate":
					copy := make(map[string]any)
					for key, value := range fixture.rules["*10"] {
						copy[key] = value
					}
					copy[".id"] = "*100"
					fixture.rules["*100"] = copy
				case "source-topics":
					fixture.rules["*1"]["topics"] = "info,!fetch,!wireguard"
				}
				fixture.ops = nil
			})
			if _, err := client.SuppressServiceInfoLogs(context.Background()); err != nil {
				t.Fatal(err)
			}
			fixture.assertSteady(t)
			fixture.change(func() {
				for _, op := range fixture.ops {
					if !strings.HasPrefix(op, "GET ") {
						if op != "PATCH /rest/system/logging/*1" {
							t.Errorf("repair did not restore source first: %s", op)
						}
						break
					}
				}
			})
		})
	}
}

func TestSuppressServiceInfoLogsPreservesCustomDisabledAndAuditRules(t *testing.T) {
	fixture, client := newServiceLogFixture(t)
	protected := map[string]map[string]any{
		"*2": {".id": "*2", "topics": "info,!fetch", "action": "remote", "prefix": "custom", "regex": "^operator", "comment": "custom", "disabled": "false"},
		"*3": {".id": "*3", "topics": "info", "action": "disk", "prefix": "disabled", "regex": "", "disabled": "true"},
		"*4": {".id": "*4", "topics": "warning", "action": "memory", "prefix": "warning", "regex": "", "disabled": "false"},
		"*5": {".id": "*5", "topics": "error", "action": "memory", "prefix": "error", "regex": "", "disabled": "false"},
	}
	fixture.change(func() {
		for id, rule := range protected {
			copy := make(map[string]any)
			for key, value := range rule {
				copy[key] = value
			}
			fixture.rules[id] = copy
		}
	})
	if _, err := client.SuppressServiceInfoLogs(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.change(func() {
		for id, rule := range protected {
			if !reflect.DeepEqual(fixture.rules[id], rule) {
				t.Errorf("protected rule %s changed", id)
			}
		}
	})
}

func TestSuppressServiceInfoLogsOwnershipAndUninstallGuards(t *testing.T) {
	for _, guard := range []string{"foreign-user", "denied-user", "pending-uninstall", "too-many-sources"} {
		t.Run(guard, func(t *testing.T) {
			fixture, client := newServiceLogFixture(t)
			fixture.change(func() {
				switch guard {
				case "foreign-user":
					fixture.users[0]["comment"] = "operator account"
				case "denied-user":
					fixture.userStatus = http.StatusForbidden
				case "pending-uninstall":
					fixture.schedulers = []map[string]any{{"name": fullUninstallScheduler, "comment": "SB-GATEWAY autonomous full uninstall", "disabled": "false"}}
				case "too-many-sources":
					for index := 2; index <= 9; index++ {
						id := fmt.Sprintf("*%X", index)
						fixture.rules[id] = map[string]any{".id": id, "topics": "info,!fetch", "action": "memory", "regex": "", "disabled": "false"}
					}
				}
			})
			changed, err := client.SuppressServiceInfoLogs(context.Background())
			wantError := guard == "denied-user" || guard == "too-many-sources"
			if changed || (err != nil) != wantError {
				t.Fatalf("guard=%s changed=%t err=%v", guard, changed, err)
			}
			fixture.change(func() {
				if fixture.writes != 0 {
					t.Errorf("guard performed %d writes", fixture.writes)
				}
			})
		})
	}
}

func TestRestoreServiceInfoLogsPreservesSourceAndHandlesLostResponse(t *testing.T) {
	fixture, client := newServiceLogFixture(t)
	if _, err := client.SuppressServiceInfoLogs(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.change(func() {
		delete(fixture.rules, "*10")
		fixture.failWrite, fixture.failStatus, fixture.failAfter = fixture.writes+1, 500, true
	})
	if _, err := client.RestoreServiceInfoLogs(context.Background()); err == nil {
		t.Fatal("uncertain restore response was accepted")
	}
	fixture.change(func() {
		if len(fixture.rules) != 26 {
			t.Error("clones removed after uncertain restore response")
		}
	})
	changed, err := client.RestoreServiceInfoLogs(context.Background())
	if err != nil || !changed {
		t.Fatalf("retry restore: changed=%t err=%v", changed, err)
	}
	fixture.change(func() {
		if len(fixture.rules) != 1 || text(fixture.rules["*1"]["regex"]) != "" || text(fixture.rules["*1"]["comment"]) != "operator comment" || text(fixture.rules["*1"]["prefix"]) != "original" {
			t.Errorf("source was not preserved: %v", fixture.rules)
		}
	})
	changed, err = client.RestoreServiceInfoLogs(context.Background())
	if err != nil || changed {
		t.Fatalf("repeat restore: changed=%t err=%v", changed, err)
	}
}

func TestServiceInfoLogsOperatorChangesAreConservative(t *testing.T) {
	for _, change := range []string{"custom-regex", "disabled", "removed"} {
		t.Run(change, func(t *testing.T) {
			fixture, client := newServiceLogFixture(t)
			if _, err := client.SuppressServiceInfoLogs(context.Background()); err != nil {
				t.Fatal(err)
			}
			fixture.change(func() {
				fixture.checkCoverage = false
				switch change {
				case "custom-regex":
					fixture.rules["*1"]["regex"] = "^operator"
				case "disabled":
					fixture.rules["*1"]["disabled"] = "true"
				case "removed":
					delete(fixture.rules, "*1")
				}
			})
			_, err := client.SuppressServiceInfoLogs(context.Background())
			if err != nil {
				t.Fatalf("change=%s err=%v", change, err)
			}
			fixture.change(func() {
				switch change {
				case "custom-regex":
					if len(fixture.rules) != 1 || text(fixture.rules["*1"]["regex"]) != "^operator" {
						t.Error("operator regex changed or owned clones remain")
					}
				case "disabled":
					if len(fixture.rules) != 1 || text(fixture.rules["*1"]["disabled"]) != "true" {
						t.Error("disabled source or clones not respected")
					}
				case "removed":
					if len(fixture.rules) != 0 {
						t.Error("orphan clones not removed")
					}
				}
			})
		})
	}
}

func TestFullUninstallStopsOnAmbiguousLogCoverage(t *testing.T) {
	fixture, client := newServiceLogFixture(t)
	if _, err := client.SuppressServiceInfoLogs(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.change(func() {
		for id, rule := range fixture.rules {
			if id != "*1" {
				rule["regex"] = "^operator"
			}
		}
	})
	if _, err := client.ScheduleFullUninstall(context.Background(), "usb1/sb-gateway"); err == nil {
		t.Fatal("uninstall ignored unsafe log restoration")
	}
	fixture.change(func() {
		for _, op := range fixture.ops {
			if strings.HasPrefix(op, "PUT /rest/system/script") || strings.HasPrefix(op, "PUT /rest/system/scheduler") {
				t.Errorf("uninstall armed before log restoration: %s", op)
			}
		}
	})
}

func TestServiceInfoLogsRetiredAccountIsRestoredUnlessLookupFails(t *testing.T) {
	for _, account := range []string{"foreign", "unsupported", "denied", "ambiguous"} {
		t.Run(account, func(t *testing.T) {
			fixture, client := newServiceLogFixture(t)
			if _, err := client.SuppressServiceInfoLogs(context.Background()); err != nil {
				t.Fatal(err)
			}
			fixture.change(func() {
				switch account {
				case "foreign":
					fixture.users[0]["comment"] = "operator-owned account"
				case "unsupported":
					client.username = strings.Repeat("a", 33)
					fixture.users[0]["name"] = client.username
				case "denied":
					fixture.userStatus = http.StatusForbidden
				case "ambiguous":
					fixture.users = append(fixture.users, fixture.users[0])
				}
			})
			_, err := client.SuppressServiceInfoLogs(context.Background())
			if (err != nil) != (account != "foreign") {
				t.Fatalf("account=%s err=%v", account, err)
			}
			fixture.change(func() {
				if account == "denied" || account == "ambiguous" {
					if len(fixture.rules) != 27 || fixture.writes != 27 {
						t.Error("uncertain ownership mutated existing coverage")
					}
				} else if len(fixture.rules) != 1 || text(fixture.rules["*1"]["regex"]) != "" {
					t.Error("retired account's filter was not restored")
				}
			})
		})
	}
}

func TestRestoreServiceInfoLogsHonorsOperatorRegex(t *testing.T) {
	fixture, client := newServiceLogFixture(t)
	if _, err := client.SuppressServiceInfoLogs(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.change(func() {
		fixture.checkCoverage = false
		fixture.rules["*1"]["regex"] = "^operator"
	})
	if changed, err := client.RestoreServiceInfoLogs(context.Background()); err != nil || !changed {
		t.Fatalf("restore: changed=%t err=%v", changed, err)
	}
	fixture.change(func() {
		if len(fixture.rules) != 1 || text(fixture.rules["*1"]["regex"]) != "^operator" || text(fixture.rules["*1"]["comment"]) != "operator comment" {
			t.Error("operator-owned regex or comment was changed")
		}
	})
}

func TestRestoreServiceInfoLogsRetriesUnknownDeleteOutcome(t *testing.T) {
	fixture, client := newServiceLogFixture(t)
	if _, err := client.SuppressServiceInfoLogs(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.change(func() {
		fixture.failWrite, fixture.failStatus, fixture.failAfter = fixture.writes+2, 500, true
	})
	if _, err := client.RestoreServiceInfoLogs(context.Background()); err == nil {
		t.Fatal("unknown deletion outcome was accepted")
	}
	if _, err := client.RestoreServiceInfoLogs(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.change(func() {
		if len(fixture.rules) != 1 || text(fixture.rules["*1"]["regex"]) != "" {
			t.Error("retry failed to restore source and remove only surviving clones")
		}
	})
}

func TestServiceInfoLogsMalformedOwnershipIsNotMutated(t *testing.T) {
	fixture, client := newServiceLogFixture(t)
	fixture.change(func() {
		fixture.rules["*2"] = map[string]any{".id": "*2", "topics": "warning", "action": "memory", "comment": serviceLogCommentPrefix + "malformed", "disabled": "false"}
	})
	if _, err := client.SuppressServiceInfoLogs(context.Background()); err == nil {
		t.Fatal("malformed reserved ownership comment was accepted")
	}
	fixture.change(func() {
		if fixture.writes != 0 || len(fixture.rules) != 2 {
			t.Error("ambiguous ownership caused mutation")
		}
	})
}

func TestServiceInfoLogsMissingAllOwnershipEvidenceIsReported(t *testing.T) {
	fixture, client := newServiceLogFixture(t)
	if _, err := client.SuppressServiceInfoLogs(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.change(func() {
		for id := range fixture.rules {
			if id != "*1" {
				delete(fixture.rules, id)
			}
		}
	})
	if _, err := client.SuppressServiceInfoLogs(context.Background()); err == nil {
		t.Fatal("orphan first-shard regex silently accepted")
	}
	if _, err := client.RestoreServiceInfoLogs(context.Background()); err == nil {
		t.Fatal("unproven regex ownership silently accepted during restore")
	}
	fixture.change(func() {
		if fixture.writes != 27 || text(fixture.rules["*1"]["regex"]) != serviceLogSourceFilter {
			t.Error("unproven source was overwritten")
		}
	})
}

func TestServiceInfoLogsExceedingDesiredBoundRestoresExistingGroup(t *testing.T) {
	fixture, client := newServiceLogFixture(t)
	if _, err := client.SuppressServiceInfoLogs(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.change(func() {
		for index := 2; index <= 9; index++ {
			id := fmt.Sprintf("*%X", index)
			fixture.rules[id] = map[string]any{".id": id, "topics": "info,!fetch", "action": "memory", "regex": "", "disabled": "false"}
		}
	})
	if changed, err := client.SuppressServiceInfoLogs(context.Background()); !changed || err == nil {
		t.Fatalf("over-bound group: changed=%t err=%v", changed, err)
	}
	fixture.change(func() {
		if len(fixture.rules) != 9 || text(fixture.rules["*1"]["regex"]) != "" {
			t.Error("over-bound configuration retained a partial suppression group")
		}
	})
}

func TestServiceInfoLogsSyntacticOwnershipWithoutFingerprintIsPreserved(t *testing.T) {
	fixture, client := newServiceLogFixture(t)
	fixture.change(func() {
		fixture.rules["*2"] = map[string]any{
			".id": "*2", "topics": "info,!fetch", "action": "memory", "prefix": "foreign", "disabled": "false",
			"regex":   serviceAccountInfoFilters("sb-gateway-api")[1],
			"comment": serviceLogCommentPrefix + "*1 73622d676174657761792d617069 000000000000 1",
		}
	})
	if _, err := client.SuppressServiceInfoLogs(context.Background()); err == nil {
		t.Fatal("syntactically valid but unproven group was accepted")
	}
	if _, err := client.RestoreServiceInfoLogs(context.Background()); err == nil {
		t.Fatal("unproven clone was accepted during restore")
	}
	fixture.change(func() {
		if fixture.writes != 0 || len(fixture.rules) != 2 {
			t.Error("unproven clone was deleted or source modified")
		}
	})
}
