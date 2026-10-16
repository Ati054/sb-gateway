//go:build xray_multicall

package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	statscommand "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/protobuf/proto"
)

func TestTelemetryRPCWireMatchesPinnedStatsService(t *testing.T) {
	client := controlRPCFixture(t, func(_ context.Context, method string, body []byte) ([]byte, error) {
		if strings.HasSuffix(method, "/QueryStats") {
			var request statscommand.QueryStatsRequest
			if err := proto.Unmarshal(body, &request); err != nil {
				return nil, err
			}
			if request.Pattern != "user>>>" || request.Reset_ {
				return nil, errors.New("pinned stats request mismatch")
			}
			return proto.Marshal(&statscommand.QueryStatsResponse{Stat: []*statscommand.Stat{{Name: "user>>>alice>>>traffic>>>downlink", Value: 1<<53 + 7}}})
		}
		if strings.HasSuffix(method, "/GetAllOnlineUsers") {
			var request statscommand.GetAllOnlineUsersRequest
			if err := proto.Unmarshal(body, &request); err != nil {
				return nil, err
			}
			return proto.Marshal(&statscommand.GetAllOnlineUsersResponse{Users: []string{"alice", "user>>>reverse-vless-demo>>>online"}})
		}
		return nil, errors.New("unexpected pinned stats operation")
	})
	got := newTelemetryCollector(Options{control: client}).remoteMeasurements(context.Background())
	if got.statsErr != nil || got.onlineErr != nil || got.measurements["alice"].Downlink != 1<<53+7 || len(got.online) != 2 {
		t.Fatalf("pinned wire response mismatch: %#v", got)
	}
}
