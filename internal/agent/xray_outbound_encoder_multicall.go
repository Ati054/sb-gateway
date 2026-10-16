//go:build xray_multicall

package agent

import (
	"encoding/json"

	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

// The packaged appliance already links this pinned compiler. Compile in the
// controller instead of starting another full engine just to call AddOutbound.
func newXrayOutboundEncoder() xrayOutboundEncoder {
	return func(outbound map[string]any) ([]byte, error) {
		body, err := json.Marshal(outbound)
		if err != nil {
			return nil, err
		}
		var config conf.OutboundDetourConfig
		if err := json.Unmarshal(body, &config); err != nil {
			return nil, err
		}
		compiled, err := config.Build()
		if err != nil {
			return nil, err
		}
		return proto.Marshal(compiled)
	}
}
