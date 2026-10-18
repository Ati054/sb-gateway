package watchdog

import "context"

// /proc socket tables are live traversals, not atomic snapshots. Confirm a
// missing port independently before treating it as a closed listener.
func verifyMissingListener(ctx context.Context, protocol string, port int, ports map[int]struct{}, probe func(context.Context, string, int) (bool, error)) (bool, error) {
	if _, ok := ports[port]; ok {
		return true, nil
	}
	present, err := probe(ctx, protocol, port)
	if err == nil && present && ports != nil {
		ports[port] = struct{}{}
	}
	return present, err
}
