package agent

import "time"

// Outage penalties only affect voluntary switches back to a recently failed
// node. Emergency failover may still use that node after a fresh success.
type outagePenalty struct {
	LastAt float64 `json:"last_at"`
	Count  int     `json:"count"`
	Until  float64 `json:"until"`
	Open   bool    `json:"open,omitempty"`
}

func recordConfirmedOutage(now time.Time, item *policyHealthState, node string) bool {
	if node == "" || node == "block" {
		return false
	}
	ensureHealthMaps(item)
	penalty := item.OutagePenalty[node]
	if penalty.Open {
		return false
	}
	at := float64(now.Unix())
	if penalty.LastAt <= 0 || at < penalty.LastAt || at-penalty.LastAt >= 24*60*60 {
		penalty.Count = 0
	}
	penalty.Count = minInt(penalty.Count+1, 3)
	duration := time.Hour
	if penalty.Count == 2 {
		duration = 4 * time.Hour
	} else if penalty.Count >= 3 {
		duration = 12 * time.Hour
	}
	penalty.LastAt = at
	penalty.Until = at + duration.Seconds()
	penalty.Open = true
	item.OutagePenalty[node] = penalty
	item.Recoveries[node] = 0
	return true
}

func finishOutageEpisode(item *policyHealthState, node string) {
	penalty, ok := item.OutagePenalty[node]
	if !ok || !penalty.Open {
		return
	}
	penalty.Open = false
	item.OutagePenalty[node] = penalty
}

func outagePenaltyActive(now time.Time, item *policyHealthState, node string) bool {
	return item.OutagePenalty[node].Until > float64(now.Unix())
}
