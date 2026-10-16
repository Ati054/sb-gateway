package agent

import (
	"context"
	"strings"
)

func (client *xrayControlClient) remoteMeasurements(ctx context.Context) remoteMeasurementResult {
	type trafficResult struct {
		values map[string]counterPair
		err    error
	}
	type onlineResult struct {
		values map[string]struct{}
		err    error
	}
	traffic, online := make(chan trafficResult, 1), make(chan onlineResult, 1)
	go func() { values, err := client.traffic(ctx); traffic <- trafficResult{values, err} }()
	go func() { values, err := client.onlineUsers(ctx); online <- onlineResult{values, err} }()
	t, o := <-traffic, <-online
	return remoteMeasurementResult{measurements: t.values, online: o.values, statsErr: t.err, onlineErr: o.err}
}

func (client *xrayControlClient) traffic(ctx context.Context) (map[string]counterPair, error) {
	request, response := client.message("QueryStatsRequest"), client.message("QueryStatsResponse")
	setControlString(request, "pattern", "user>>>")
	// Reset is absent from the read-only projection, so counters are retained.
	if err := client.invoke(ctx, "statsquery", "stats", "StatsService/QueryStats", request, response); err != nil {
		return nil, err
	}
	list := response.Get(response.Descriptor().Fields().ByName("stat")).List()
	result := make(map[string]counterPair)
	for i := 0; i < list.Len(); i++ {
		stat := list.Get(i).Message()
		name := stat.Get(stat.Descriptor().Fields().ByName("name")).String()
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
			continue
		}
		amount := max(int64(0), stat.Get(stat.Descriptor().Fields().ByName("value")).Int())
		pair := result[parts[1]]
		if parts[3] == "uplink" {
			pair.Uplink = amount
		} else if parts[3] == "downlink" {
			pair.Downlink = amount
		}
		result[parts[1]] = pair
	}
	return result, nil
}

func (client *xrayControlClient) onlineUsers(ctx context.Context) (map[string]struct{}, error) {
	request, response := client.message("GetAllOnlineUsersRequest"), client.message("GetAllOnlineUsersResponse")
	if err := client.invoke(ctx, "statsgetallonlineusers", "stats", "StatsService/GetAllOnlineUsers", request, response); err != nil {
		return nil, err
	}
	list := response.Get(response.Descriptor().Fields().ByName("users")).List()
	result := make(map[string]struct{}, list.Len())
	for i := 0; i < list.Len(); i++ {
		if name := list.Get(i).String(); name != "" {
			result[name] = struct{}{}
		}
	}
	normalizeOnlineUsers(result)
	return result, nil
}
