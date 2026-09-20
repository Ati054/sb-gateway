package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

const subscriptionUpdateDynamicPrefix = "sb-subscription-update-"

type subscriptionXrayCommand func(context.Context, string, ...string) ([]byte, error)

func runSubscriptionXrayCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, binary, args...).CombinedOutput()
}

func selectSubscriptionXrayOutbound(ctx context.Context, options RuntimeOptions, outbound string, command subscriptionXrayCommand) error {
	outbound = strings.TrimSpace(outbound)
	if outbound == "" {
		return errors.New("subscription update outbound is empty")
	}
	previous, err := readXraySelector(ctx, options, "subscription-update-egress", command)
	if err != nil {
		return err
	}
	runtimeTag := outbound
	poolBody, readErr := os.ReadFile(options.XrayHealthPool)
	if readErr != nil {
		return errors.New("Xray health-pool contract is unavailable")
	}
	var pool struct {
		Outbounds map[string]json.RawMessage `json:"outbounds"`
	}
	if json.Unmarshal(poolBody, &pool) != nil {
		return errors.New("Xray health-pool contract is invalid")
	}
	if raw := pool.Outbounds[outbound]; len(raw) != 0 {
		runtimeTag = runtimeconfig.DynamicOutboundTag(subscriptionUpdateDynamicPrefix, outbound, raw)
		if previous == runtimeTag {
			// The deterministic handler is already live and selected. Re-adding
			// it is rejected by Xray and would make a normal repeated refresh
			// fail even though the requested egress is ready.
			return nil
		}
		if err := addSubscriptionXrayOutbound(ctx, options, runtimeTag, raw, command); err != nil {
			return err
		}
	}
	if previous == runtimeTag {
		return nil
	}
	output, err := command(ctx, options.XrayBinary, "api", "bo", "--server="+options.XrayAPIServer, "-b", "subscription-update-egress", runtimeTag)
	if err != nil {
		return fmt.Errorf("Xray rejected subscription update selector: %w: %s", err, strings.TrimSpace(string(output)))
	}
	actual, err := readXraySelector(ctx, options, "subscription-update-egress", command)
	if err != nil {
		return err
	}
	if actual != runtimeTag {
		return fmt.Errorf("Xray subscription update selector remained on %q", actual)
	}
	if previous != "" && previous != runtimeTag && strings.HasPrefix(previous, subscriptionUpdateDynamicPrefix) {
		_, _ = command(ctx, options.XrayBinary, "api", "rmo", "--server="+options.XrayAPIServer, previous)
	}
	return nil
}

func addSubscriptionXrayOutbound(ctx context.Context, options RuntimeOptions, tag string, raw json.RawMessage, command subscriptionXrayCommand) error {
	var outbound map[string]any
	if json.Unmarshal(raw, &outbound) != nil {
		return errors.New("subscription update outbound is invalid")
	}
	outbound["tag"] = tag
	body, err := json.Marshal(map[string]any{"outbounds": []any{outbound}})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp("", "sb-subscription-update-*.json")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(body, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	output, err := command(ctx, options.XrayBinary, "api", "ado", "--server="+options.XrayAPIServer, path)
	if err != nil && !strings.Contains(strings.ToLower(string(output)), "already") {
		return fmt.Errorf("Xray rejected subscription update outbound: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func readXraySelector(ctx context.Context, options RuntimeOptions, selector string, command subscriptionXrayCommand) (string, error) {
	output, err := command(ctx, options.XrayBinary, "api", "bi", "--server="+options.XrayAPIServer, selector)
	if err != nil {
		return "", errors.New("Xray subscription update selector is unavailable")
	}
	section := false
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "Selecting Override:") {
			section = true
			continue
		}
		if section && strings.HasPrefix(trimmed, "- Selects:") {
			break
		}
		if !section || trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			return fields[len(fields)-1], nil
		}
	}
	return "", nil
}
