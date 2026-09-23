package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

const subscriptionUpdateDynamicPrefix = "sb-subscription-update-"

const subscriptionUpdateRetirementState = "subscription-update-retired"

var subscriptionUpdateDynamicTag = regexp.MustCompile(`^sb-subscription-update-[a-f0-9]{12}$`)

type subscriptionOutboundRetirement struct {
	repository *stateRepository
	pid        string
	tags       []string
	pending    []string
}

type subscriptionXrayCommand func(context.Context, string, ...string) ([]byte, error)

func runSubscriptionXrayCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, binary, args...).CombinedOutput()
}

func selectSubscriptionXrayOutbound(ctx context.Context, options RuntimeOptions, outbound string, command subscriptionXrayCommand, repository *stateRepository) error {
	outbound = strings.TrimSpace(outbound)
	if outbound == "" {
		return errors.New("subscription update outbound is empty")
	}
	previous, err := readXraySelector(ctx, options, "subscription-update-egress", command)
	if err != nil {
		return err
	}
	retirement, err := loadSubscriptionOutboundRetirement(options, repository)
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
			retirement.cleanup(ctx, options, runtimeTag, command)
			return nil
		}
		if repository != nil {
			// ado can succeed even when its response is lost. Record the new
			// handler before creating it so an unselected candidate is reclaimed.
			if err := retirement.rememberPending(runtimeTag); err != nil {
				return err
			}
		}
		if err := addSubscriptionXrayOutbound(ctx, options, runtimeTag, raw, command); err != nil {
			return err
		}
	}
	if previous == runtimeTag {
		retirement.cleanup(ctx, options, runtimeTag, command)
		return nil
	}
	if previous != "" && subscriptionUpdateDynamicTag.MatchString(previous) && repository != nil {
		// Persist ownership before changing the selector. A lost API response or
		// process crash must not turn the old handler into an untracked orphan.
		if err := retirement.remember(previous); err != nil {
			return err
		}
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
		if repository == nil {
			// Stateless callers are limited to tests and retain the old behavior.
			_, _ = command(ctx, options.XrayBinary, "api", "rmo", "--server="+options.XrayAPIServer, previous)
		}
	}
	retirement.cleanup(ctx, options, runtimeTag, command)
	return nil
}

func loadSubscriptionOutboundRetirement(options RuntimeOptions, repository *stateRepository) (*subscriptionOutboundRetirement, error) {
	state := &subscriptionOutboundRetirement{repository: repository}
	if repository == nil {
		return state, nil
	}
	marker, err := os.ReadFile(options.XrayReadyFile)
	if err == nil {
		if pid, parseErr := strconv.Atoi(strings.TrimSpace(string(marker))); parseErr == nil && pid > 0 {
			state.pid = strconv.Itoa(pid)
		}
	}
	stored, err := repository.auxiliary(subscriptionUpdateRetirementState)
	if err != nil {
		return nil, err
	}
	if savedPID, _ := stored["xray_pid"].(string); savedPID != "" && state.pid != "" && savedPID != state.pid {
		return state, nil // Xray restart cleared all dynamic handlers.
	}
	for _, value := range collectionArray(stored["tags"]) {
		if tag, ok := value.(string); ok && subscriptionUpdateDynamicTag.MatchString(tag) && !slices.Contains(state.tags, tag) {
			state.tags = append(state.tags, tag)
		}
	}
	for _, value := range collectionArray(stored["pending"]) {
		if tag, ok := value.(string); ok && subscriptionUpdateDynamicTag.MatchString(tag) && !slices.Contains(state.pending, tag) {
			state.pending = append(state.pending, tag)
		}
	}
	return state, nil
}

func (state *subscriptionOutboundRetirement) save() error {
	if state.repository == nil {
		return nil
	}
	tags := make([]any, len(state.tags))
	for index, tag := range state.tags {
		tags[index] = tag
	}
	pending := make([]any, len(state.pending))
	for index, tag := range state.pending {
		pending[index] = tag
	}
	return state.repository.saveAuxiliary(subscriptionUpdateRetirementState, map[string]any{
		"xray_pid": state.pid, "tags": tags, "pending": pending,
	})
}

func (state *subscriptionOutboundRetirement) remember(tag string) error {
	if !slices.Contains(state.tags, tag) {
		state.tags = append(state.tags, tag)
	}
	return state.save()
}

func (state *subscriptionOutboundRetirement) rememberPending(tag string) error {
	if !slices.Contains(state.pending, tag) {
		state.pending = append(state.pending, tag)
	}
	return state.save()
}

func (state *subscriptionOutboundRetirement) cleanup(ctx context.Context, options RuntimeOptions, selected string, command subscriptionXrayCommand) {
	if state.repository == nil {
		return
	}
	unconfirmed := state.pending[:0]
	for _, tag := range state.pending {
		if tag == selected {
			continue
		}
		output, err := command(ctx, options.XrayBinary, "api", "rmo", "--server="+options.XrayAPIServer, tag)
		if err != nil && !subscriptionOutboundAlreadyAbsent(output) {
			log.Printf("subscription update unselected outbound cleanup deferred: %v", err)
			unconfirmed = append(unconfirmed, tag)
		}
	}
	state.pending = unconfirmed
	retained := state.tags[:0]
	for _, tag := range state.tags {
		if tag != selected {
			retained = append(retained, tag)
		}
	}
	state.tags = retained
	// One previous generation remains available to connections opened before
	// the switch. Older generations are removed, oldest first.
	for len(state.tags) > 1 {
		tag := state.tags[0]
		output, err := command(ctx, options.XrayBinary, "api", "rmo", "--server="+options.XrayAPIServer, tag)
		if err != nil && !subscriptionOutboundAlreadyAbsent(output) {
			log.Printf("subscription update outbound cleanup deferred: %v", err)
			break
		}
		state.tags = state.tags[1:]
	}
	if err := state.save(); err != nil {
		log.Printf("subscription update outbound cleanup state deferred: %v", err)
	}
}

func subscriptionOutboundAlreadyAbsent(output []byte) bool {
	message := strings.ToLower(string(output))
	return strings.Contains(message, "not found") || strings.Contains(message, "non existing")
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
