package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
)

type hotRuntimeGeneration struct {
	PoolSHA256        string `json:"pool_sha256"`
	PoolMTimeUnixNano int64  `json:"pool_mtime_unix_nano"`
	XrayPID           int    `json:"xray_pid"`
}

type hotRuntimeAcknowledgement struct {
	hotRuntimeGeneration
	PolicySelections map[string]string `json:"policy_selections"`
}

type hotRuntimeGenerationSource interface {
	hotRuntimeGeneration() hotRuntimeGeneration
}

func (runtime *xraySelectorRuntime) hotRuntimeGeneration() hotRuntimeGeneration {
	return hotRuntimeGeneration{runtime.poolSignature, runtime.poolMTimeUnixNano, runtime.xrayPID}
}

func (runtime *responsiveSelectorRuntime) hotRuntimeGeneration() hotRuntimeGeneration {
	if source, ok := runtime.selectorRuntime.(hotRuntimeGenerationSource); ok {
		return source.hotRuntimeGeneration()
	}
	return hotRuntimeGeneration{}
}

func (controller *healthController) hotRuntimeReconciled() bool {
	if controller.yielded || len(controller.transitions) > 0 {
		return false
	}
	for id, contract := range controller.processedPool.HealthPolicies {
		candidates := uniqueCandidates(contract.Candidates)
		if len(candidates) == 0 {
			continue
		}
		item := controller.state[id]
		if item == nil || !controller.warmStarted[id] || !item.RuntimeConfirmed ||
			item.Selected != item.RuntimeSelected || item.Mode != contract.Mode ||
			item.CandidateSignature != strings.Join(candidates, "\n") ||
			(item.Selected != "block" && !contains(candidates, item.Selected)) {
			return false
		}
	}
	return true
}

func (controller *healthController) publishHotRuntimeReady() error {
	if !controller.hotRuntimeReconciled() {
		return nil
	}
	selections := make(map[string]string, len(controller.processedPool.HealthPolicies))
	for id := range controller.processedPool.HealthPolicies {
		if item := controller.state[id]; item != nil {
			selections[id] = item.RuntimeSelected
		}
	}
	return publishHotRuntimeReady(controller.opts, hotRuntimeAcknowledgement{controller.processedGeneration, selections})
}

// The acknowledgement names the generation consumed by Tick, never whatever
// happens to be on disk afterwards. An interrupted or partially applied Tick
// cannot acknowledge a newer Apply or a rollback publication.
func publishHotRuntimeReady(opts Options, processed hotRuntimeAcknowledgement) error {
	return publishHotRuntimeReadyAt(opts, processed, "/proc")
}

func publishHotRuntimeReadyAt(opts Options, processed hotRuntimeAcknowledgement, procRoot string) error {
	if processed.PoolSHA256 == "" || processed.PoolMTimeUnixNano == 0 || processed.XrayPID <= 0 {
		return nil
	}
	file, err := os.Open(opts.HealthPoolFile)
	if err != nil {
		return err
	}
	info, statErr := file.Stat()
	digest := sha256.New()
	_, copyErr := io.Copy(digest, io.LimitReader(file, (32<<20)+1))
	closeErr := file.Close()
	if err := errors.Join(statErr, copyErr, closeErr); err != nil {
		return err
	}
	if processed.PoolSHA256 != hex.EncodeToString(digest.Sum(nil)) ||
		processed.PoolMTimeUnixNano != info.ModTime().UnixNano() ||
		processed.XrayPID != readyProcessPIDAt(procRoot, opts.XrayReadyFile, "xray") {
		return nil
	}
	return writeJSONAtomic(opts.HotRuntimeReadyFile, processed)
}
