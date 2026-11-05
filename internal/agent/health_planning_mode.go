package agent

import "fmt"

// URLTestPlanningMode selects an ordinary best-mode measurement. Startup,
// availability, priority and emergency probes keep their independent contract.
type URLTestPlanningMode string

const (
	URLTestPlanningLegacy      URLTestPlanningMode = "legacy"
	URLTestPlanningWarmPaired  URLTestPlanningMode = "warm-paired"
	URLTestPlanningFreshPaired URLTestPlanningMode = "fresh-paired"
)

func (opts Options) validatePlanningMode() error {
	switch opts.URLTestPlanningMode {
	case "", URLTestPlanningLegacy, URLTestPlanningWarmPaired, URLTestPlanningFreshPaired:
		return nil
	default:
		return fmt.Errorf("invalid SB_URLTEST_PLANNING_MODE %q: expected legacy, warm-paired or fresh-paired", opts.URLTestPlanningMode)
	}
}

func (opts Options) planningMode() URLTestPlanningMode {
	if opts.URLTestPlanningMode != "" {
		return opts.URLTestPlanningMode
	}
	if opts.URLTestWarmCompare {
		return URLTestPlanningWarmPaired
	}
	return URLTestPlanningLegacy
}

func (opts Options) planningMeasurement() qualityMeasurement {
	switch opts.planningMode() {
	case URLTestPlanningFreshPaired:
		return qualityMeasurementFreshPaired
	case URLTestPlanningWarmPaired:
		return qualityMeasurementWarm
	}
	return qualityMeasurementCold
}
