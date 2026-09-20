package runtimeconfig

import "errors"

type NativeArtifactOptions struct {
	RuleSetRoot string
	Nginx       NginxRenderOptions
}

// BuildNativeRuntimeArtifacts renders every container-local artifact. The
// RouterOS script is intentionally a separate stage because it is applied over
// the RouterOS API rather than published into the container runtime directory.
func BuildNativeRuntimeArtifacts(
	config map[string]any,
	nodes []map[string]any,
	readSecret SecretReader,
	secretPath SecretPathResolver,
	options NativeArtifactOptions,
) (map[string][]byte, error) {
	if readSecret == nil || secretPath == nil {
		return nil, errors.New("native runtime artifacts require secret and path resolvers")
	}
	secretValues := make(map[string]string)
	uncachedRead := readSecret
	readSecret = func(reference string) (string, error) {
		if value, exists := secretValues[reference]; exists {
			return value, nil
		}
		value, err := uncachedRead(reference)
		if err != nil {
			return "", err
		}
		secretValues[reference] = value
		return value, nil
	}
	xray, err := BuildXrayCandidateFromSchema(config, nodes, readSecret, secretPath, options.RuleSetRoot)
	if err != nil {
		return nil, err
	}
	healthPool, err := BuildXrayHealthPool(config, nodes, xray.Config)
	if err != nil {
		return nil, err
	}
	if err := PruneDynamicXrayOutbounds(xray.Config, healthPool); err != nil {
		return nil, err
	}
	xrayBody, err := MarshalXrayCandidate(xray.Config)
	if err != nil {
		return nil, err
	}
	nginx, err := RenderNginxCandidate(config, readSecret, secretPath, options.Nginx)
	if err != nil {
		return nil, err
	}
	watchdog, err := RenderWatchdogEnvironment(config)
	if err != nil {
		return nil, err
	}
	telemetry, err := RenderClientTelemetryNFT(config)
	if err != nil {
		return nil, err
	}
	exclusions, err := RenderTransparentExclusions(config)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		"xray.json":                  xrayBody,
		"urltest-pool.json":          healthPool,
		"policy-dns.json":            xray.PolicyDNSBody,
		"nginx.conf":                 []byte(nginx),
		"watchdog.env":               watchdog,
		"client-telemetry.nft":       telemetry,
		"transparent-exclusions.txt": exclusions,
	}, nil
}
