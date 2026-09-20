package runtimeconfig

// XraySourceArtifacts is the short-lived normalized source graph plus the
// conversion-only settings that must not be duplicated inside that graph.
type XraySourceArtifacts struct {
	Model   map[string]any
	Options XrayCandidateOptions
}

// BuildXraySourceModel assembles the complete current-schema Xray source in
// Go. The caller supplies only the already-selected runtime nodes and bounded
// local resolvers; no migration, network request, or Python bridge is used.
func BuildXraySourceModel(
	config map[string]any,
	nodes []map[string]any,
	readSecret SecretReader,
	secretPath SecretPathResolver,
	ruleSetRoot string,
) (XraySourceArtifacts, error) {
	nodes, err := augmentRuntimeNodes(config, nodes)
	if err != nil {
		return XraySourceArtifacts{}, err
	}
	outbounds, err := BuildXrayOutboundSource(config, nodes, readSecret)
	if err != nil {
		return XraySourceArtifacts{}, err
	}
	inbound, err := BuildXrayInboundSource(config, readSecret, secretPath)
	if err != nil {
		return XraySourceArtifacts{}, err
	}
	route, err := BuildXrayRouteSource(config, nodes, outbounds)
	if err != nil {
		return XraySourceArtifacts{}, err
	}
	inbound.Options.RuleSetRoot = ruleSetRoot
	return XraySourceArtifacts{
		Model: map[string]any{
			"inbounds": inbound.Inbounds, "outbounds": outbounds, "route": route,
		},
		Options: inbound.Options,
	}, nil
}

// BuildXrayCandidateFromSchema is the production entry point for a complete
// Xray candidate and its policy-DNS sidecar from the current control-plane
// schema.
func BuildXrayCandidateFromSchema(
	config map[string]any,
	nodes []map[string]any,
	readSecret SecretReader,
	secretPath SecretPathResolver,
	ruleSetRoot string,
) (XrayCandidateArtifacts, error) {
	source, err := BuildXraySourceModel(config, nodes, readSecret, secretPath, ruleSetRoot)
	if err != nil {
		return XrayCandidateArtifacts{}, err
	}
	return RenderXrayCandidate(config, source.Model, source.Options)
}
