# Typed Health Configuration Boundary

Updated 2026-10-06. These are source changes, not an installed CHR image claim.

## Scope

The control-plane draft remains a JSON-shaped map. This preserves incomplete
drafts, validation paths and legacy unknown fields without making them active.
A full conversion of every configuration consumer is not claimed.

The health-controller policy now has one shared definition in
`internal/healthcontract`. The renderer publishes `healthcontract.Policy` and
the agent reads the same type, rather than independently matching string keys.
Routing monitor inputs are projected into a typed `RoutingMonitor` before
assigning the controller's cadence and probe budget. Budget defaults and
maximum also come from the shared contract: ten and 64.

The typed runtime projection contains only the controller's supported fields.
Route-editor metadata, unknown draft properties and retired speed controls are
not forwarded to the agent. Rendering does not modify the original draft.
An omitted or blank optional tolerance retains the 50 ms default; explicit
zero remains zero. Blank optional monitor inputs are treated as omitted,
consistent with existing control-plane validation.

Malformed known numeric, array or service-access fields cause a health-pool
compilation error, instead of becoming silently missing/default values.
Port-reservation helpers retain a bounded fallback for malformed drafts;
complete candidate compilation still rejects the malformed health contract.
This does not add network probes or a per-packet conversion: projection
happens during configuration generation.

## Remaining Risks

Other dynamic readers in routing, ingress, WireGuard, DNS and control-plane
configuration still require scoped typed projections or contract tests.
The existence of `map[string]any` alone is not a defect. The remaining risk
is silent interpretation after validation, or validator/renderer schema drift.
No large source file was split and no broad schema migration was performed.
