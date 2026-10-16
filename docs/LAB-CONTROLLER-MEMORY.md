# Diagnostic Controller Memory Override

Normal builds exclude this facility. Builds tagged `sb_cpu_lab` must explicitly
enable both `SB_LAB_CPU_PROFILE=1` and `SB_LAB_GATEWAY_LIMIT=1` in the appliance
role. A bounded request file at `/run/sb-gateway/lab-gateway-limit-request`
accepts only `<token>:110` or `<token>:restore`; tokens follow the CPU profile
token restrictions. Each new token is handled once.

The 110 MiB override changes only the controller Go soft limit. It requires
finite cgroup limits of at least 256/320 MiB and at least 48 MiB below
`memory.high` at admission. The first override records the previous runtime
limit; a restore request returns it. Restarting the controller also removes the
override. No cgroup limit or core budget is changed by this request.

This is an isolated lab experiment, not a production memory policy or a promise
that concurrent helper jobs fit. Keep ACME tasks inactive, monitor memory events
throughout the workload, stop on pressure or OOM, and compare the same completed
work, errors and CPU counters. Test higher `memory.high` separately from raising
the controller limit. Profiles and environment-specific results remain private.
