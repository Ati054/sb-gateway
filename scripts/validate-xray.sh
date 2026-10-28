#!/bin/sh
# Startup validation is silent on success: the running core reports warnings.
# Keep complete diagnostics and the original status when validation fails.
set -eu
umask 077
output="$(mktemp "${TMPDIR:-/tmp}/sb-xray-validation.XXXXXX")"
trap 'rm -f "$output"' 0
status=0
xray run -test -config "$1" >"$output" 2>&1 || status=$?
if [ "$status" -ne 0 ]; then
  cat "$output" >&2
fi
exit "$status"
