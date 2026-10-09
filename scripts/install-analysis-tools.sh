#!/bin/sh
set -eu

destination=${1:?analysis tool destination required}
mkdir -p "$destination"
destination=$(cd "$destination" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cd "$work"
go mod init sb-gateway-analysis-tools
# The newer importer understands the export format emitted by Go 1.27.2.
go get honnef.co/go/tools/cmd/staticcheck@v0.8.1 golang.org/x/vuln/cmd/govulncheck@v1.8.0 golang.org/x/tools@v0.51.0
go build -o "$destination/staticcheck" honnef.co/go/tools/cmd/staticcheck
go build -o "$destination/govulncheck" golang.org/x/vuln/cmd/govulncheck
