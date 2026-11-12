#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
 echo 'Usage: prepare-xray-multicall.sh PATCHED_XRAY_ROOT PATCHED_REALITY_ROOT OUTPUT_MODFILE' >&2
 exit 2
fi
xray_root="$(cd "$1" && pwd)"
reality_root="$(cd "$2" && pwd)"
output="$3"
test -f "$xray_root/main/main.go"
test -f "$reality_root/go.mod"
grep -q '^package maincmd$' "$xray_root/main/main.go"
case "$output" in *.mod) ;; *) echo 'Output must use a .mod suffix' >&2; exit 2;; esac
test "$output" != go.mod
test ! -e "$output"
sum="${output%.mod}.sum"
test ! -e "$sum"
cp go.mod "$output"
cp go.sum "$sum"
go mod edit -modfile="$output" \
 -require=github.com/xtls/xray-core@v0.0.0 \
 -require=github.com/klauspost/compress@v1.20.2 \
 -require=github.com/molecule-man/go-brrr@v1.2.0 \
 -require=golang.org/x/net@v0.62.0 \
 -require=golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2 \
 -replace="github.com/xtls/xray-core=$xray_root" \
 -replace="github.com/xtls/reality=$reality_root"
go mod tidy -modfile="$output"
