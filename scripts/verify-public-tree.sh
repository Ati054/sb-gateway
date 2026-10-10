#!/bin/sh
set -eu

root="${1:-$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)}"
cd "$root"

if [ "$(git rev-parse --is-inside-work-tree 2>/dev/null || true)" != "true" ]; then
  printf '%s\n' "public source verification requires a Git work tree" >&2
  exit 1
fi

for path in \
  .agents .codex .lab .openai AGENTS.md CODEX_HANDOFF.md \
  IMPLEMENTATION_REPORT.md QUATTRO_SERVERS_AUDIT.md \
  docs/ACCEPTANCE-TESTS.md docs/RC3-CHR-VERIFICATION.md \
  docs/RC4-CHR-VERIFICATION.md docs/research templates/xray.smoke.json \
  docs/LARGE-POOL-VERIFICATION.md docs/URLTEST-CLEANUP-VERIFICATION.md \
  docs/URLTEST-LATENCY-VERIFICATION.md docs/URLTEST-SIMPLIFICATION-VERIFICATION.md \
  docs/URLTEST-LOAD-RESEARCH.md docs/URLTEST-TRAFFIC-ACCOUNTING.md \
  docs/GEOIP-BINARY-EXPERIMENT.md docs/XRAY-PAYLOAD-SNAPSHOT.md \
  tools/geoipbench/run-chr.sh internal/appliance/image_artifact_test.go \
  internal/routeros/image_transfer_chr_test.go internal/routeros/logging_native_test.go; do
  if git ls-files --error-unmatch "$path" >/dev/null 2>&1 \
    || git ls-files "$path/**" | grep -q .; then
    printf '%s\n' "forbidden public path: $path" >&2
    exit 1
  fi
done

if git ls-files docs | grep -E '(-VERIFICATION|-RESEARCH)\.md$' >/dev/null; then
  printf '%s\n' "internal report entered the public tree" >&2
  exit 1
fi

if ! git ls-files | grep -E '(^|/)[^/]+_test\.go$' >/dev/null \
  || ! git ls-files | grep -E '^tests/[^/]+\.test\.mjs$' >/dev/null; then
  printf '%s\n' "public regression tests are missing" >&2
  exit 1
fi

for path in \
  tests/lab-stress-harness.test.mjs \
  tests/password-persistence.test.mjs \
  tests/ruleset-domain-audit.test.mjs; do
  if git ls-files --error-unmatch "$path" >/dev/null 2>&1; then
    printf '%s\n' "private-lab test entered the public tree: $path" >&2
    exit 1
  fi
done

package_version="$(sed -nE 's/^[[:space:]]*"version":[[:space:]]*"([0-9]+\.[0-9]+\.[0-9]+(-rc\.[1-9][0-9]*)?)",?[[:space:]]*$/\1/p' package.json | head -n 1)"
if [ -z "$package_version" ]; then
  printf '%s\n' "package.json must contain a stable or numbered RC version" >&2
  exit 1
fi

first_release="$(tr -d '\r' <CHANGELOG.md | sed -nE 's/^## ([0-9]+\.[0-9]+\.[0-9]+(-rc\.[1-9][0-9]*)?)$/\1/p' | head -n 1)"
if [ "$first_release" != "$package_version" ]; then
  printf '%s\n' "public CHANGELOG must start with package version $package_version" >&2
  exit 1
fi

release_count="$(tr -d '\r' <CHANGELOG.md | grep -Ec '^## [0-9]+\.[0-9]+\.[0-9]+(-rc\.[1-9][0-9]*)?$')"
if [ "$release_count" -ne 1 ]; then
  printf '%s\n' "first public source must contain exactly one CHANGELOG release" >&2
  exit 1
fi

release_files="$(find docs/releases -maxdepth 1 -type f -name '*.md' -printf '%f\n' | sort)"
expected_release_files="$package_version.md"
if [ "$release_files" != "$expected_release_files" ]; then
  printf '%s\n' "first public source must contain only the current release document" >&2
  exit 1
fi

if git grep -In -- '1.6.15' -- README.md README-RU.md PRODUCT.md CHANGELOG.md docs 2>/dev/null | grep -q .; then
  printf '%s\n' "superseded pre-public release reference detected in public documentation" >&2
  exit 1
fi

if git grep -InE -- \
  'обход.{0,24}блокиров|разблокиров.{0,24}сайт|censorship.{0,24}(bypass|circumvention)|bypass.{0,24}(block|censor)|unblock.{0,24}(site|web)' \
  -- README.md README-RU.md PRODUCT.md CHANGELOG.md docs '*.md' 2>/dev/null | grep -q .; then
  printf '%s\n' "prohibited public positioning detected in release documentation" >&2
  exit 1
fi

if git grep -InE -- \
  'C:\\Users\\|codex-clipboard|send_user_message_question_reply|sb-gateway-lab-(chr|client)' \
  -- . ':(exclude)scripts/verify-public-tree.sh' 2>/dev/null | grep -q .; then
  printf '%s\n' "private lab identity or topology detected in public source" >&2
  exit 1
fi

if git grep -Il -E -- \
  '-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}' \
  | grep -q .; then
  printf '%s\n' "credential signature detected in public source" >&2
  exit 1
fi

if git rev-list --objects --all \
  | cut -d' ' -f2- \
  | grep -E '(^|/)(\.lab|\.agents|\.codex|\.openai)(/|$)|^docs/(research/|.*(-VERIFICATION|-RESEARCH)\.md$|GEOIP-BINARY-EXPERIMENT\.md$|URLTEST-TRAFFIC-ACCOUNTING\.md$|XRAY-PAYLOAD-SNAPSHOT\.md$)|^internal/(appliance/image_artifact_test|routeros/(image_transfer_chr_test|logging_native_test))\.go$' \
  >/dev/null; then
  printf '%s\n' "private project material exists in public Git history" >&2
  exit 1
fi

for revision in $(git rev-list --all); do
  if git grep -Il -E -- \
    'внутренних отч[её]тах при[её]мки|фактическая при[её]мка|Windows / Node [0-9]' \
    "$revision" -- docs | grep -q .; then
    printf '%s\n' "private acceptance report exists in public documentation history" >&2
    exit 1
  fi
  if git grep -Il -E -- \
    '-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}' \
    "$revision" -- | grep -q .; then
    printf '%s\n' "credential signature exists in public Git history" >&2
    exit 1
  fi
done

printf '%s\n' "public source boundary verified"
