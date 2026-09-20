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
  docs/ACCEPTANCE-TESTS.md docs/research templates/xray.smoke.json; do
  if git ls-files --error-unmatch "$path" >/dev/null 2>&1 \
    || git ls-files "$path/**" | grep -q .; then
    printf '%s\n' "forbidden public path: $path" >&2
    exit 1
  fi
done

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

package_version="$(sed -nE 's/^[[:space:]]*"version":[[:space:]]*"([0-9]+\.[0-9]+\.[0-9]+)",?[[:space:]]*$/\1/p' package.json | head -n 1)"
if [ -z "$package_version" ]; then
  printf '%s\n' "package.json does not contain a stable release version" >&2
  exit 1
fi

first_release="$(tr -d '\r' <CHANGELOG.md | sed -nE 's/^## ([0-9]+\.[0-9]+\.[0-9]+)$/\1/p' | head -n 1)"
if [ "$first_release" != "$package_version" ]; then
  printf '%s\n' "public CHANGELOG must start with package version $package_version" >&2
  exit 1
fi

release_count="$(tr -d '\r' <CHANGELOG.md | grep -Ec '^## [0-9]+\.[0-9]+\.[0-9]+$')"
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
  'CABINET-PC|ATInsk999|192\.168\.99\.|192\.168\.22\.199|desktop-m6fq9t9|C:\\Users\\' \
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

if git rev-list --objects HEAD \
  | cut -d' ' -f2- \
  | grep -E '(^|/)(\.lab|\.agents|\.codex|\.openai)(/|$)' \
  >/dev/null; then
  printf '%s\n' "private project material exists in public Git history" >&2
  exit 1
fi

for revision in $(git rev-list HEAD); do
  if git grep -Il -E -- \
    '-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}' \
    "$revision" -- | grep -q .; then
    printf '%s\n' "credential signature exists in public Git history" >&2
    exit 1
  fi
done

printf '%s\n' "public source boundary verified"
