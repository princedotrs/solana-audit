#!/bin/sh
# check-eval-isolation.sh: maintainer lint, never part of an audit.
#
# Fails (exit 1) when a file an audit can read names the eval folder or a
# labelled fixture variant path, which would hand the answer key to the auditor.
# Allowed to mention them: templates/evals/ itself, this script, README.md,
# ATTRIBUTION.md, and the single "maintainers only" row in SKILL.md.
#
# Usage: "<skill-root>/scripts/check-eval-isolation.sh" [<skill-root>]

set -eu
ROOT="${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
cd "$ROOT"

# 1. Links to the eval folder or the label file.
# 2. Fixture variant paths such as `4-initialization/secure` or `9-closing-accounts/insecure-still`.
PATTERN='templates/evals|labels\.json|[0-9]+-[a-z0-9-]+/(secure|insecure|recommended)([^A-Za-z]|$)'

HITS="$(grep -rnE "$PATTERN" --include='*.md' --include='*.rs' --include='*.toml' --include='*.sh' . \
  | grep -vE '^\./(templates/evals/|scripts/check-eval-isolation\.sh|README\.md|ATTRIBUTION\.md)' \
  | grep -vE '^\./SKILL\.md:[0-9]+:\| `templates/evals/` \| maintainers only' || true)"

if [ -n "$HITS" ]; then
  echo "check-eval-isolation: eval material reachable from an audit path:" >&2
  echo "$HITS" >&2
  exit 1
fi
echo "check-eval-isolation: ok"
