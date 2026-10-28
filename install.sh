#!/usr/bin/env bash
# Install the solana-program-audit skill into the user-level skills directory
# of every coding agent found on this machine.
#
#   curl -fsSL https://raw.githubusercontent.com/princedotrs/solana-audit/main/install.sh | bash
#
# Options (environment variables):
#   SKILLS_DIR=<dir>   install only into <dir> (the skill lands in <dir>/solana-program-audit)
#   REF=<branch|tag>   install from this branch or tag instead of main
set -euo pipefail

REPO="princedotrs/solana-audit"
REF="${REF:-main}"
NAME="solana-program-audit"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $REPO@$REF ..."
curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$REF" | tar -xz -C "$tmp"
src="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | head -n 1)/skills/$NAME"
[ -f "$src/SKILL.md" ] || { echo "error: SKILL.md not found in download" >&2; exit 1; }

targets=()
if [ -n "${SKILLS_DIR:-}" ]; then
  targets+=("$SKILLS_DIR")
else
  # ~/.claude and ~/.agents are always installed to; the rest only if the agent is present.
  targets+=("$HOME/.claude/skills" "$HOME/.agents/skills")
  for d in "$HOME/.codex" "$HOME/.cursor" "$HOME/.gemini" "$HOME/.config/opencode"; do
    [ -d "$d" ] && targets+=("$d/skills")
  done
fi

for dir in "${targets[@]}"; do
  mkdir -p "$dir"
  rm -rf "${dir:?}/$NAME"
  cp -R "$src" "$dir/$NAME"
  echo "Installed $NAME -> $dir/$NAME"
done

echo
echo "Done. Restart your agent, then ask it e.g.:"
echo "  Audit the Solana program in programs/<your_program>/ and write the findings to audit.md"
