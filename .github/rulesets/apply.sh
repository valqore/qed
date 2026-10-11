#!/usr/bin/env bash
# Install the repository's own controls: the rulesets in this directory plus the
# settings that cannot be expressed as one.
#
# Prints a plan and changes nothing unless given `--apply`. Idempotent: a
# ruleset whose name already exists is updated in place rather than duplicated,
# because two rulesets called `main` both apply and neither is the one you
# edited.
#
# Rulesets need a public repository or a paid plan. While `valqore/qed` is
# private on a free plan every ruleset call answers 403, which is the whole
# reason this is a script: it runs in the minute after the repository becomes
# public, not whenever somebody next opens the settings page.
#
#   .github/rulesets/apply.sh                 # what it would do
#   .github/rulesets/apply.sh --apply         # do it
#   QED_HOMEPAGE=https://qed.valqore.io .github/rulesets/apply.sh --apply
set -euo pipefail

REPO="${QED_REPO:-valqore/qed}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

command -v gh >/dev/null || { echo "gh is not installed" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh is not authenticated" >&2; exit 1; }

say() { printf '%s\n' "$*"; }

# One refusal must not abandon the rest. Publication day is the wrong time to
# discover that a 403 on the first security endpoint meant the rulesets were
# never installed, so a failure is reported by name and counted, and the
# script exits non-zero at the end with the count.
FAILED=0
run() {
  if (( ! APPLY )); then
    say "    would run: $*"
    return 0
  fi
  local out
  if out="$("$@" 2>&1)"; then
    say "    ok"
  else
    FAILED=$(( FAILED + 1 ))
    say "    !! FAILED: $*"
    printf '       %s
' "$(printf '%s' "$out" | head -3)"
  fi
}

say "repository: $REPO"
visibility="$(gh api "repos/$REPO" --jq .visibility)"
say "visibility: $visibility"
if [[ "$visibility" == "private" ]]; then
  say ""
  say "  NOTE  rulesets are refused on a private repository on this plan. The"
  say "        settings below will apply; the rulesets will return 403 and the"
  say "        branch stays unprotected. Run this again after going public."
fi
say ""

# --------------------------------------------------------------------------
# Settings. Each one is here because a document in the repository claims it.
# --------------------------------------------------------------------------
say "settings"
say "  squash-only merges, delete the branch after, no wiki, no projects,"
say "  Discussions on (GOVERNANCE.md promises a weekly changelog post there)"
run gh api -X PATCH "repos/$REPO" \
  -F allow_squash_merge=true \
  -F allow_merge_commit=false \
  -F allow_rebase_merge=false \
  -F delete_branch_on_merge=true \
  -F has_wiki=false \
  -F has_projects=false \
  -F has_discussions=true \
  -F allow_auto_merge=false \
  -F web_commit_signoff_required=true

if [[ -n "${QED_HOMEPAGE:-}" ]]; then
  say "  homepage: $QED_HOMEPAGE"
  run gh api -X PATCH "repos/$REPO" -f "homepage=$QED_HOMEPAGE"
else
  say "  homepage: unset, and left alone. Set QED_HOMEPAGE once the docs site"
  say "            has its final URL (SPEC 24.1 names the subdomain decision)."
fi

say ""
say "security"
say "  private vulnerability reporting -- SECURITY.md tells a reporter to use"
say "  the 'Report a vulnerability' button, which does not exist until this is on"
run gh api -X PUT "repos/$REPO/private-vulnerability-reporting"
say "  Dependabot alerts and the automatic security-fix PRs"
run gh api -X PUT "repos/$REPO/vulnerability-alerts"
run gh api -X PUT "repos/$REPO/automated-security-fixes"
say "  secret scanning with push protection (public repositories, free)"
run gh api -X PATCH "repos/$REPO" \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'

# --------------------------------------------------------------------------
# Rulesets.
# --------------------------------------------------------------------------
say ""
say "rulesets"
existing="$(gh api "repos/$REPO/rulesets" 2>/dev/null || echo '[]')"
for file in "$HERE"/*.json; do
  name="$(python -c "import json,sys;print(json.load(open(sys.argv[1]))['name'])" "$file")"
  id="$(printf '%s' "$existing" | python -c "
import json,sys
name = sys.argv[1]
try:
    rulesets = json.load(sys.stdin)
except ValueError:
    rulesets = []
print(next((str(r['id']) for r in rulesets if r.get('name') == name), ''))
" "$name")"
  if [[ -n "$id" ]]; then
    say "  update '$name' (id $id) from $(basename "$file")"
    run gh api -X PUT "repos/$REPO/rulesets/$id" --input "$file"
  else
    say "  create '$name' from $(basename "$file")"
    run gh api -X POST "repos/$REPO/rulesets" --input "$file"
  fi
done

say ""
if (( APPLY )) && (( FAILED )); then
  say "$FAILED call(s) FAILED above. None of this is all-or-nothing, so the"
  say "rest went through -- read the names and re-run after fixing them."
  exit 1
fi
if (( APPLY )); then
  say "done. Verify from outside: gh api repos/$REPO/rulesets --jq '.[].name'"
  say "and open a pull request -- the merge button is the only real check that"
  say "the required contexts are spelled the way Actions reports them."
else
  say "plan only. Re-run with --apply."
fi
