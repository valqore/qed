#!/usr/bin/env bash
# Render `qed.rb.template` into the formula that goes in the tap repository.
#
#   ./render.sh 1.0.0                 # checksums from the v1.0.0 release
#   ./render.sh 1.0.0 /tmp/sums       # checksums from a directory
#
# Writes the formula to stdout. The second form exists so the tests can render
# without a network, and so you can check a release's sums by hand first.
#
# ## Why this is a script and not a sed one-liner
#
# The obvious one-liner is `sed 's/VERSION/1.0.0/g'`, and it is wrong: the
# template's header prose contains the word VERSION, so a blanket substitution
# rewrites the documentation into nonsense ("`1.0.0`, and the three SHA256
# values, come from the release"). It was written as a one-liner first and it
# did exactly that. So substitution here happens only on lines that are not
# comments, and the result is checked for leftover placeholders before it is
# printed -- a rendered formula with `SHA256_LINUX_X86_64` still in it would be
# a `brew install` that fails on a checksum mismatch.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$HERE/qed.rb.template"

version="${1:-}"
sums_dir="${2:-}"

if [ -z "$version" ]; then
  echo "usage: render.sh <version> [directory-of-sha256-files]" >&2
  exit 2
fi

# `[ -n "$tmp" ] && rm -rf "$tmp"` would be the obvious body, and it makes the
# script exit 1 whenever no temporary directory was created: the test fails,
# the status of a trap's last command becomes the script's exit status, and
# nothing is printed to say why.
cleanup() {
  if [ -n "${tmp:-}" ]; then
    rm -rf "$tmp"
  fi
}
trap cleanup EXIT

if [ -z "$sums_dir" ]; then
  tmp="$(mktemp -d)"
  sums_dir="$tmp"
  # The release is the only acceptable source: see the header of the template.
  gh release download "v$version" --pattern 'qed-*.sha256' --dir "$sums_dir" >&2
fi

# Map each checksum file onto its placeholder by the platform in its name, so
# that a new platform in the release matrix fails loudly here rather than
# silently shipping a formula with one stale hash.
declare -A sums=()
for file in "$sums_dir"/*.sha256; do
  [ -e "$file" ] || continue
  hash="$(cut -d' ' -f1 < "$file")"
  case "$(basename "$file")" in
    *macos-arm64*)  sums[SHA256_MACOS_ARM64]="$hash" ;;
    *macos-x86_64*) sums[SHA256_MACOS_X86_64]="$hash" ;;
    *linux-x86_64*) sums[SHA256_LINUX_X86_64]="$hash" ;;
    *) echo "render.sh: no placeholder for $(basename "$file")" >&2; exit 1 ;;
  esac
done

for key in SHA256_MACOS_ARM64 SHA256_MACOS_X86_64 SHA256_LINUX_X86_64; do
  if [ -z "${sums[$key]:-}" ]; then
    echo "render.sh: no checksum found for $key in $sums_dir" >&2
    exit 1
  fi
done

rendered="$(
  awk -v ver="$version" \
      -v arm="${sums[SHA256_MACOS_ARM64]}" \
      -v x86="${sums[SHA256_MACOS_X86_64]}" \
      -v lin="${sums[SHA256_LINUX_X86_64]}" '
    # Comments keep their prose. Everything else gets the real values.
    /^[[:space:]]*#/ { print; next }
    {
      gsub(/SHA256_MACOS_ARM64/, arm)
      gsub(/SHA256_MACOS_X86_64/, x86)
      gsub(/SHA256_LINUX_X86_64/, lin)
      gsub(/VERSION/, ver)
      print
    }
  ' "$TEMPLATE" | awk '/^class Qed < Formula/ { found = 1 } found'
)"

if [ -z "$rendered" ]; then
  echo "render.sh: no formula body found in $TEMPLATE" >&2
  exit 1
fi

# Only non-comment lines, for the same reason the substitution skips comments:
# a placeholder matters where Homebrew reads it. A body comment that mentions
# VERSION is prose, and refusing to render because of it would be this script
# failing on the very distinction it exists to draw.
leftover="$(printf '%s\n' "$rendered" | grep -v -E '^[[:space:]]*#' | grep -n -E 'SHA256_|VERSION' || true)"
if [ -n "$leftover" ]; then
  echo "render.sh: placeholders left after rendering:" >&2
  printf '%s\n' "$leftover" >&2
  exit 1
fi

cat <<HEADER
# Homebrew formula for the \`qed\` single-file binary (SPEC §24.1).
#
# ## Generated, not written
#
# This file is \`deploy/homebrew/qed.rb.template\` in valqore/qed, rendered by
# \`deploy/homebrew/render.sh $version\`. Edit the template there, never this
# copy: the binary and the formula that installs it are meant to change
# together, and a hand-edit here is a second source of truth that will
# disagree with the first one at the worst possible moment.
#
# The checksums below are the ones CI wrote beside each binary in the v$version
# release. They are not computed from a local build -- the point of the
# checksum is that the file Homebrew downloads is the file CI produced.
HEADER
printf '%s\n' "$rendered"
