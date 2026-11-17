#!/bin/sh
# Fails when the default version in docker-compose.yml, install.sh or the README differs from
# Cargo.toml.
# Run from the repository root; a missing file is skipped.
set -eu

cargo=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
[ -n "$cargo" ] || { echo "no version in Cargo.toml" >&2; exit 1; }
status=0

check() {
  file=$1
  found=$2
  if [ "$found" != "$cargo" ]; then
    echo "$file: default version '$found' differs from Cargo.toml version $cargo" >&2
    status=1
  fi
}

if [ -f docker-compose.yml ]; then
  check docker-compose.yml "$(sed -n 's/.*HANGAR_VERSION:-\([^}]*\)}.*/\1/p' docker-compose.yml | head -n 1)"
fi
if [ -f README.md ]; then
  check README.md "$(sed -n 's|.*ghcr.io/feoren/hangar-server:\([0-9][0-9.]*[0-9]\).*|\1|p' README.md | head -n 1)"
fi
if [ -f install.sh ]; then
  check install.sh "$(sed -n 's/^DEFAULT_VERSION=\([0-9][^ ]*\)$/\1/p' install.sh | head -n 1)"
fi

[ "$status" = 0 ] && echo "versions match Cargo.toml ($cargo)"
exit "$status"
