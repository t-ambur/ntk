#!/bin/bash

set -euo pipefail

VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
TAG="v$VERSION"

echo "Tagging release $TAG"

git checkout main
git pull origin main
git tag "$TAG"
git push origin "$TAG"

echo "Done — $TAG pushed, release workflow should be running."