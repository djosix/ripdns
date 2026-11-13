#!/usr/bin/env bash
# Build the ripdns Docker image, or build it for several platforms and push it.
set -euo pipefail

IMAGE="${IMAGE:-djosix/ripdns}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
BUILDER="${BUILDER:-ripdns}"

usage() {
  cat >&2 <<EOF
Usage:
  scripts/image.sh build             build for this machine and load as $IMAGE:latest
  scripts/image.sh push [VERSION]    build $PLATFORMS, push $IMAGE:latest
                                     (and $IMAGE:VERSION when given)

Environment: IMAGE, PLATFORMS, BUILDER (buildx builder used by push).
EOF
  exit 2
}

case "${1:-}" in
build) [ $# -eq 1 ] || usage ;;
push) [ $# -le 2 ] || usage ;;
*) usage ;;
esac

cd "$(dirname "$0")/.."

labels=(--label "org.opencontainers.image.source=https://github.com/djosix/ripdns")
if rev=$(git rev-parse HEAD 2>/dev/null); then
  if [ -n "$(git status --porcelain)" ]; then
    echo "warning: uncommitted changes are included in the image" >&2
    rev="$rev-dirty"
  fi
  labels+=(--label "org.opencontainers.image.revision=$rev")
fi

case "$1" in
build)
  docker build "${labels[@]}" -t "$IMAGE:latest" .
  ;;
push)
  tags=(-t "$IMAGE:latest")
  if [ $# -eq 2 ]; then
    tags+=(-t "$IMAGE:$2")
  fi
  # A docker-container builder can always produce multi-platform images. The
  # build stage runs on the build platform and cross-compiles, so no QEMU.
  if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
    docker buildx create --name "$BUILDER" --driver docker-container >/dev/null
  fi
  docker buildx build --builder "$BUILDER" --platform "$PLATFORMS" \
    "${labels[@]}" "${tags[@]}" --push .
  docker buildx imagetools inspect "$IMAGE:latest"
  ;;
esac
