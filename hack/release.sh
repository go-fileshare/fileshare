#!/usr/bin/env bash
# Builds the release archives of a tag: one static binary per platform
# (CGO_ENABLED=0), with the LICENSE and the README, and SHA256SUMS over them.
# The release workflow runs it; so can anybody, from a checkout of the same
# tag, and compare the sums.
#
#   hack/release.sh v0.29.1 <checkout of v0.29.1> <output directory>
#
# It refuses to build anything but a clean checkout of exactly that tag: the
# version a binary reports is the one Go stamps from the tag, and a binary
# that says "unknown", another version or "+dirty" must never be published.
# Hence the script and the output live OUTSIDE the checkout: Go counts an
# untracked file in the tree as a modification, and stamps "+dirty".
set -euo pipefail
usage="usage: hack/release.sh vX.Y.Z <source checkout> <output directory>"
tag="${1:?$usage}" root="${2:?$usage}" dist="${3:?$usage}"
root="$(cd "$root" && pwd)"
mkdir -p "$dist"
dist="$(cd "$dist" && pwd)"
case "$dist/" in "$root"/*) echo "the output must not be inside the checkout" >&2; exit 2 ;; esac
cd "$root"

[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a release tag: $tag" >&2; exit 2; }
[ "$(git rev-parse HEAD)" = "$(git rev-parse "$tag^{commit}")" ] || { echo "HEAD is not $tag" >&2; exit 2; }
[ -z "$(git status --porcelain)" ] || { echo "the checkout is not clean" >&2; exit 2; }

# Every platform it builds on, minus netbsd: a dependency (awnumar/memcall)
# uses MADV_DONTDUMP, which x/sys does not define there.
targets=(
  linux/amd64 linux/arm64 linux/riscv64 linux/ppc64le linux/s390x linux/loong64
  darwin/amd64 darwin/arm64
  windows/amd64 windows/arm64
  freebsd/amd64 freebsd/arm64
  openbsd/amd64
)

rm -rf "${dist:?}"/*
when="$(git log -1 --format=%ct)"
# The same instant for touch -t, which BSD and GNU both read (POSIX), in UTC.
stamp="$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y%m%d%H%M.%S)"
export CGO_ENABLED=0 GOWORK=off GOFLAGS=-mod=readonly
for t in "${targets[@]}"; do
  os="${t%/*}" arch="${t#*/}"
  name="fileshare_${tag}_${os}_${arch}"
  stage="$dist/$name"
  mkdir -p "$stage"
  exe=fileshare
  [ "$os" = windows ] && exe=fileshare.exe
  # -trimpath: no path of the machine that built it inside the binary.
  # -buildvcs stamps the commit; the module version comes from the tag.
  GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w" -o "$stage/$exe" .
  cp LICENSE README.md "$stage/"
  # Reproducible archives: fixed order, owner and times, and no timestamp
  # in the gzip header (gzip -n) -- the binaries are already identical from
  # one build to the next; only the wrapping varied.
  if [ "$os" = windows ]; then
    find "$stage" -exec env TZ=UTC touch -t "$stamp" {} +
    (cd "$dist" && find "$name" | LC_ALL=C sort | zip -qX "$name.zip" -@)
  else
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$when" \
      -C "$dist" -cf - "$name" | gzip -9n > "$dist/$name.tar.gz"
  fi
  rm -rf "$stage"
done

# The binary for this machine, when there is one, must say it is this tag.
host="$(go env GOOS)_$(go env GOARCH)"
if [ -f "$dist/fileshare_${tag}_${host}.tar.gz" ]; then
  tmp="$(mktemp -d)"
  tar -xzf "$dist/fileshare_${tag}_${host}.tar.gz" -C "$tmp"
  got="$("$tmp/fileshare_${tag}_${host}/fileshare" --version)"
  rm -rf "$tmp"
  [ "$got" = "fileshare version $tag" ] || { echo "the binary says \"$got\", not $tag" >&2; exit 1; }
  echo "$got"
fi

(cd "$dist" && sha256sum -- *.tar.gz *.zip > SHA256SUMS)
ls -l "$dist"
