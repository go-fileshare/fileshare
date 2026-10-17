#!/bin/sh
# Runs a release binary the way a tester first will -- the quickstart of the
# release notes: a directory shared over WebDAV, a file put, read back, and
# refused to somebody who did not log in -- and fails on any difference.
# POSIX sh and curl only, so that NetBSD, FreeBSD and OpenBSD run it as is.
#
#   hack/smoke.sh <directory of the extracted archive> <tag>
set -eu
dir="${1:?usage: hack/smoke.sh <extracted archive directory> <tag>}"
tag="${2:?usage: hack/smoke.sh <extracted archive directory> <tag>}"
cd "$dir"
exe=./fileshare
[ -f ./fileshare.exe ] && exe=./fileshare.exe

fail() { echo "smoke: $*" >&2; [ -f serve.log ] && sed 's/^/  serve: /' serve.log >&2; exit 1; }

got="$("$exe" --version)"
[ "$got" = "fileshare version $tag" ] || fail "the binary says \"$got\", not $tag"
echo "ok   $got"

mkdir -p shared
printf 'correct horse battery staple\n' > alice.pw
chmod 600 alice.pw
# A port of its own: something else may well listen on a round number, and
# answer the readiness check in this server's place.
port=$((20000 + $$ % 20000))
cat > fileshare.hcl <<HCL
user "alice" { password_file = "alice.pw" }

share "files" {
  directory = "shared"
  allow     = ["alice"]
  writers   = ["alice"]
}

serve "webdav" { addr = "127.0.0.1:$port" }
HCL

"$exe" check -c fileshare.hcl > check.log 2>&1 || { cat check.log >&2; fail "check refused the quickstart"; }
grep -q 'this configuration can be served' check.log || fail "check did not say it can be served"
echo "ok   check"

"$exe" -c fileshare.hcl > serve.log 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
up=no
i=0
while [ "$i" -lt 60 ]; do
  # Its OWN line, not just an answer on the port: another program on that
  # port would answer too, and the PUT below would fail for the wrong reason.
  if grep -q "webdav on 127.0.0.1:$port" serve.log 2>/dev/null; then up=yes; break; fi
  kill -0 "$pid" 2>/dev/null || fail "the server stopped"
  sleep 1
  i=$((i + 1))
done
[ "$up" = yes ] || fail "nothing answers on port $port after 60 s"
echo "ok   serving"

auth='alice:correct horse battery staple'
url="http://127.0.0.1:$port/files/hello.txt"
printf 'hello from %s\n' "$tag" > hello.txt
code="$(curl -s -o /dev/null -w '%{http_code}' -u "$auth" -T hello.txt "$url")"
[ "$code" = 201 ] || fail "PUT answered $code, not 201"
back="$(curl -s -u "$auth" "$url")"
[ "$back" = "hello from $tag" ] || fail "GET returned \"$back\""
cmp -s hello.txt shared/hello.txt || fail "the file on disk is not what was put"
code="$(curl -s -o /dev/null -w '%{http_code}' "$url")"
[ "$code" = 401 ] || fail "an anonymous GET answered $code, not 401"
code="$(curl -s -o /dev/null -w '%{http_code}' -u 'alice:wrong' "$url")"
[ "$code" = 401 ] || fail "a wrong password answered $code, not 401"
echo "ok   put, get, on disk, anonymous 401, wrong password 401"
