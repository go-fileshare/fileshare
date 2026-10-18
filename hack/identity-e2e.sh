#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
#
# identity-e2e.sh FILESHARE -- shares served as their people, end to end, as
# root, with real accounts (docs/identity.md, phase 1). It CREATES accounts
# and removes them: run it in a throwaway machine (CI), never on one that
# matters.
#
#   - the front runs as the service account, not root;
#   - a file alice writes, over WebDAV and over SFTP, belongs to alice;
#   - bob is refused by the KERNEL on a tree that is alice's alone;
#   - alice's worker runs as alice;
#   - an account below min_uid is refused by the launcher;
#   - stopping the server leaves no worker behind.
#
# POSIX sh: Linux, FreeBSD and OpenBSD. Needs curl, ssh-keygen and sftp.
set -eu

bin=${1:?usage: identity-e2e.sh FILESHARE}
[ "$(id -u)" = 0 ] || { echo "identity-e2e: must run as root" >&2; exit 2; }
os=$(uname -s)

# --- accounts ---------------------------------------------------------------
nologin=/usr/sbin/nologin
[ -x "$nologin" ] || nologin=/sbin/nologin
addaccount() { # name uid
	case "$os" in
	Linux)
		groupadd -g "$2" "$1"
		useradd -u "$2" -g "$2" -M -d /nonexistent -s "$nologin" "$1" ;;
	FreeBSD)
		pw groupadd "$1" -g "$2"
		pw useradd "$1" -u "$2" -g "$2" -d /nonexistent -s "$nologin" ;;
	OpenBSD)
		groupadd -g "$2" "$1"
		useradd -u "$2" -g "$2" -d /nonexistent -s "$nologin" "$1" ;;
	*) echo "identity-e2e: no way to add an account on $os" >&2; exit 2 ;;
	esac
}
delaccount() {
	case "$os" in
	Linux) userdel "$1" 2>/dev/null || :; groupdel "$1" 2>/dev/null || : ;;
	FreeBSD) pw userdel "$1" 2>/dev/null || :; pw groupdel "$1" 2>/dev/null || : ;;
	OpenBSD) userdel "$1" 2>/dev/null || :; groupdel "$1" 2>/dev/null || : ;;
	esac
}
accounts="fsfront:1990 fsalice:2001 fsbob:2002 fslow:500"

work=/tmp/fsid.$$
pid=
cleanup() {
	[ -n "$pid" ] && kill "$pid" 2>/dev/null || :
	for a in $accounts; do delaccount "${a%%:*}"; done
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
for a in $accounts; do addaccount "${a%%:*}" "${a##*:}"; done

fail() { echo "FAIL: $*" >&2; echo "--- server log" >&2; cat "$work/log" >&2 || :; exit 1; }
ok() { echo "ok   $*"; }
owner() { ls -ln "$1" | awk '{print $3}'; }

# --- the tree, the configuration --------------------------------------------
mkdir -p "$work/home/private"
chmod 755 "$work"
chmod 1777 "$work/home"                 # anybody may create, nobody may delete another's
echo "alice's secret" > "$work/home/private/secret.txt"
chown -R 2001:2001 "$work/home/private"
chmod 700 "$work/home/private"
chmod 600 "$work/home/private/secret.txt"
for u in fsalice fsbob fslow; do printf '%s-pw\n' "$u" > "$work/$u.pw"; done
chmod 644 "$work"/*.pw
ssh-keygen -q -t ed25519 -N '' -f "$work/key"
cp "$bin" "$work/fileshare" && chmod 755 "$work/fileshare"

port=$((20000 + $$ % 20000))
cat > "$work/c.hcl" <<EOF
user "fsalice" {
  password_file   = "$work/fsalice.pw"
  authorized_keys = ["$(cat "$work/key.pub")"]
}
user "fsbob" { password_file = "$work/fsbob.pw" }
user "fslow" { password_file = "$work/fslow.pw" }
identity {
  service_user = "fsfront"
  idle         = "1s"
}
share "home" {
  directory = "$work/home"
  identity  = "system"
}
serve "webdav" { addr = "127.0.0.1:$port" }
serve "sftp"   { addr = "127.0.0.1:$((port + 1))" }
EOF
chmod 644 "$work/c.hcl"

# --- serve --------------------------------------------------------------------
"$work/fileshare" serve -c "$work/c.hcl" > "$work/log" 2>&1 &
pid=$!
i=0
# The announcements are aligned: "sftp   on", "webdav on".
until grep -Eq "sftp +on 127\.0\.0\.1:$((port + 1))" "$work/log" && grep -Eq "webdav +on 127\.0\.0\.1:$port" "$work/log"; do
	kill -0 "$pid" 2>/dev/null || fail "the server exited"
	i=$((i + 1)); [ "$i" -lt 100 ] || fail "the server never announced itself"
	sleep 0.1
done

front=$(sed -n 's/.*the front runs as fsfront (uid [0-9]*), pid \([0-9]*\).*/\1/p' "$work/log")
[ -n "$front" ] || fail "the launcher did not say which process the front is"
[ "$(ps -o uid= -p "$front" | tr -d ' ')" = 1990 ] || fail "the front is not uid 1990: $(ps -o uid=,args= -p "$front")"
ok "the front runs as fsfront (uid 1990)"

dav="http://127.0.0.1:$port/home"
code() { curl -s -o "$work/body" -w '%{http_code}' "$@"; }

echo "from alice" > "$work/a.txt"
c=$(code -u fsalice:fsalice-pw -T "$work/a.txt" "$dav/a.txt")
case "$c" in 2*) ;; *) fail "alice's PUT: $c" ;; esac
[ "$(owner "$work/home/a.txt")" = 2001 ] || fail "a.txt belongs to $(owner "$work/home/a.txt"), not alice (2001)"
ok "a file alice PUTs over WebDAV belongs to alice"

c=$(code -u fsalice:fsalice-pw "$dav/private/secret.txt")
[ "$c" = 200 ] && grep -q "alice's secret" "$work/body" || fail "alice cannot read her own file: $c"
ok "alice reads her own 0600 file"

c=$(code -u fsbob:fsbob-pw "$dav/private/secret.txt")
[ "$c" != 200 ] || fail "bob read alice's 0600 file"
grep -q "alice's secret" "$work/body" && fail "bob was sent alice's secret"
ok "bob is refused alice's 0600 file ($c), by the kernel"

c=$(code -u fsbob:fsbob-pw -T "$work/a.txt" "$dav/private/b.txt")
case "$c" in 2*) fail "bob wrote into alice's 0700 directory" ;; esac
[ ! -e "$work/home/private/b.txt" ] || fail "b.txt exists in alice's directory"
ok "bob may not write into alice's 0700 directory ($c)"

# -ww: OpenBSD's ps cuts the command line at 80 columns otherwise. The uid
# column is what is checked; the arguments only say which process it is.
ps -A -ww -o uid= -o args= > "$work/ps"
grep -q '^ *2001 .*fileshare worker ' "$work/ps" || { cat "$work/ps"; fail "no worker running as alice"; }
if grep ' worker ' "$work/ps" | grep -v '^ *200[12] ' | grep -q fileshare; then
	cat "$work/ps"; fail "a worker runs as somebody other than its person"
fi
ok "alice's worker runs as alice, bob's as bob"

c=$(code -u fslow:fslow-pw "$dav/")
[ "$c" = 403 ] || fail "fslow (uid 500, below min_uid) got $c, not 403"
grep -q "below min_uid" "$work/log" || fail "the refusal of fslow is not in the log"
ok "an account below min_uid is refused by the launcher"

printf 'put %s /home/s.txt\n' "$work/a.txt" > "$work/batch"
sftp -q -b "$work/batch" -i "$work/key" -P "$((port + 1))" \
	-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	fsalice@127.0.0.1 > "$work/sftp.log" 2>&1 || { cat "$work/sftp.log"; fail "alice's sftp put"; }
[ "$(owner "$work/home/s.txt")" = 2001 ] || fail "s.txt belongs to $(owner "$work/home/s.txt"), not alice (2001)"
ok "a file alice puts over SFTP belongs to alice"

kill "$pid"
wait "$pid" 2>/dev/null || :
pid=
i=0
while ps -A -o args= | grep -q '[f]ileshare worker'; do
	i=$((i + 1)); [ "$i" -lt 50 ] || { ps -A -o uid= -o args= | grep '[f]ileshare'; fail "a worker outlived the server"; }
	sleep 0.1
done
ok "stopping the server leaves no worker behind"
