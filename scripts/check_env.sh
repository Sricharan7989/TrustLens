#!/usr/bin/env bash
# Dev A. FIRST TASK FOR EVERY TEAMMATE: can this laptop run the sandbox? Pure bash, needs no venv. Exit 0 = live runner OK, 1 = use Docker/fixture fallback.
ok=1
say() { printf '%-34s %s\n' "$1" "$2"; }
echo "== TrustLens environment check =="
say "OS" "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-$(uname -sr)}")"
say "python3" "$(python3 --version 2>&1)"
python3 -c "import venv, ensurepip" 2>/dev/null && say "python3-venv" "ok" || { say "python3-venv" "MISSING: sudo apt install python3-venv"; }
if command -v bwrap >/dev/null; then say "bwrap" "$(bwrap --version)"; else say "bwrap" "MISSING: sudo apt install bubblewrap"; ok=0; fi
if command -v strace >/dev/null; then say "strace" "$(strace -V 2>&1 | head -1)"; else say "strace" "MISSING (2nd tracing layer off): sudo apt install strace"; fi
command -v docker >/dev/null && say "docker" "present (fallback runner)" || say "docker" "absent (fine if bwrap works)"
for f in /proc/sys/kernel/unprivileged_userns_clone /proc/sys/kernel/apparmor_restrict_unprivileged_userns /proc/sys/user/max_user_namespaces; do
  [ -r "$f" ] && say "$(basename "$f")" "$(cat "$f")"
done
if command -v bwrap >/dev/null; then
  if bwrap --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin --unshare-net --unshare-pid --proc /proc --dev /dev /usr/bin/true 2>/tmp/tl_bwrap.err; then
    say "bwrap rootless + no-net" "WORKS"
    if bwrap --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin --unshare-net --proc /proc --dev /dev /usr/bin/python3 -c "import socket,sys; s=socket.socket(); s.settimeout(1)
try: s.connect(('1.1.1.1',80)); sys.exit(1)
except OSError: sys.exit(0)" ; then say "network really blocked" "YES"; else say "network really blocked" "NO  <-- do NOT run samples"; ok=0; fi
  else
    say "bwrap rootless + no-net" "FAILS: $(head -c 160 /tmp/tl_bwrap.err)"; ok=0
    if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = "1" ]; then
      echo "  Ubuntu 23.10+/24.04 restricts unprivileged user namespaces. Options (pick one):"
      echo "   a) sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0   (until reboot; weakens the host, use only on a lab laptop)"
      echo "   b) AppArmor profile that allows /usr/bin/bwrap userns (see 'man apparmor.d', profile flags=(unconfined) { userns, })"
      echo "   c) fall back to Docker: --network none --read-only --cap-drop ALL with strace inside (runner=docker, Dev A stretch task)"
    fi
  fi
fi
echo "== result: $([ $ok = 1 ] && echo 'LIVE RUNNER OK' || echo 'LIVE RUNNER NOT AVAILABLE -> use Docker or --runner fixture') =="
[ $ok = 1 ]
