#!/usr/bin/env bash
# Dev A. Can this laptop run the live sandbox safely?
# Exit 0 only when rootless bwrap works AND a connect to 1.1.1.1:80 inside the netns fails.
# strace, docker, libfaketime and python3-venv are reported; only the network-block failure
# (or a missing/broken bwrap) makes the live runner unsafe.
ok=1
say() { printf '%-34s %s\n' "$1" "$2"; }
echo "== TrustLens environment check =="
say "OS" "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-$(uname -sr)}")"
say "python3" "$(python3 --version 2>&1)"
if python3 -c "import venv, ensurepip" 2>/dev/null; then
  say "python3-venv" "ok"
else
  say "python3-venv" "MISSING: sudo apt install python3-venv (host tooling only)"
fi
if command -v bwrap >/dev/null; then
  say "bwrap" "$(bwrap --version 2>&1 | head -1)"
else
  say "bwrap" "MISSING: sudo apt install bubblewrap"
  ok=0
fi
if command -v strace >/dev/null; then
  say "strace" "$(strace -V 2>&1 | head -1)"
else
  say "strace" "MISSING (2nd tracing layer off): sudo apt install strace"
fi
if command -v docker >/dev/null; then
  if docker info >/dev/null 2>&1; then
    say "docker" "present and daemon responds (fallback runner)"
  else
    say "docker" "binary present but 'docker info' failed (runner=docker unavailable)"
  fi
else
  say "docker" "absent (fine if bwrap works; runner=docker unavailable)"
fi
if [ -e /usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 ] || [ -e /usr/lib/aarch64-linux-gnu/faketime/libfaketime.so.1 ]; then
  say "libfaketime" "present (clock+30d can shift C-level time)"
else
  say "libfaketime" "absent (clock+30d will patch Python time only)"
fi
for f in /proc/sys/kernel/unprivileged_userns_clone /proc/sys/kernel/apparmor_restrict_unprivileged_userns /proc/sys/user/max_user_namespaces; do
  if [ -r "$f" ]; then
    say "$(basename "$f")" "$(cat "$f")"
  else
    say "$(basename "$f")" "absent"
  fi
done
if command -v bwrap >/dev/null; then
  if bwrap --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin \
      --unshare-net --unshare-pid --proc /proc --dev /dev /usr/bin/true 2>/tmp/tl_bwrap.err; then
    say "bwrap rootless + no-net" "WORKS"
    if bwrap --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin \
        --unshare-net --proc /proc --dev /dev /usr/bin/python3 -c "import socket,sys; s=socket.socket(); s.settimeout(1)
try: s.connect(('1.1.1.1',80)); sys.exit(1)
except OSError: sys.exit(0)"; then
      say "network really blocked" "YES"
    else
      say "network really blocked" "NO  <-- do NOT run samples"
      ok=0
    fi
  else
    say "bwrap rootless + no-net" "FAILS: $(head -c 160 /tmp/tl_bwrap.err)"
    ok=0
    if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = "1" ]; then
      echo "  Ubuntu 23.10+/24.04 restricts unprivileged user namespaces. Options (pick one):"
      echo "   a) sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0   (until reboot; weakens the host, use only on a lab laptop)"
      echo "   b) AppArmor profile that allows /usr/bin/bwrap userns (see 'man apparmor.d', profile flags=(unconfined) { userns, })"
      echo "   c) fall back to Docker: --network none --read-only --cap-drop ALL (runner=docker)"
    fi
  fi
  if command -v strace >/dev/null && [ "$ok" = 1 ]; then
    if bwrap --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin \
        --proc /proc --dev /dev --tmpfs /tmp --unshare-net --unshare-pid --die-with-parent \
        /usr/bin/strace -e trace=execve -o /tmp/tl-strace-probe.txt /usr/bin/true 2>/tmp/tl_strace.err; then
      say "strace inside bwrap" "WORKS"
    else
      say "strace inside bwrap" "FAILS (native layer off): $(head -c 120 /tmp/tl_strace.err)"
    fi
  fi
fi
if [ "$ok" = 1 ]; then
  say "live_safe" "YES"
  echo "== result: LIVE RUNNER OK =="
else
  say "live_safe" "NO"
  echo "== result: LIVE RUNNER NOT AVAILABLE -> use Docker or --runner fixture =="
fi
[ "$ok" = 1 ]
