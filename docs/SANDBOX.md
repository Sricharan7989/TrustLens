# SANDBOX notes (Owner: Dev A)

What the live runner actually does, what was executed on this machine, and what is still a stub. Fixture replay (`runner="fixture"`) is unchanged: it copies `schemas/examples/<name>/` and sets `run.stub=true`. It does not run the package.

`runner="auto"` uses bwrap when `check_env()["bwrap_ok"]` is true, otherwise the fixture runner. It does not prefer Docker.

## Layer status

| Layer | Status | What it catches | Blind spots | Test |
|---|---|---|---|---|
| bwrap isolation (`--unshare-net`, `--unshare-pid`, `--clearenv`, fake `$HOME`, fake `/etc`) | real | process, network, and host home stay outside the sandbox | needs unprivileged user namespaces | `scripts/check_env.sh`, `tests/sandbox/test_sandbox.py` |
| env check | real | bwrap starts, connect to `1.1.1.1:80` inside the netns fails, strace inside bwrap, docker daemon, libfaketime, venv | exit 0 only when bwrap works and that connect fails | `test_check_env_shape`, `test_check_env_script_exit_matches_live_safe` |
| offline `pip install --no-index --no-build-isolation --target /w/installed` | real | setup.py side effects during install; `coverage.install_completed` | no build isolation means the sandbox interpreter's setuptools/wheel are copied in; user-site `.pth` is not a separate trigger | `tests/sandbox/test_install.py` |
| site-packages diff | real | `startup.pth` lines, `startup.sitecustomize` / `usercustomize`, `install.hook` (console scripts and `cmdclass`), `file.new` outside the import package | `*.dist-info` is not emitted as `file.new` | `test_install_diff_emits_pth_and_entry_points` |
| fresh-interpreter startup | real | `.pth` `import ` lines run in phase `startup`, trigger `fresh_startup`, without importing the package | see the CPython order note below | `test_pth_toy_install_and_fresh_startup` |
| audit hook | real | `open`, urllib `Request` (url, headers, body), `getaddrinfo`, `connect`, `subprocess`, `compile` / `exec`, `ctypes.dlopen` | C `open` that never enters Python; header names are urllib's capitalized form (`X-Canary` becomes `X-canary`) | `test_live_evil_slug_has_canary_read_and_blocked_net`, `test_five_exfil_shapes_match_canary` |
| env wrapper | real | `os.getenv`, `os.environ.get`, `in`, `.items()`, `.copy()`, `dict(os.environ)` (bulk dump is one `env.read` with `name:"*"` plus canary keys) | C code reading the `environ` block; `HOSTNAME` / `NUMBER_OF_PROCESSORS` are logged but not in Dev B's `PROBE_ENV` list | `tests/sandbox/test_env_wrapper.py` |
| attribution | real | innermost non-stdlib frame; toolchain and the agent are dropped; unsure stays `pkg` | a package that calls through a stdlib wrapper we do not skip can be missed | `test_clean_slug_has_no_pkg_env_or_file_events`, `test_rest_wrapper_pkg_events_are_the_claimed_ones` |
| dev / ci profiles | real | `CI`, `GITHUB_ACTIONS`, `RUNNER_OS`, `JENKINS_URL`, hostname, user, cwd, `~/.gitconfig`, `/.dockerenv` on ci only; events carry `profile` | profiles run in parallel, each in its own work dir | `test_live_delayed_slug_is_env_differential`, `tests/sandbox/test_profiles.py` |
| strace second layer | real on this VM | `openat` / `connect` / `sendto` / `execve` after a `python -c pass` baseline subtraction; `native.load` for a package `.so`; `evidence.layer="strace"` | only sensitive paths and package `.so` files are kept (not every open); `strace` missing → `not_observed` says the layer is not active | `tests/sandbox/test_strace.py` |
| trigger matrix | real | typed callables (3 arg sets), classes and public methods, `if __name__ == "__main__"`, console scripts `cli:<name>` with no-arg and `--help` | `runpy` cannot execute a package, so a guard in `__init__.py` is re-exec'd with `__name__="__main__"`; plain modules and `__main__.py` use `runpy` | `tests/sandbox/test_triggers.py` |
| clock `+30d` | real when `libfaketime.so.1` is present | call and cli triggers run again with `variant:"clock+30d"` | if the `.so` is absent, the agent patches `time.time` / `datetime` only and `not_observed` says C-level time is not shifted; the two are never stacked | `tests/sandbox/test_clock.py` |
| canary match | real | token plus unpadded base32 and url-safe base64, in URLs, headers, bodies, DNS labels, `socket.send`, subprocess argv | file canaries match by path suffix; env canaries match by variable name | `tests/sandbox/test_canary_bytes.py` |
| loopback sinkhole | real on bwrap here | DNS on `127.0.0.1:53` answers A with `127.0.0.1`; HTTP on `:80` returns a marker script; second stage is `dyn.compile` / `dyn.exec` | audit-layer `net.*` outcomes stay `blocked` (the hook fires before the socket result); Docker `--cap-drop ALL` is not expected to bind 53/80 | `tests/sandbox/test_sinkhole.py` |
| sandbox-probe logging | real, as `file.read` / `env.read` | `/.dockerenv`, `/proc/1/cgroup`, `/proc/uptime`, `/proc/cpuinfo`, `DISPLAY`, `CI`, `HOSTNAME` (via `gethostname`), `NUMBER_OF_PROCESSORS` (via `cpu_count`) | there is no `sandbox_probe` raw kind (the schema enum does not have it); Dev B already scores the file paths and the CI env names | `tests/sandbox/test_probe.py` |
| docker fallback | implemented, not executed here | same agent, canaries, and harness behind `docker run --rm --network none --read-only --cap-drop ALL` | no docker daemon on this VM; live test is `skipif` | `tests/sandbox/test_docker.py` |
| profile parallelism | real | one work dir per profile, merged and re-numbered | per-phase timeout is still `timeout_s`, not a global budget | timed in the run notes below |

## Verified on this VM

Ubuntu 24.04. `bubblewrap` 0.9.0, `strace` 6.8, and `libfaketime` 0.9.10 are installed. `python3` is 3.12. `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` is absent. `max_user_namespaces` is non-zero. Rootless bwrap works.

Checked live, not mocked:

- `scripts/check_env.sh` exits 0. A connect to `1.1.1.1:80` inside `--unshare-net` fails. `strace` inside bwrap works **without** `--cap-add CAP_SYS_PTRACE`.
- `LD_PRELOAD` of `/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1` with `FAKETIME=+30d` moves `date` forward 30 days. There is no `faketime` binary; the runner uses the `.so`.
- Offline `pip install --no-index --no-build-isolation --no-deps --target /w/installed` of the bench toys and `tests/sandbox/data/*` succeeds inside bwrap. Toolchain packages are copied from the sandbox interpreter's dist-packages (`/usr/bin/python3`, not the project venv).
- A `.pth` line injected by `wheel.bdist_wheel` is installed and runs on the fresh-startup trigger.
- The sinkhole binds ports 53 and 80 as uid 0 with `--cap-add CAP_NET_BIND_SERVICE`. Writing `ip_unprivileged_port_start` still fails; the capability is what makes the bind succeed. `tests/sandbox/test_sinkhole.py` sees `run.network=sinkhole` and the marker in a `dyn.*` event.
- `ctypes` `open` of the ssh canary is visible to strace and not to the audit hook (`test_libc_open_of_canary_is_visible_to_strace`).

Not executed here:

- Docker. `docker` is not installed. `docker_command()` is unit-tested for `--rm --network none --read-only --cap-drop ALL` and tmpfs mounts. `run_package(..., runner="docker")` raises if the daemon is down. Do not pull an image; the runner uses `TRUSTLENS_DOCKER_IMAGE` or a local image whose name contains `python`, else `python:3.12-slim`.
- Dev C's extra packages. They are not in the tree. Recorded fixtures below are only the synthetic toys in `tests/sandbox/data/`.

## Fresh startup and `.pth` order

CPython's `site.addsitedir` runs `import ` lines in site-packages `.pth` files **before** `sitecustomize`. A normal `python -c pass` would run the payload before the audit hook. The startup trigger is therefore:

```text
python -S /w/agent/startup_bootstrap.py
```

`startup_bootstrap.py` imports `sitecustomize` (the hook) and then calls `site.addsitedir("/w/installed")`. Phase is `startup`, trigger is `fresh_startup`.

`PYTHONNOUSERSITE` is not set. The fake `/etc` has no passwd database, so the per-user site directory is not populated. A `.pth` dropped in a real user site is not a separate case.

## Network, canaries, and attribution

`--unshare-net` stays on for every bwrap run. The audit hook records `net.dns`, `net.connect`, `net.http`, and `net.send` with outcome `blocked` at the moment of the call. The sinkhole, when it binds, is how a later `dyn.exec` of the downloaded marker can still happen without leaving the netns. `run.network` and `coverage.network` are `sinkhole` when `/w/sinkhole.status` starts with `ok`, otherwise `blocked`.

Canary ids from the contract: `ssh_key`, `aws_creds`, `npmrc`, `aws_secret_env`, `github_token_env`. Additive file canaries (not yet listed in `docs/CONTRACTS.md`): `gcloud_creds` at `.config/gcloud/application_default_credentials.json`, `docker_config` at `.docker/config.json`. Tokens are `TLCANARY…` plus random hex. Targets are RFC 5737 addresses and `*.invalid` names only.

`HOSTNAME` (from `socket.gethostname`) and `NUMBER_OF_PROCESSORS` (from `os.cpu_count`) are ordinary `env.read` events. Dev B's classifier does not treat those names as `sandbox_probe` until `PROBE_ENV` is extended. File reads of `/.dockerenv`, `/proc/1/cgroup`, `/proc/uptime`, and `/proc/cpuinfo` already match B's `PROBE_PATH`.

Strace file events are limited to sensitive suffixes (ssh, aws, npmrc, docker, gcloud, gitconfig, shell rc, `/.dockerenv`, the proc probe paths) and to `.so` files under `/w/installed` or `/w/site`. That keeps pip's own opens out of `attributed_to=pkg`. The strace baseline is `python -c pass`, `lsb_release -a`, `uname -rs` / `uname -m`, and the `tr` / `cut` argv that `lsb_release` uses. An `execve` whose full argv appeared there is subtracted, which removes pip's distro probe without hiding a different argv. `sendto` toward `127.0.0.0/8` is dropped: that is glibc talking to the loopback DNS sink, and the audit hook already records the package's own `socket.send`. strace has no Python frame, so leaving the probe as `pkg` made a live `clean_slug` scan look like unexplained subprocess use.

## Coverage honesty

`coverage.not_observed` is built by `trustlens.sandbox.coverage.build_not_observed`. It mentions a gap only when that gap applies, including: fresh startup not run, clock variant not run, Python-only clock shift, strace layer not active, sinkhole not active, CLI not run or no console scripts, pip install did not complete, modules that failed to import. Timeouts and crashes become `run.error` plus `coverage.install_note` when the failure is the install. They do not raise. `run_package` raises only for a missing path, a bad profile, an unknown runner, or a missing bwrap/docker binary.

## Fixtures and ownership notes

New toys live in `tests/sandbox/data/` (synthetic only). The repo `.gitignore` pattern `data/` also ignores that directory, so the files are tracked with `git add -f`. Lead: adding `!tests/sandbox/data/` to `.gitignore` keeps the next toy visible to `git status`.

Recorded live outputs for those toys are under `tests/sandbox/recorded/<name>/` (`raw_events.jsonl`, `run_meta.json`). They are not copied into `schemas/examples/` (lead-owned). Dev C has not added packages, so there is nothing further to record for C.

`AUDIT.md` is lead-owned and was not edited.

## Reproduce

```bash
bash scripts/check_env.sh          # exit 0 only if bwrap works and the netns connect fails
python -m pytest tests/sandbox -q
python -m trustlens scan bench/packages/malicious/delayed_slug --runner live --out /tmp/d
```

`delayed_slug` is expected to exit 20. Only `bench/packages/` and `tests/sandbox/data/` are executed, and only inside the runner.
