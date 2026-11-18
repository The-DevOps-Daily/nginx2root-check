# nginx2root-check

A small, read-only checker for the five "nginx2root" CVEs that Xint disclosed on
18 November 2026 and that nginx fixed in **1.31.9** (mainline) and **1.30.7**
(stable).

| CVE | Bug | Needed to reach it |
| --- | --- | --- |
| CVE-2026-123007 | Memory corruption in HTTP/2 flow control | HTTP/2 enabled |
| CVE-2026-123633 | Use-after-free in HTTP/2 | HTTP/2 + requests proxied to an upstream |
| CVE-2026-121810 | Use-after-free in HTTP/3 | HTTP/3 (QUIC) + requests proxied to an upstream |
| CVE-2026-123634 | Use-after-free in the resolver | `resolver` + a per-request `proxy_pass` + `mirror`/SSI |
| CVE-2026-113425 | Use-after-free in the mail proxy | mail proxy with `proxy on` and `auth_http` |

Each one is an independent, unauthenticated path to code execution as the nginx
worker process. `CVE-2026-123007` only needs HTTP/2, which most TLS sites turn
on, so it is the one that reaches the most servers.

## What it does

The script reads three things and nothing else:

- `nginx -v` for the version,
- `nginx -V` for the compiled-in modules,
- `nginx -T` for the running configuration (read-only).

From those it prints a version verdict (vulnerable / fixed) and which of the
five attack-path features are actually enabled, then maps that to a per-CVE
result. It never sends a request, never touches the network, and changes
nothing. There is no exploit code here.

## Usage

```bash
# check the local nginx (run with sudo so nginx -T can read every include)
sudo sh nginx2root-check.sh

# machine-readable
sudo sh nginx2root-check.sh --json

# check a container image instead (needs a working docker CLI)
sh nginx2root-check.sh --image nginx:1.31.8
sh nginx2root-check.sh --image myregistry/myapp:latest --json
```

Exit codes: `0` not affected, `1` affected, `2` fixed version but the running
worker may still need a restart, `3` cannot tell.

## Example

A patched image reports `fixed` and reminds you to restart the worker:

```text
nginx version:    1.31.9 (branch 1.31) -> fixed
verdict:          Patched build (1.31.9 / 1.30.7 or later). Confirm the running worker was restarted.
exit code:        2
```

A vulnerable version with HTTP/2, a resolver and a proxied upstream lights up
the matching paths:

```text
nginx version:    1.31.8 (branch 1.31) -> vulnerable
features enabled: http2=yes http3/quic=no resolver=yes proxy_pass=yes mail_proxy=no ssl_preread=no
attack paths:
  CVE-2026-123007 HTTP/2 flow control      : YES
  CVE-2026-123633 HTTP/2 use-after-free     : YES
  CVE-2026-123634 resolver use-after-free   : likely (resolver in use; confirm per-request proxy_pass + mirror/SSI)
verdict:          Affected: a vulnerable version has at least one nginx2root feature enabled. Patch now.
exit code:        1
```

Sample runs against the official `nginx:1.31.8`, `1.31.9`, `1.30.6` and `1.30.7`
images, plus a deliberately vulnerable config, are in [`results/`](results/).

## Notes and limits

- **Distro backports.** Ubuntu, Debian, RHEL and others may backport the fix
  without changing the `X.Y.Z` string that `nginx -v` prints. When the build
  looks like a distro package, the script says so. Compare the full package
  version with your distro's advisory to be sure.
- **A reload is not enough.** Installing a fixed package and reloading keeps the
  old worker binary running. Restart nginx or do a supported live binary upgrade
  so the new executable actually serves traffic.
- **`nginx -T` reads the config on disk.** If you edited it without reloading,
  the running configuration may differ from what the script sees.
- **CVE-2026-123634** depends on subrequests (`mirror`, SSI and similar). The
  script flags the `resolver` directive as the signal; confirm the full
  condition by hand.

## Sources

See [SOURCES.md](SOURCES.md). All facts come from nginx.org, the Xint writeup,
the F5 advisory and the official Docker images.
