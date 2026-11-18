# Sources

Primary sources used to build and verify this checker (checked 18 Nov 2026).

- nginx security advisories: https://nginx.org/en/security_advisories.html
- nginx 1.31.9 changelog: https://nginx.org/en/CHANGES
- Xint writeup, "NGINX2Root: New Remote Code Execution Vulnerabilities in nginx":
  https://xint.io/blog/nginx2root-remote-code-execution
- nginx2root landing page: https://nginx2root.com
- F5 advisory K000163926: https://my.f5.com/manage/s/article/K000163926
- Official nginx Docker images (library/nginx): https://hub.docker.com/_/nginx

## Fixed versions

- nginx mainline: 1.31.9 (released 18 Nov 2026)
- nginx stable: 1.30.7 (released 18 Nov 2026)

## Affected configuration, per CVE (from the Xint writeup)

| CVE | Affected configuration | First affected release | Blocked by disabling HTTP/2 |
| --- | --- | --- | --- |
| CVE-2026-123007 | HTTP/2 enabled | 1.9.5 | yes |
| CVE-2026-123633 | HTTP/2 with requests forwarded to an upstream | 1.19.7 | yes |
| CVE-2026-121810 | HTTP/3 with requests forwarded to an upstream | 1.25.0 | no |
| CVE-2026-123634 | resolver + request-derived proxy_pass + mirror (or other subrequest) | 1.13.4 | no |
| CVE-2026-113425 | mail proxy with proxy on and auth_http | 0.5.15 | no |

The nginx.org advisory list records the vulnerable ranges as `1.9.5-1.31.8`
(123007), `1.19.7-1.31.8` (123633), `1.25.0-1.31.8` (121810),
`0.6.18-1.31.8` (123634) and `0.5.33-1.31.8` (113425), all fixed in
`1.31.9+` and `1.30.7+`.
