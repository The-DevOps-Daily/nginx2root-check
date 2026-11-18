#!/bin/sh
# nginx2root-check: read-only exposure check for the five "nginx2root" CVEs
# disclosed by Xint on 18 Nov 2026 and fixed in nginx 1.31.9 (mainline) and
# 1.30.7 (stable).
#
#   CVE-2026-123007  memory corruption in HTTP/2 flow control   (HTTP/2 on)
#   CVE-2026-123633  use-after-free in HTTP/2                    (HTTP/2 + upstream)
#   CVE-2026-121810  use-after-free in HTTP/3                    (HTTP/3/QUIC + upstream)
#   CVE-2026-123634  use-after-free in the resolver             (resolver + per-request
#                                                                 proxy_pass + mirror/SSI)
#   CVE-2026-113425  use-after-free in the mail proxy           (mail proxy on + auth_http)
#
# The script reads `nginx -v`, `nginx -V` and `nginx -T` (the running config,
# read-only). It reports a version verdict and which affected features are
# enabled. It never sends a request, never changes anything and contains no
# exploit code.
#
# Exit codes: 0 not affected, 1 affected, 2 fixed version but restart/reload
#             may be pending, 3 cannot tell.
#
# Usage:
#   sh nginx2root-check.sh [--json]            # check the local nginx
#   sh nginx2root-check.sh --image <tag> [--json]  # check an nginx container image
#
# Docker mode runs `nginx -v`, `nginx -V` and `nginx -T` inside a throwaway
# container from <tag> and parses the output. It needs a working docker CLI.

# Fixed PATH: do not resolve tools from the caller's environment.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

JSON=0
IMAGE=""
while [ $# -gt 0 ]; do
	case "$1" in
		--json) JSON=1 ;;
		--image) IMAGE="$2"; shift ;;
		--image=*) IMAGE="${1#--image=}" ;;
		-h|--help) sed -n '2,30p' "$0" 2>/dev/null; exit 0 ;;
		*) echo "unknown option: $1" >&2; exit 3 ;;
	esac
	shift
done

notes=""
add_note() { notes="${notes:+$notes|}$1"; }
json_str() { printf '"%s"' "$(printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g')"; }
yesno() { [ "$1" = 1 ] && echo yes || echo no; }

# --- gather the three nginx outputs, locally or from an image ---------------
ver_line=""; cfg_V=""; cfg_T=""; source="local"

if [ -n "$IMAGE" ]; then
	source="image:$IMAGE"
	command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 3; }
	ver_line=$(docker run --rm --entrypoint nginx "$IMAGE" -v 2>&1)
	cfg_V=$(docker run --rm --entrypoint nginx "$IMAGE" -V 2>&1)
	cfg_T=$(docker run --rm --entrypoint nginx "$IMAGE" -T 2>&1)
else
	command -v nginx >/dev/null 2>&1 || { echo "nginx not found on PATH" >&2; exit 3; }
	ver_line=$(nginx -v 2>&1)
	cfg_V=$(nginx -V 2>&1)
	# -T needs root to read every included file; fall back to -t output note.
	cfg_T=$(nginx -T 2>/dev/null)
	[ -z "$cfg_T" ] && { cfg_T=$(nginx -V 2>&1); add_note "nginx -T returned nothing: run as root for the full config dump"; }
fi

# strip comments from the config dump before matching
cfg=$(printf '%s\n' "$cfg_T" | sed 's/#.*//')

# --- version verdict --------------------------------------------------------
# Use only the real "nginx version:" line, ignoring any docker/platform warnings.
ver_line=$(printf '%s\n' "$ver_line" | grep -i 'nginx version' | head -1)
version=$(printf '%s' "$ver_line" | sed -n 's#.*nginx/\([0-9][0-9.]*\).*#\1#p' | head -1)
branch=$(printf '%s' "$version" | cut -d. -f1,2)

ver_ge() { # $1 >= $2 ?
	[ "$1" = "$2" ] && return 0
	s=$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)
	[ "$s" = "$2" ]
}

# Is this build patched for the nginx2root set?
version_status="unknown"
if [ -n "$version" ]; then
	case "$branch" in
		1.30) if ver_ge "$version" 1.30.7; then version_status="fixed"; else version_status="vulnerable"; fi ;;
		1.31) if ver_ge "$version" 1.31.9; then version_status="fixed"; else version_status="vulnerable"; fi ;;
		*)
			if ver_ge "$version" 1.31.9; then
				version_status="fixed"            # 1.32+ and later
			elif ver_ge "$version" 1.9.5; then
				version_status="vulnerable"       # any other branch in range, no back-branch fix
			else
				version_status="pre-http2"        # < 1.9.5: CVE-2026-123007 does not apply,
			fi                                    # but resolver/mail CVEs still can
			;;
	esac
fi

# Distro builds backport fixes without changing the reported version, so warn.
if printf '%s' "$ver_line" | grep -qiE 'ubuntu|debian|deb[0-9]|\+|~|el[0-9]|amzn|alpine'; then
	add_note "distro package build: the X.Y.Z number may not reflect a backported fix. Compare the full package version with your distro advisory."
fi
[ "$version_status" = "fixed" ] && add_note "running binary must be replaced (restart or supported live upgrade); a config reload alone keeps the old executable."

# --- compiled modules (from nginx -V) ---------------------------------------
mod_http2=0;  printf '%s' "$cfg_V" | grep -q -- '--with-http_v2_module'          && mod_http2=1
mod_http3=0;  printf '%s' "$cfg_V" | grep -q -- '--with-http_v3_module'          && mod_http3=1
mod_mail=0;   printf '%s' "$cfg_V" | grep -q -- '--with-mail'                    && mod_mail=1
mod_sslpre=0; printf '%s' "$cfg_V" | grep -q -- '--with-stream_ssl_preread_module' && mod_sslpre=1

# --- enabled features (from nginx -T) ---------------------------------------
en_http2=0;  printf '%s' "$cfg" | grep -Eq 'listen[^;]*[[:space:]]http2|^[[:space:]]*http2[[:space:]]+on' && en_http2=1
en_http3=0;  printf '%s' "$cfg" | grep -Eq 'listen[^;]*quic|^[[:space:]]*http3[[:space:]]+on'             && en_http3=1
en_resolver=0; printf '%s' "$cfg" | grep -Eq '^[[:space:]]*resolver[[:space:]]'                          && en_resolver=1
en_varproxy=0; printf '%s' "$cfg" | grep -Eq 'proxy_pass[[:space:]]+[^;]*\$'                              && en_varproxy=1
en_mirror=0; printf '%s' "$cfg" | grep -Eq '^[[:space:]]*mirror[[:space:]]'                              && en_mirror=1
en_proxypass=0; printf '%s' "$cfg" | grep -Eq '^[[:space:]]*proxy_pass[[:space:]]'                       && en_proxypass=1
en_sslpre=0; printf '%s' "$cfg" | grep -Eq 'ssl_preread[[:space:]]+on'                                   && en_sslpre=1
en_alias=0;  printf '%s' "$cfg" | grep -Eq '^[[:space:]]*alias[[:space:]]'                                && en_alias=1
en_tryfiles=0; printf '%s' "$cfg" | grep -Eq '^[[:space:]]*try_files[[:space:]]'                          && en_tryfiles=1
# mail proxy: a mail block with proxy on and auth_http
en_mailproxy=0
printf '%s' "$cfg" | grep -Eq '^[[:space:]]*mail[[:space:]]*\{' \
	&& printf '%s' "$cfg" | grep -Eq 'proxy[[:space:]]+on' \
	&& printf '%s' "$cfg" | grep -Eq 'auth_http[[:space:]]' && en_mailproxy=1

# --- per-CVE verdicts -------------------------------------------------------
# A path is "exposed" only if the version is vulnerable AND the feature is on.
vuln=0
c123007="no"; c123633="no"; c121810="no"; c123634="no"; c113425="no"
# Each CVE has its own first-affected version (nginx.org ranges). Only flag a
# path when the version is in range for that specific CVE and not yet patched.
if [ "$version_status" = "vulnerable" ] && [ -n "$version" ]; then
	ver_ge "$version" 1.9.5  && [ "$en_http2" = 1 ] && { c123007="YES"; vuln=1; }
	ver_ge "$version" 1.19.7 && [ "$en_http2" = 1 ] && [ "$en_proxypass" = 1 ] && { c123633="YES"; vuln=1; }
	ver_ge "$version" 1.25.0 && [ "$en_http3" = 1 ] && [ "$en_proxypass" = 1 ] && { c121810="YES"; vuln=1; }
	ver_ge "$version" 0.6.18 && [ "$en_resolver" = 1 ] && { c123634="likely (resolver in use; confirm per-request proxy_pass + mirror/SSI)"; vuln=1; }
	ver_ge "$version" 0.5.33 && [ "$en_mailproxy" = 1 ] && { c113425="YES"; vuln=1; }
elif [ "$version_status" = "pre-http2" ] && [ -n "$version" ]; then
	# Older than 1.9.5: HTTP/2 CVEs do not apply, but resolver/mail can.
	ver_ge "$version" 0.6.18 && [ "$en_resolver" = 1 ] && { c123634="likely (resolver in use; confirm per-request proxy_pass + mirror/SSI)"; vuln=1; }
	ver_ge "$version" 0.5.33 && [ "$en_mailproxy" = 1 ] && { c113425="YES"; vuln=1; }
fi
# try_files + alias is the separate CVE-2026-125283 fixed in the same release
if [ "$en_alias" = 1 ] && [ "$en_tryfiles" = 1 ]; then
	add_note "alias and try_files both present: also review CVE-2026-125283 (fixed in the same 1.31.9 / 1.30.7 release)."
fi

# --- overall verdict / exit code -------------------------------------------
verdict=""; code=3
case "$version_status" in
	fixed)      verdict="Patched build (1.31.9 / 1.30.7 or later). Confirm the running worker was restarted."; code=2 ;;
	pre-http2)
		if [ "$vuln" = 1 ]; then
			verdict="Pre-HTTP/2 build with a resolver or mail-proxy path enabled. Affected. Upgrade."; code=1
		else
			verdict="Pre-HTTP/2 build: CVE-2026-123007 does not apply, but this release is old. Upgrade."; code=3
		fi ;;
	vulnerable)
		if [ "$vuln" = 1 ]; then
			verdict="Affected: a vulnerable version has at least one nginx2root feature enabled. Patch now."; code=1
		else
			verdict="Vulnerable version, but none of the five attack-path features are enabled in the dumped config. Patch anyway; confirm the dump is the running config."; code=0
		fi ;;
	*)          verdict="Could not read the nginx version. Check the binary and permissions."; code=3 ;;
esac

# --- output -----------------------------------------------------------------
if [ "$JSON" = 1 ]; then
	printf '{'
	printf '"tool":"nginx2root-check","source":%s,' "$(json_str "$source")"
	printf '"version":%s,"branch":%s,"version_status":%s,' "$(json_str "$version")" "$(json_str "$branch")" "$(json_str "$version_status")"
	printf '"modules":{"http2":%s,"http3":%s,"mail":%s,"stream_ssl_preread":%s},' \
		"$(yesno "$mod_http2" | sed 's/yes/true/;s/no/false/')" \
		"$(yesno "$mod_http3" | sed 's/yes/true/;s/no/false/')" \
		"$(yesno "$mod_mail" | sed 's/yes/true/;s/no/false/')" \
		"$(yesno "$mod_sslpre" | sed 's/yes/true/;s/no/false/')"
	printf '"enabled":{"http2":%s,"http3_quic":%s,"resolver":%s,"variable_proxy_pass":%s,"mirror":%s,"proxy_pass":%s,"mail_proxy":%s,"ssl_preread":%s,"alias":%s,"try_files":%s},' \
		"$(yesno "$en_http2" | sed 's/yes/true/;s/no/false/')" \
		"$(yesno "$en_http3" | sed 's/yes/true/;s/no/false/')" \
		"$(yesno "$en_resolver" | sed 's/yes/true/;s/no/false/')" \
		"$(yesno "$en_varproxy" | sed 's/yes/true/;s/no/false/')" \
		"$(yesno "$en_mirror" | sed 's/yes/true/;s/no/false/')" \
		"$(yesno "$en_proxypass" | sed 's/yes/true/;s/no/false/')" \
		"$(yesno "$en_mailproxy" | sed 's/yes/true/;s/no/false/')" \
		"$(yesno "$en_sslpre" | sed 's/yes/true/;s/no/false/')" \
		"$(yesno "$en_alias" | sed 's/yes/true/;s/no/false/')" \
		"$(yesno "$en_tryfiles" | sed 's/yes/true/;s/no/false/')"
	printf '"cves":{"CVE-2026-123007":%s,"CVE-2026-123633":%s,"CVE-2026-121810":%s,"CVE-2026-123634":%s,"CVE-2026-113425":%s},' \
		"$(json_str "$c123007")" "$(json_str "$c123633")" "$(json_str "$c121810")" "$(json_str "$c123634")" "$(json_str "$c113425")"
	printf '"verdict":%s,"exit_code":%d,"notes":[' "$(json_str "$verdict")" "$code"
	first=1; old_ifs=$IFS; IFS='|'
	for n in $notes; do [ "$first" = 1 ] || printf ','; json_str "$n"; first=0; done
	IFS=$old_ifs
	printf ']}\n'
else
	echo "nginx2root-check  (source: $source)"
	echo "nginx version:    ${version:-unknown} (branch ${branch:-unknown}) -> ${version_status}"
	echo "modules built:    http2=$(yesno $mod_http2) http3=$(yesno $mod_http3) mail=$(yesno $mod_mail) ssl_preread=$(yesno $mod_sslpre)"
	echo "features enabled: http2=$(yesno $en_http2) http3/quic=$(yesno $en_http3) resolver=$(yesno $en_resolver) proxy_pass=$(yesno $en_proxypass) mail_proxy=$(yesno $en_mailproxy) ssl_preread=$(yesno $en_sslpre)"
	echo "attack paths:"
	echo "  CVE-2026-123007 HTTP/2 flow control      : $c123007"
	echo "  CVE-2026-123633 HTTP/2 use-after-free     : $c123633"
	echo "  CVE-2026-121810 HTTP/3 use-after-free     : $c121810"
	echo "  CVE-2026-123634 resolver use-after-free   : $c123634"
	echo "  CVE-2026-113425 mail proxy use-after-free : $c113425"
	echo "verdict:          $verdict"
	if [ -n "$notes" ]; then
		echo "notes:"
		old_ifs=$IFS; IFS='|'
		for n in $notes; do echo "  - $n"; done
		IFS=$old_ifs
	fi
	echo "exit code:        $code"
fi
exit $code
