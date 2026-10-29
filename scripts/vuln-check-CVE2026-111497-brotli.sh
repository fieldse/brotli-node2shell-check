#!/bin/bash
# vuln-check-CVE2026-111497-brotli.sh
# Read-only exposure check for CVE-2026-111497 (Node2Shell / HTTP2Shell), the out-of-bounds write in
# Google's Brotli decoder. Compares host runtimes, packages under the scan roots, OS packages and
# (opt-in) local Docker or Podman images with the fixed versions in the vendor advisories, and looks for the fix marker
# string that fixed upstream decoder builds contain. Prints one PASS/FAIL/WARN/INFO/SKIP line per finding.
# Advisory: https://www.cve.org/CVERecord?id=CVE-2026-111497
set -euo pipefail

# Fixed releases as "branch=first-fixed-version", from the vendor advisories.
NODE_FIXED="22=22.23.4 24=24.22.1 26=26.12.1"
DOTNET_FIXED="8.0=8.0.33 9.0=9.0.22 10.0=10.0.14"
BROTLI_FIXED="1.0=1.0.10 1.1=1.1.1 1.2=1.2.1"
ENVOY_FIXED="1.36=1.36.12 1.37=1.37.8 1.38=1.38.6 1.39=1.39.3 1.40=1.40.0"
ISTIO_FIXED="1.29=1.29.9 1.30=1.30.6 1.31=1.31.2"
BROTLI_DEB_FIXED="1.0.9-2+deb12u1 1.1.0-2+deb13u1 1.2.0-4.1"
# Debian suite builds the security tracker lists as vulnerable (binNMU suffixes included).
BROTLI_DEB_VULN='^(1\.0\.9-2|1\.1\.0-2|1\.2\.0-4)(\+b[0-9]+)?$'
# First fixed dpkg build per release as "id:codename=version", from the Debian and Ubuntu trackers.
# Debian forky (and sid, which reports forky) is left out: no fix yet, so BROTLI_DEB_* decide.
BROTLI_DPKG_FIXED="debian:bookworm=1.0.9-2+deb12u1 debian:trixie=1.1.0-2+deb13u1
  ubuntu:xenial=1.0.3-1ubuntu1~16.04.2+esm1 ubuntu:bionic=1.0.3-1ubuntu1.3+esm1
  ubuntu:focal=1.0.7-6ubuntu0.1+esm1 ubuntu:jammy=1.0.9-2ubuntu0.1 ubuntu:noble=1.1.0-2ubuntu0.1
  ubuntu:resolute=1.2.0-3ubuntu0.1 ubuntu:stonking=1.2.0-4ubuntu0.1"
# Alpine releases whose secdb lists a CVE-2026-111497 fix, as "release=first-fixed-version".
BROTLI_APK_SECFIX="3.21=1.1.1-r0 edge=1.2.1-r0"
# Fixed decoders compile in the error name for the new check: 1.1+ as _ERROR_FORMAT_BLOCK_SWITCH,
# 1.0.x (including .NET 8's copy) as a bare NUL-terminated BLOCK_SWITCH. Matched per NUL-split line.
FIX_MARKER_RE='_ERROR_FORMAT_BLOCK_SWITCH|^BLOCK_SWITCH$'
FIX_MARKER_SRC="BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH"
# Seconds to wait for "docker info" / "podman info" before treating the engine as down.
ENGINE_TIMEOUT=5

ROOTS=""
DO_CONTAINERS=0
IMAGES=""
ENGINE=""
QUIET=0
STRICT=0
N_PASS=0
N_FAIL=0
N_WARN=0
N_INFO=0
N_SKIP=0
LAST_LEVEL=""
CHECK_NO="00"
NODE_STATE="unknown"
SYS_BROTLI="unknown"
HOST_OS=""
WORK=""
INDEX=""

# Show usage information
function usage() {
  cat <<EOF
Usage: $(basename "$0") [-r|--root ROOT]... [-c|--containers] [-i|--image IMAGE]... [-e|--engine ENGINE]
       [-q|--quiet] [-s|--strict] [-h|--help]

Read-only check for the Brotli decoder flaw CVE-2026-111497 (Node2Shell / HTTP2Shell).

Options:
  -r, --root ROOT   Directory to scan for package files and bundled copies (repeatable, default \$HOME).
                    Also accepts --root=ROOT
  -c, --containers  Also probe local Docker or Podman images (runs a version probe with --network=none)
  -i, --image IMAGE Probe only this local image (repeatable, implies -c)
  -e, --engine ENGINE
                    Container engine for -c: docker or podman. Also accepts --engine=ENGINE.
                    Default: docker if it responds within ${ENGINE_TIMEOUT}s, else podman
  -q, --quiet       Print only FAIL and WARN lines plus the summary
  -s, --strict      Exit 1 on WARN as well as FAIL
  -h, --help        Show this help

Output lines start with PASS, FAIL, WARN, INFO or SKIP, then the check number in brackets, then the subject,
location, found and fixed version.
FAIL means a known-vulnerable version. WARN means it needs a manual look (unknown version, distro build,
exposure path on an unpatched runtime). The fix marker is an error-name string fixed decoders compile in.
Upstream 1.0.10 / 1.1.1 / 1.2.1, the Debian and Ubuntu security builds and .NET 8.0.33 all carry it;
OS packages are still judged by version, and a missing marker in other builds is a WARN, not a FAIL.

Checks (the number printed on each line):
  00 header                           10 Java brotli4j
  01 OS packages                      11 Ruby brotli gem
  02 node and bun on PATH             12 Go modules
  03 nvm / volta / asdf / fnm Node    13 Rust crates
  04 .NET runtimes                    14 vendored decode.c sources
  05 Python dist-info / egg-info      15 bundled libbrotlidec copies
  06 Python compiled extensions       16 curl
  07 Python pins and lock files       17 Envoy, Istio, nginx
  08 host Python packages             18 container preflight and images (-c)
  09 npm middleware exposure

Exit codes: 0 no FAIL, 1 any FAIL (or WARN with --strict), 2 usage or environment error.

Examples:
  $(basename "$0") -r ~/src -r /srv -q
  $(basename "$0") --root=/srv --containers
  $(basename "$0") -e podman -i docker.io/library/node:24
EOF
}

# Print an error and exit with the environment-error code
function die() {
  echo "$(basename "$0"): $*" >&2
  exit 2
}

# Remove the temp directory on exit
function cleanup() {
  if [[ -n "$WORK" && -d "$WORK" ]]; then
    rm -rf "$WORK"
  fi
}

# Count and print one finding line, honouring quiet mode
function emit() {
  local level="$1"
  shift
  LAST_LEVEL="$level"
  case "$level" in
    PASS) N_PASS=$((N_PASS + 1)) ;;
    FAIL) N_FAIL=$((N_FAIL + 1)) ;;
    WARN) N_WARN=$((N_WARN + 1)) ;;
    INFO) N_INFO=$((N_INFO + 1)) ;;
    SKIP) N_SKIP=$((N_SKIP + 1)) ;;
  esac
  if [[ "$QUIET" -eq 1 && "$level" != "FAIL" && "$level" != "WARN" ]]; then
    return 0
  fi
  printf '%-4s  [%s] %s\n' "$level" "$CHECK_NO" "$*"
}

# Run one numbered check, tagging its output lines with the number
function run_check() {
  CHECK_NO="$1"
  "$2"
  CHECK_NO="00"
}

# True if the command exists and is not a macOS stub that would open an installer prompt
function have_cmd() {
  local c="$1" p
  p=$(command -v "$c" 2>/dev/null) || return 1
  if [[ "$(uname -s)" == "Darwin" && "$p" == /usr/bin/* ]]; then
    case "$c" in
      python3|otool) xcode-select -p >/dev/null 2>&1 || return 1 ;;
    esac
  fi
  return 0
}

# Lowercase a package name and turn underscores into dashes
function norm_name() {
  printf '%s\n' "$1" | tr '[:upper:]_' '[:lower:]-'
}

# Print dotted-numeric comparison as -1, 0 or 1, or "?" when either side is not dotted-numeric
function ver_cmp() {
  local a="$1" b="$2" re='^[0-9]+(\.[0-9]+)*$' n i x y
  local -a pa pb
  if ! [[ "$a" =~ $re ]] || ! [[ "$b" =~ $re ]]; then
    echo "?"
    return 0
  fi
  IFS=. read -r -a pa <<< "$a"
  IFS=. read -r -a pb <<< "$b"
  n=${#pa[@]}
  if [[ ${#pb[@]} -gt $n ]]; then
    n=${#pb[@]}
  fi
  for ((i = 0; i < n; i++)); do
    x=$((10#${pa[i]:-0}))
    y=$((10#${pb[i]:-0}))
    if ((x > y)); then
      echo 1
      return 0
    fi
    if ((x < y)); then
      echo -1
      return 0
    fi
  done
  echo 0
}

# Print a version without its prerelease (-rc.1, Go pseudo-version) and build (+meta) suffixes
function release_part() {
  local v="${1%%+*}"
  printf '%s\n' "${v%%-*}"
}

# Print ge, lt or unk for found against fixed
function classify() {
  case "$(ver_cmp "$1" "$2")" in
    "-1") echo lt ;;
    "0"|"1") echo ge ;;
    *) echo unk ;;
  esac
}

# Emit PASS, the given level, or WARN (not comparable) for one found-vs-fixed pair
function judge() {
  local subject="$1" where="$2" found="$3" fixed="$4" lt="$5" note="${6:-}" base
  base=$(release_part "$found")
  if [[ "$base" != "${found%%+*}" && "$(ver_cmp "$base" "$fixed")" == "0" ]]; then
    emit "$lt" "$subject [$where] found $found, a prerelease of the fixed $fixed${note:+ ($note)}"
    return 0
  fi
  case "$(classify "$base" "$fixed")" in
    ge) emit PASS "$subject [$where] found $found, fixed $fixed" ;;
    lt) emit "$lt" "$subject [$where] found $found, fixed $fixed${note:+ ($note)}" ;;
    *) emit WARN "$subject [$where] found $found, fixed $fixed: not comparable, check manually" ;;
  esac
  return 0
}

# Judge a version against the fixed release of its own branch (key = first DEPTH components)
function judge_branched() {
  local subject="$1" where="$2" found="$3" list="$4" depth="$5" lt="$6" unl="$7" note="${8:-}"
  local re='^[0-9]+(\.[0-9]+)*$' key entry k fixed highest="" base c
  base=$(release_part "$found")
  if ! [[ "$base" =~ $re ]]; then
    emit WARN "$subject [$where] found $found: not a plain dotted version, check manually"
    return 0
  fi
  key=$(printf '%s\n' "$base" | cut -d. -f1-"$depth")
  for entry in $list; do
    k=${entry%%=*}
    fixed=${entry#*=}
    if [[ "$k" == "$key" ]]; then
      judge "$subject" "$where" "$found" "$fixed" "$lt" "$note"
      return 0
    fi
    if [[ -z "$highest" || "$(ver_cmp "$fixed" "$highest")" == "1" ]]; then
      highest="$fixed"
    fi
  done
  c=$(ver_cmp "$base" "$highest")
  if [[ "$c" != "-1" && "$base" != "${found%%+*}" ]]; then
    emit WARN "$subject [$where] found $found, a prerelease on branch $key, which has no listed fix (highest listed fix $highest), check manually"
  elif [[ "$c" == "1" || "$c" == "0" ]]; then
    emit PASS "$subject [$where] found $found, newer than highest listed fix $highest"
  else
    emit "$unl" "$subject [$where] found $found, no fix for branch $key (highest listed fix $highest)${note:+ ($note)}"
  fi
  return 0
}

# Print yes if a file contains a compiled fix marker, else no
function has_marker() {
  if { LC_ALL=C tr '\000' '\n' < "$1" 2>/dev/null || true; } | LC_ALL=C grep -aqE -- "$FIX_MARKER_RE"; then
    echo yes
  else
    echo no
  fi
}

# Print the dpkg sort weight of one character (empty and digits weigh 0, ~ sorts first)
function deb_order() {
  local c="$1" n
  if [[ -z "$c" ]]; then echo 0; return 0; fi
  n=$(printf '%d' "'$c")
  if [[ "$c" == "~" ]]; then
    echo -1
  elif ((n >= 48 && n <= 57)); then
    echo 0
  elif ((n >= 65 && n <= 90)) || ((n >= 97 && n <= 122)); then
    echo "$n"
  else
    echo $((n + 256))
  fi
}

# Print -1, 0 or 1 comparing two upstream or revision strings with dpkg's verrevcmp rules
function deb_verrevcmp() {
  local a="$1" b="$2" ac bc da db
  while [[ -n "$a" || -n "$b" ]]; do
    while [[ ( -n "$a" && "${a:0:1}" != [0-9] ) || ( -n "$b" && "${b:0:1}" != [0-9] ) ]]; do
      ac=$(deb_order "${a:0:1}")
      bc=$(deb_order "${b:0:1}")
      if ((ac < bc)); then echo -1; return 0; fi
      if ((ac > bc)); then echo 1; return 0; fi
      a=${a:1}
      b=${b:1}
    done
    da=${a%%[^0-9]*}
    db=${b%%[^0-9]*}
    a=${a#"$da"}
    b=${b#"$db"}
    if ((10#${da:-0} < 10#${db:-0})); then echo -1; return 0; fi
    if ((10#${da:-0} > 10#${db:-0})); then echo 1; return 0; fi
  done
  echo 0
}

# Print -1, 0 or 1 comparing two Debian versions, with dpkg when present
function deb_vercmp() {
  local a="$1" b="$2" ea=0 eb=0 ra="" rb="" c
  if have_cmd dpkg; then
    if dpkg --compare-versions "$a" lt "$b"; then echo -1
    elif dpkg --compare-versions "$a" eq "$b"; then echo 0
    else echo 1; fi
    return 0
  fi
  if [[ "$a" == *:* ]]; then ea=${a%%:*}; a=${a#*:}; fi
  if [[ "$b" == *:* ]]; then eb=${b%%:*}; b=${b#*:}; fi
  if ((10#$ea != 10#$eb)); then
    if ((10#$ea < 10#$eb)); then echo -1; else echo 1; fi
    return 0
  fi
  if [[ "$a" == *-* ]]; then ra=${a##*-}; a=${a%-*}; fi
  if [[ "$b" == *-* ]]; then rb=${b##*-}; b=${b%-*}; fi
  c=$(deb_verrevcmp "$a" "$b")
  if [[ "$c" != "0" ]]; then echo "$c"; return 0; fi
  deb_verrevcmp "$ra" "$rb"
}

# Print -1, 0 or 1 comparing two Alpine versions (apk version -t when present), or "?"
function apk_vercmp() {
  local a="$1" b="$2" c
  if have_cmd apk; then
    case "$(apk version -t "$a" "$b" 2>/dev/null)" in
      "<") echo -1 ;;
      "=") echo 0 ;;
      ">") echo 1 ;;
      *) echo "?" ;;
    esac
    return 0
  fi
  c=$(ver_cmp "${a%-r*}" "${b%-r*}")
  if [[ "$c" != "0" ]]; then echo "$c"; return 0; fi
  if [[ "$a" != *-r* || "$b" != *-r* ]]; then echo "?"; return 0; fi
  ver_cmp "${a##*-r}" "${b##*-r}"
}

# Print the release key from an os-release file: id:codename, or alpine:MAJOR.MINOR / alpine:edge
function os_key() {
  local f="$1" id cn ver
  [[ -r "$f" ]] || return 0
  id=$(awk -F= '$1 == "ID" { gsub(/"/, "", $2); print $2; exit }' "$f")
  cn=$(awk -F= '$1 == "VERSION_CODENAME" { gsub(/"/, "", $2); print $2; exit }' "$f")
  if [[ -z "$cn" ]]; then
    cn=$(awk -F= '$1 == "UBUNTU_CODENAME" { gsub(/"/, "", $2); print $2; exit }' "$f")
  fi
  ver=$(awk -F= '$1 == "VERSION_ID" { gsub(/"/, "", $2); print $2; exit }' "$f")
  case "$id" in
    "") ;;
    alpine)
      if [[ "$ver" == *_alpha* ]]; then echo alpine:edge; else echo "alpine:$(printf '%s\n' "$ver" | cut -d. -f1-2)"; fi ;;
    *) echo "$id:$cn" ;;
  esac
  return 0
}

# Print the value for a key in a "key=value" list, or nothing
function list_get() {
  local entry
  for entry in $2; do
    if [[ "${entry%%=*}" == "$1" ]]; then
      echo "${entry#*=}"
      return 0
    fi
  done
  return 0
}

# Print yes if a binary dynamically links a libbrotli decoder, else no
function links_libbrotli() {
  local out=""
  if have_cmd ldd; then out=$(ldd "$1" 2>/dev/null || true); fi
  if [[ -z "$out" ]] && have_cmd otool; then out=$(otool -L "$1" 2>/dev/null || true); fi
  if [[ "$out" == *libbrotlidec* ]]; then echo yes; else echo no; fi
}

# Emit the version verdict for a node or bun binary that bundles its own decoder
function judge_runtime_version() {
  case "$1" in
    node) judge_branched node "$2" "$3" "$NODE_FIXED" 1 FAIL FAIL ;;
    bun) judge bun "$2" "$3" 1.4.4 FAIL "rebuild bun build --compile executables" ;;
  esac
}

# Emit one verdict for a runtime binary from how it gets its decoder: system library, fix marker or version
function judge_runtime() {
  local tool="$1" where="$2" v="$3" linked="$4" marker="$5" sys="$6"
  if [[ "$linked" == "yes" ]]; then
    case "$sys" in
      fixed) emit PASS "$tool [$where] $v links the system libbrotli, which the OS package check found fixed" ;;
      vulnerable) emit FAIL "$tool [$where] $v links the system libbrotli, which the OS package check found vulnerable" ;;
      *) emit WARN "$tool [$where] $v links the system libbrotli, whose patch state is unknown; check the OS brotli package changelog" ;;
    esac
  elif [[ "$marker" == "yes" ]]; then
    emit PASS "$tool [$where] $v bundles a decoder with the fix marker"
  else
    judge_runtime_version "$tool" "$where" "$v"
    if [[ "$LAST_LEVEL" == "PASS" && "$marker" == "no" ]]; then
      emit WARN "$tool [$where] version is fixed but the bundled decoder lacks the fix marker, check the build source"
    fi
  fi
  return 0
}

# Judge a runtime binary on the host or under a scan root
function judge_runtime_binary() {
  local tool="$1" where="$2" v="$3" bin="$4" linked=no marker=unknown
  if [[ -n "$bin" && -f "$bin" ]]; then
    linked=$(links_libbrotli "$bin")
    marker=$(has_marker "$bin")
  fi
  judge_runtime "$tool" "$where" "$v" "$linked" "$marker" "$SYS_BROTLI"
}

# Print the state a verdict level implies: fixed, vulnerable or unknown
function state_of() {
  case "$1" in
    PASS) echo fixed ;;
    FAIL) echo vulnerable ;;
    *) echo unknown ;;
  esac
}

# Print matching lines from the file index
function idx() {
  grep -E -- "$1" "$INDEX" || true
}

# Walk the scan roots once and record candidate files and directories
function build_index() {
  local root
  : > "$INDEX"
  while IFS= read -r root; do
    [[ -n "$root" ]] || continue
    find -H "$root" -xdev \
      \( -path '*/.git' -o -path '*/.Trash' -o -path '*/Library/Containers' -o -path '*/Library/Group Containers' \
         -o -path '*/Library/Mail' -o -path '*/Library/Messages' -o -path '*/Library/Safari' \
         -o -path '*/Library/CloudStorage' -o -path '*/Library/Mobile Documents' -o -path '*/.local/share/containers' \) -prune -o \
      \( -type d \( -path '*/.nvm/versions/node/v*' -o -path '*/.volta/tools/image/node/*' \
         -o -path '*/.asdf/installs/nodejs/*' -o -path '*/fnm/node-versions/v*' \) -print -prune \) -o \
      \( -name '*.dist-info' -type d -print -prune \) -o \( -name '*.egg-info' -print -prune \) -o \
      \( -type f \( -name package.json -o -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \
         -o -name bun.lock -o -name go.mod -o -name Cargo.lock -o -name Gemfile.lock -o -name pom.xml \
         -o -name 'build.gradle*' -o -name '*brotli4j*.jar' -o -name 'libbrotlidec*.so*' -o -name 'libbrotlidec*.dylib' \
         -o -name 'libbrotlidec*.a' -o -name '_brotli*.so' \
         -o -path '*/brotlicffi/*.so' -o -path '*/curl_cffi/*.so' -o -name decode.c -o -name decode.cpp \
         -o -name poetry.lock -o -name uv.lock -o -name pdm.lock -o -name 'requirements*.txt' \) -print \) \
      2>/dev/null >> "$INDEX" || true
  done <<< "$ROOTS"
}

# Print the version numbers of a package in a TOML-style lock file (Cargo.lock, poetry.lock, uv.lock, pdm.lock)
function lock_versions() {
  awk -v want="$2" '
    { sub(/\r$/, "") }
    /^name = / { n = $3; gsub(/"/, "", n); n = tolower(n); gsub(/_/, "-", n); next }
    /^version = / { v = $3; gsub(/"/, "", v); if (n == want) print v; n = "" }
  ' "$1" 2>/dev/null || true
}

# Print the version of a gem in Gemfile.lock
function gem_version() {
  tr -d '\r' < "$1" 2>/dev/null | sed -n "s/^ *$2 (\([0-9][^)]*\))\$/\1/p" | head -1 || true
}

# Print the version field of a package.json
function pkg_json_version() {
  sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -1 || true
}

# Print the fixed version of a tracked PyPI package, or nothing if not tracked
function py_fixed() {
  case "$1" in
    brotli) echo 1.2.1 ;;
    brotlicffi) echo 1.2.1.0 ;;
    curl-cffi) echo 0.17.0 ;;
  esac
  return 0
}

# Judge one PyPI package version against its fixed release; distro builds get WARN, not a version verdict
function py_judge() {
  local name="$1" ver="$2" where="$3" installer="${4:-pip}" fixed
  fixed=$(py_fixed "$name")
  [[ -n "$fixed" ]] || return 0
  case "$installer" in
    pip|uv|poetry|pdm|pipenv|"") judge "$name" "$where" "$ver" "$fixed" FAIL ;;
    unknown)
      case "$where" in
        */usr/lib/python3*|*/usr/lib64/python3*)
          emit INFO "$name [$where] found $ver from an OS package; its python3-brotli / py3-brotli package is judged under OS packages" ;;
        *) emit WARN "$name [$where] found $ver with no installer record, check where it came from (fixed $fixed)" ;;
      esac ;;
    *) emit WARN "$name [$where] found $ver installed by '$installer' (a distro or conda build that may carry a backport), check that package's changelog for CVE-2026-111497" ;;
  esac
}

# Parse the version token from a runtime's version output
function parse_rt_version() {
  case "$1" in
    node) printf '%s\n' "${2#v}" | awk '{print $1}' ;;
    bun) printf '%s\n' "$2" | awk '{print $1}' ;;
  esac
  return 0
}

# Check node and bun on the host PATH, by version and fix marker
function check_host_runtimes() {
  local tool bin line v
  for tool in node bun; do
    if ! have_cmd "$tool"; then
      emit INFO "$tool [host] not installed"
      continue
    fi
    bin=$("$tool" -p 'process.execPath' 2>/dev/null | head -1 || true)
    if [[ -z "$bin" || ! -f "$bin" ]]; then
      bin=$(command -v "$tool")
      bin="$(cd "$(dirname "$bin")" && pwd -P)/$(basename "$bin")"
    fi
    line=$("$tool" --version 2>/dev/null | head -1 || true)
    v=$(parse_rt_version "$tool" "$line" || true)
    if [[ -z "$v" ]]; then
      emit WARN "$tool [host] version output not recognised: $line"
      continue
    fi
    judge_runtime_binary "$tool" "host $bin" "$v" "$bin"
    if [[ "$tool" == "node" ]]; then
      NODE_STATE=$(state_of "$LAST_LEVEL")
    fi
  done
  return 0
}

# Judge Node.js versions installed by nvm, volta, asdf or fnm
function check_node_version_dirs() {
  local list p v n=0 bin
  list=$(idx '/(\.nvm/versions/node/v|\.volta/tools/image/node/|\.asdf/installs/nodejs/|fnm/node-versions/v)[0-9.]+(-[0-9A-Za-z.-]+)?$')
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    v=${p##*/}
    v=${v#v}
    bin="$p/bin/node"
    [[ -f "$bin" ]] || bin="$p/installation/bin/node"
    n=$((n + 1))
    judge_runtime_binary node "$p" "$v" "$bin"
  done <<< "$list"
  if [[ "$n" -eq 0 ]]; then
    emit INFO "node [version managers] no nvm, volta, asdf or fnm installs under scan roots"
  fi
  return 0
}

# Judge installed .NET runtimes (opt-in Brotli paths only)
function check_dotnet() {
  local name v
  have_cmd dotnet || return 0
  dotnet --list-runtimes 2>/dev/null > "$WORK/dotnet.txt" || true
  while read -r name v _; do
    [[ "$name" == "Microsoft.NETCore.App" ]] || continue
    if [[ "$v" == *-* ]]; then
      emit WARN ".NET runtime [host] found $v, a pre-release: fixed only from 11.0.0-rc.3.26522.148, check manually"
      continue
    fi
    judge_branched ".NET runtime" host "$v" "$DOTNET_FIXED" 2 FAIL FAIL "exposed only through Brotli decompression; rebuild self-contained apps"
  done < "$WORK/dotnet.txt"
  return 0
}

# Judge PyPI packages from installed dist-info and egg-info metadata under the scan roots
function scan_python_dist_info() {
  local list p base x name ver n=0
  list=$(idx '\.(dist|egg)-info$')
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    base=${p##*/}
    x=${base%.*-info}
    name=$(norm_name "${x%%-*}")
    ver=${x#*-}
    ver=${ver%%-*}
    [[ -n "$(py_fixed "$name")" ]] || continue
    n=$((n + 1))
    py_judge "$name" "$ver" "$p" "$(head -1 "$p/INSTALLER" 2>/dev/null || echo unknown)"
  done <<< "$list"
  if [[ "$n" -eq 0 ]]; then
    emit INFO "python [dist-info] none of Brotli, brotlicffi, curl_cffi installed under scan roots"
  fi
  return 0
}

# Report the fix marker in compiled Python extensions that bundle the decoder
function scan_python_extensions() {
  local p
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    if [[ "$(has_marker "$p")" == "yes" ]]; then
      emit PASS "python extension [$p] fix marker present"
    elif [[ "$(links_libbrotli "$p")" == "yes" ]]; then
      emit INFO "python extension [$p] links the system libbrotli; see OS packages"
    else
      emit WARN "python extension [$p] bundles a Brotli decoder without the fix marker, upgrade the owning package"
    fi
  done <<< "$(idx '/_brotli[^/]*\.so$|/brotlicffi/[^/]*\.so$|/curl_cffi/[^/]*\.so$')"
  return 0
}

# Judge pinned PyPI versions in requirements files and poetry.lock / uv.lock / pdm.lock
function scan_python_pins() {
  local list p line name rest ver n v
  list=$(idx '/requirements[^/]*\.txt$')
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    tr -d '\r' < "$p" 2>/dev/null | sed 's/[[:space:]]*\\$//' |
      grep -iE '^[[:space:]]*(brotli|brotlicffi|curl[-_]cffi)[[:space:]]*(==|>=|<=|~=|!=|>|<|;|\[|$)' > "$WORK/req.lines" 2>/dev/null || true
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      name=$(norm_name "$(printf '%s\n' "$line" | sed -E 's/^[[:space:]]*([A-Za-z0-9_.-]+).*/\1/')")
      rest=$(printf '%s\n' "$line" | sed -E 's/^[[:space:]]*[A-Za-z0-9_.-]+[[:space:]]*(\[[^]]*\])?[[:space:]]*//; s/[[:space:]]*(;|#|--hash).*$//')
      if [[ "$rest" == ==* ]]; then
        ver=${rest#==}
        py_judge "$name" "${ver// /}" "$p"
      else
        emit WARN "$name [$p] requirement '${rest:-unpinned}' is not an exact pin, check the installed version"
      fi
    done < "$WORK/req.lines"
  done <<< "$list"
  list=$(idx '/(poetry|uv|pdm)\.lock$')
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    for n in brotli brotlicffi curl-cffi; do
      for v in $(lock_versions "$p" "$n"); do
        py_judge "$n" "$v" "$p"
      done
    done
  done <<< "$list"
  return 0
}

# Print "name version installer location" for the host Python's Brotli packages, without importing them
function host_python_dists() {
  python3 -B -c '
import importlib.metadata as m
for d in m.distributions():
    n = (d.metadata["Name"] or "").lower().replace("_", "-")
    if n in ("brotli", "brotlicffi", "curl-cffi"):
        i = (d.read_text("INSTALLER") or "").strip() or "unknown"
        print(n, d.version, i, getattr(d, "_path", "?"))
' 2>/dev/null
}

# Judge Brotli packages in the host Python environment
function check_host_python_pkgs() {
  local n v i loc
  if have_cmd python3 && host_python_dists > "$WORK/py.txt"; then
    while read -r n v i loc; do
      [[ -n "$n" && -n "${v:-}" ]] || continue
      py_judge "$n" "$v" "host python $loc" "$i"
    done < "$WORK/py.txt"
  else
    emit SKIP "python [host] python3 not usable, host package check skipped"
  fi
  return 0
}

# Flag a project that feeds Brotli input to the runtime decoder, with the host Node.js state as context
function flag_exposure() {
  local level=WARN
  if [[ "$NODE_STATE" == "fixed" ]]; then level=INFO; fi
  emit "$level" "$1 [$2] $3: decodes Brotli input, safe only on a fixed runtime (host Node.js: $NODE_STATE)"
}

# True if a lockfile pins the package at the given major version (package-lock v1 to v3, nested installs included)
function lock_has_major() {
  local f="$1" pkg="$2" major="$3"
  case "$f" in
    */package-lock.json)
      { grep -A3 -E "\"(node_modules/[^\"]*/)?node_modules/$pkg\":|^[[:space:]]*\"$pkg\": \{" "$f" 2>/dev/null || true; } |
        grep -Eq "\"version\": \"$major\\." ;;
    *)
      grep -Eq "(^|[^A-Za-z0-9@_./-])/?${pkg}@(npm:)?[~^>=v ]*${major}[.0-9*x]" "$f" 2>/dev/null ;;
  esac
}

# Check npm declarations, installed node_modules copies and lockfiles for Brotli-decoding middleware
function scan_npm() {
  local list p name v spec others="koa-bodyparser @koa/bodyparser koa-body co-body @fastify/compress"
  list=$(idx 'package\.json$' | grep -v '/node_modules/' || true)
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    if grep -Eq '"express"[[:space:]]*:[[:space:]]*"[^0-9"]*5[^0-9]' "$p" 2>/dev/null; then flag_exposure "express 5" "$p" declared; fi
    if grep -Eq '"body-parser"[[:space:]]*:[[:space:]]*"[^0-9"]*2[^0-9]' "$p" 2>/dev/null; then flag_exposure "body-parser 2" "$p" declared; fi
    for spec in $others; do
      if grep -Fq "\"$spec\"" "$p" 2>/dev/null; then flag_exposure "$spec" "$p" declared; fi
    done
  done <<< "$list"

  list=$(idx '/node_modules/(express|body-parser|koa-bodyparser|@koa/bodyparser|koa-body|co-body|@fastify/compress)/package\.json$')
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    name=${p%/package.json}
    name=${name##*/node_modules/}
    v=$(pkg_json_version "$p")
    case "$name" in
      express) if [[ "${v%%.*}" == "5" ]]; then flag_exposure "express $v" "$p" installed; fi ;;
      body-parser) if [[ "${v%%.*}" == "2" ]]; then flag_exposure "body-parser $v" "$p" installed; fi ;;
      *) flag_exposure "$name $v" "$p" installed ;;
    esac
  done <<< "$list"

  list=$(idx '/(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock)$' | grep -v '/node_modules/' || true)
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    if lock_has_major "$p" express 5; then flag_exposure "express 5" "$p" locked; fi
    if lock_has_major "$p" body-parser 2; then flag_exposure "body-parser 2" "$p" locked; fi
    for spec in $others; do
      if grep -Eq "(^|[^A-Za-z0-9@_./-])/?$spec(@|\"|:|/| |,|\$)" "$p" 2>/dev/null; then flag_exposure "$spec" "$p" locked; fi
    done
  done <<< "$list"
  return 0
}

# Check Java: brotli4j in build files and jars
function scan_java() {
  local p v
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    grep -Fq 'brotli4j' "$p" 2>/dev/null || continue
    case "$p" in
      */pom.xml) v=$(grep -A3 'brotli4j' "$p" | sed -n 's#.*<version>\([^<]*\)</version>.*#\1#p' | head -1 || true) ;;
      *) v=$(grep -Eo 'brotli4j:[0-9][0-9.A-Za-z-]*' "$p" | head -1 | cut -d: -f2 || true) ;;
    esac
    if [[ -n "$v" ]]; then
      judge brotli4j "$p" "$v" 1.24.0 FAIL
    else
      emit WARN "brotli4j [$p] referenced, version not found, fixed 1.24.0"
    fi
  done <<< "$(idx '/pom\.xml$|/build\.gradle[^/]*$')"
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    v=$(printf '%s\n' "${p##*/}" | sed -n 's/.*brotli4j-\([0-9][0-9.]*\)\.jar$/\1/p')
    if [[ -n "$v" ]]; then
      judge brotli4j "$p" "$v" 1.24.0 FAIL
    else
      emit WARN "brotli4j [$p] jar version not found, fixed 1.24.0"
    fi
  done <<< "$(idx 'brotli4j[^/]*\.jar$')"
  return 0
}

# Check the Ruby brotli gem in Gemfile.lock
function scan_ruby() {
  local p v
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    v=$(gem_version "$p" brotli)
    if [[ -n "$v" ]]; then judge "brotli gem" "$p" "$v" 0.9.1 FAIL; fi
  done <<< "$(idx '/Gemfile\.lock$')"
  return 0
}

# Check Go modules for the cgo binding and the pure-Go decoder
function scan_go_mod() {
  local p v
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    if grep -Eq 'github\.com/google/brotli' "$p" 2>/dev/null; then
      emit WARN "go.mod [$p] uses github.com/google/brotli (cbrotli links the system libbrotli); rebuild after patching it"
    fi
    v=$(sed -n 's#^[[:space:]]*\(require[[:space:]]*\)\{0,1\}github\.com/andybalholm/brotli[[:space:]]*v\([0-9][0-9A-Za-z.+-]*\).*#\2#p' "$p" 2>/dev/null | head -1 || true)
    if [[ -n "$v" ]]; then
      judge andybalholm/brotli "$p" "$v" 1.2.7 WARN "pure Go, crash only (GHSA-c9gr-gmg4-2vqv, Low)"
    fi
  done <<< "$(idx '/go\.mod$')"
  return 0
}

# Check Rust crates in Cargo.lock
function scan_cargo() {
  local p n v
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    for n in brotli-sys brotli-src; do
      for v in $(lock_versions "$p" "$n"); do
        emit WARN "crate $n $v [$p] vendors the C decoder; no advisory exists, check the bundled source with this script's decode.c check"
      done
    done
    for n in brotli brotli-decompressor; do
      for v in $(lock_versions "$p" "$n"); do
        emit INFO "crate $n $v [$p] pure-Rust decoder, no advisory (not the affected C code)"
      done
    done
  done <<< "$(idx '/Cargo\.lock$')"
  return 0
}

# Find bundled Brotli decoder sources that lack the fix
function scan_decoder_sources() {
  local p
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    grep -q 'BrotliDecoderDecompressStream' "$p" 2>/dev/null || continue
    if grep -qF -- "$FIX_MARKER_SRC" "$p" 2>/dev/null; then
      emit PASS "brotli decoder source [$p] contains the fix"
    else
      emit FAIL "brotli decoder source [$p] lacks the fix ($FIX_MARKER_SRC missing), update the vendored copy to 1.0.10 / 1.1.1 / 1.2.1"
    fi
  done <<< "$(idx '/decode\.(c|cpp)$')"
  return 0
}

# Check libbrotlidec copies under the scan roots for the fix marker
function scan_bundled_libbrotli() {
  local p
  while IFS= read -r p; do
    [[ -n "$p" && -f "$p" && ! -L "$p" ]] || continue
    if [[ "$(has_marker "$p")" == "yes" ]]; then
      emit PASS "libbrotlidec [$p] fix marker present"
    else
      emit WARN "libbrotlidec [$p] no fix marker; fixed upstream, Debian and Ubuntu builds carry it, so update the owning app or check its build source"
    fi
  done <<< "$(idx '/libbrotlidec[^/]*\.(so[.0-9]*|dylib|a)$')"
  return 0
}

# Print the upstream part of a Debian version (no epoch, no revision)
function deb_upstream() {
  local v="${1#*:}"
  if [[ "$1" != *:* ]]; then v="$1"; fi
  printf '%s\n' "${v%-*}"
}

# Print a package's upstream version: no epoch, release (after the last -), brew _N revision or +repack suffix
function pkg_upstream() {
  local v="$1" mgr="$2"
  v=${v#[0-9]*:}
  if [[ "$mgr" != "brew" && "$mgr" != "distro" ]]; then v=${v%-*}; fi
  if [[ "$mgr" == "brew" ]]; then v=${v%_*}; fi
  printf '%s\n' "${v%%+*}"
}

# Judge a dpkg build against the fixed build of its Debian or Ubuntu release; returns 1 if the release is not
# listed or the build is from another upstream line (a foreign-release package)
function judge_dpkg_release() {
  local name="$1" where="$2" full="$3" os="$4" fixed note=""
  fixed=$(list_get "$os" "$BROTLI_DPKG_FIXED")
  [[ -n "$fixed" ]] || return 1
  [[ "$(deb_upstream "$full")" == "$(deb_upstream "$fixed")" ]] || return 1
  if [[ "$fixed" == *+esm* ]]; then note=" (Ubuntu Pro ESM)"; fi
  case "$(deb_vercmp "$full" "$fixed")" in
    "-1") emit FAIL "$name [$where] found $full, $os fixed in $fixed$note" ;;
    "0"|"1") emit PASS "$name [$where] found $full, $os fixed in $fixed$note" ;;
    *) emit WARN "$name [$where] found $full, $os fixed in $fixed$note: not comparable, check manually" ;;
  esac
  return 0
}

# Judge an Alpine build: secdb fix for its release if listed and on the same upstream line, else the upstream
# version (Alpine ships upstream releases)
function judge_apk() {
  local name="$1" where="$2" full="$3" os="$4" rel fixed up
  rel=${os#alpine:}
  fixed=$(list_get "$rel" "$BROTLI_APK_SECFIX")
  up=${full%-r*}
  if [[ "$os" == alpine:* && -n "$fixed" ]] &&
      [[ "$(printf '%s\n' "$up" | cut -d. -f1-2)" == "$(printf '%s\n' "${fixed%-r*}" | cut -d. -f1-2)" ]]; then
    case "$(apk_vercmp "$full" "$fixed")" in
      "-1") emit FAIL "$name [$where] found $full, Alpine $rel secdb lists the fix in $fixed" ;;
      "0"|"1") emit PASS "$name [$where] found $full, Alpine $rel secdb lists the fix in $fixed" ;;
      *) emit WARN "$name [$where] found $full, Alpine $rel fixed in $fixed: not comparable, check manually" ;;
    esac
    return 0
  fi
  judge_branched "$name $full" "$where" "$up" "$BROTLI_FIXED" 2 FAIL FAIL "no CVE-2026-111497 secfix for this upstream line on ${os:-this Alpine release}"
}

# Judge a system libbrotli package by release tracker, known builds, or the upstream fixed releases
function judge_brotli_pkg() {
  local name="$1" where="$2" full="$3" mgr="$4" os="${5:-}" up lt
  if [[ "$mgr" == "dpkg" && "$full" =~ $BROTLI_DEB_VULN ]]; then
    emit FAIL "$name [$where] found $full, a Debian build the security tracker lists as vulnerable (fixed: 1.0.9-2+deb12u1, 1.1.0-2+deb13u1, 1.2.0-4.1)"
    return 0
  fi
  if [[ "$mgr" == "dpkg" ]] && judge_dpkg_release "$name" "$where" "$full" "$os"; then
    return 0
  fi
  if [[ "$mgr" == "apk" ]]; then
    judge_apk "$name" "$where" "$full" "$os"
    return 0
  fi
  case " $BROTLI_DEB_FIXED " in
    *" $full "*) emit PASS "$name [$where] found $full, known fixed Debian build"; return 0 ;;
  esac
  if ! [[ "$(pkg_upstream "$full" "$mgr")" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
    emit WARN "$name [$where] found $full, not a plain release version (a prerelease sorts below its release), check the package changelog for CVE-2026-111497"
    return 0
  fi
  up=$(printf '%s\n' "$full" | sed -E 's/^[0-9]+://; s/^([0-9]+(\.[0-9]+)*).*/\1/')
  if [[ "$mgr" == "brew" ]]; then lt=FAIL; else lt=WARN; fi
  judge_branched "$name $full" "$where" "$up" "$BROTLI_FIXED" 2 "$lt" "$lt" "distro builds may backport the fix, check the package changelog for CVE-2026-111497"
}

# Print the OS packages that carry the Brotli library as "manager name version"
function list_os_packages() {
  if have_cmd dpkg-query; then
    dpkg-query -W -f='dpkg ${Package} ${Version} ${db:Status-Abbrev}\n' 'libbrotli*' brotli python3-brotli 2>/dev/null | awk '$4 ~ /^ii/ {print $1, $2, $3}' || true
  fi
  if have_cmd apk; then
    apk info -v 2>/dev/null | grep -E '^(py3-)?brotli[a-z-]*-[0-9]' | sed -n 's/^\(.*\)-\([0-9][^-]*-r[0-9]*\)$/apk \1 \2/p' || true
  fi
  if have_cmd rpm; then
    rpm -qa --qf 'rpm %{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | grep -E '^rpm (brotli|libbrotli|python3-brotli )' || true
  fi
  if have_cmd pacman; then
    pacman -Q brotli 2>/dev/null | sed 's/^/pacman /' || true
  fi
  if have_cmd brew; then
    HOMEBREW_NO_AUTO_UPDATE=1 brew list --versions brotli 2>/dev/null | awk '{for (i = 2; i <= NF; i++) print "brew", $1, $i}' || true
  fi
  return 0
}

# Check OS packages through whichever package manager exists on the host
function check_os_packages() {
  local mgr name ver n=0 f
  for f in /etc/os-release /usr/lib/os-release; do
    if [[ -r "$f" ]]; then HOST_OS=$(os_key "$f"); break; fi
  done
  list_os_packages > "$WORK/pk.txt"
  while read -r mgr name ver; do
    [[ -n "$name" && -n "${ver:-}" ]] || continue
    n=$((n + 1))
    judge_brotli_pkg "$name" host "$ver" "$mgr" "$HOST_OS"
    case "$name" in
      libbrotli1|libbrotli|brotli|brotli-libs|libbrotlidec*)
        case "$LAST_LEVEL" in
          FAIL) SYS_BROTLI="vulnerable" ;;
          PASS) if [[ "$SYS_BROTLI" == "unknown" ]]; then SYS_BROTLI="fixed"; fi ;;
        esac ;;
    esac
  done < "$WORK/pk.txt"
  if [[ "$n" -eq 0 ]]; then
    emit INFO "os [packages] no Brotli library package found"
  fi
  return 0
}

# Check the curl binary's linked Brotli version
function check_curl_brotli() {
  local v
  have_cmd curl || return 0
  v=$(curl -V 2>/dev/null | grep -Eo 'brotli/[0-9.]+' | head -1 | cut -d/ -f2 || true)
  if [[ -n "$v" && "$SYS_BROTLI" != "unknown" && "$(links_libbrotli "$(command -v curl)")" == "yes" ]]; then
    if [[ "$SYS_BROTLI" == "fixed" ]]; then
      emit PASS "curl [host] links the system libbrotli, which the OS package check found fixed (curl -V shows the upstream version $v)"
    else
      emit FAIL "curl [host] links the system libbrotli, which the OS package check found vulnerable"
    fi
    emit INFO "curl [host] decodes Brotli responses, so git-remote-https and other libcurl users follow the library's state"
  elif [[ -n "$v" ]]; then
    judge_brotli_pkg "curl links brotli" host "$v" distro
    emit INFO "curl [host] decodes Brotli responses, so git-remote-https and other libcurl users are exposed until the library is fixed"
  else
    emit INFO "curl [host] built without Brotli"
  fi
  return 0
}

# Check Envoy and Istio versions and configs that enable Brotli decompression
function check_proxies() {
  local v p
  if have_cmd envoy; then
    v=$(envoy --version 2>/dev/null | sed -n 's#.*/\([0-9][0-9.]*\)/.*#\1#p' | head -1 || true)
    if [[ -n "$v" ]]; then
      judge_branched envoy host "$v" "$ENVOY_FIXED" 2 WARN WARN "affected only with the Brotli decompressor configured"
    fi
  fi
  if have_cmd istioctl; then
    v=$(istioctl version --remote=false 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
    if [[ -n "$v" ]]; then
      judge_branched "istioctl (client)" host "$v" "$ISTIO_FIXED" 2 WARN WARN "check the control plane version too; affected only with Brotli decompression enabled"
    fi
  fi
  for p in /etc/envoy /etc/istio; do
    [[ -d "$p" ]] || continue
    if grep -rIqi 'brotli' "$p" 2>/dev/null; then
      emit WARN "proxy config [$p] mentions brotli, confirm Envoy >= 1.40.0 / 1.39.3 / 1.38.6 / 1.37.8 / 1.36.12 and Istio >= 1.31.2 / 1.30.6 / 1.29.9"
    fi
  done
  if [[ -d /etc/nginx ]] && grep -rIqi brotli /etc/nginx 2>/dev/null; then
    emit INFO "nginx config [/etc/nginx] mentions brotli; ngx_brotli only compresses and is not affected"
  fi
  return 0
}

# Print the in-container probe script (POSIX sh) that lists the OS release, runtimes, markers, Python and OS packages
function probe_script() {
  cat <<'EOF'
for f in /etc/os-release /usr/lib/os-release; do
  [ -r "$f" ] || continue
  grep -E '^(ID|VERSION_ID|VERSION_CODENAME|UBUNTU_CODENAME)=' "$f" | sed 's/^/OSR /'
  break
done
for t in node bun; do
  command -v "$t" >/dev/null 2>&1 || continue
  b=$("$t" -p 'process.execPath' 2>/dev/null) || b=""
  [ -f "$b" ] || b=$(command -v "$t")
  m=0; tr '\000' '\n' < "$b" 2>/dev/null | grep -aqE '_ERROR_FORMAT_BLOCK_SWITCH|^BLOCK_SWITCH$' && m=1
  l=0; ldd "$b" 2>/dev/null | grep -q libbrotlidec && l=1
  echo "RT $t $m $l $("$t" --version 2>&1 | head -1)"
done
if command -v python3 >/dev/null 2>&1; then
  python3 -B -c 'import importlib.metadata as m
for d in m.distributions():
    n = (d.metadata["Name"] or "").lower().replace("_", "-")
    if n in ("brotli", "brotlicffi", "curl-cffi"):
        print("PY", n, d.version, (d.read_text("INSTALLER") or "").strip() or "unknown", getattr(d, "_path", "?"))' 2>/dev/null
fi
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='PKG dpkg ${Package} ${Version} ${db:Status-Abbrev}\n' 'libbrotli*' brotli python3-brotli 2>/dev/null | awk '$5 ~ /^ii/ {print $1, $2, $3, $4}'
fi
if command -v apk >/dev/null 2>&1; then
  apk info -v 2>/dev/null | grep -E '^(py3-)?brotli[a-z-]*-[0-9]' | sed -n 's/^\(.*\)-\([0-9][^-]*-r[0-9]*\)$/PKG apk \1 \2/p'
fi
if command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf 'PKG rpm %{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | grep -E '^PKG rpm (brotli|libbrotli|python3-brotli )'
fi
exit 0
EOF
}

# Judge the probe output of one image: OS packages first, so linked runtimes inherit their state
function apply_probe() {
  local img="$1" f="$2" kind a b c rest v where sys=unknown linked marker os
  where="image:$img"
  sed -n 's/^OSR //p' "$f" > "$WORK/osr.txt"
  os=$(os_key "$WORK/osr.txt")
  while IFS=' ' read -r kind a b c rest; do
    [[ "$kind" == "PKG" && -n "$c" ]] || continue
    judge_brotli_pkg "$b" "$where" "$c" "$a" "$os"
    case "$b" in
      libbrotli1|libbrotli|brotli|brotli-libs|libbrotlidec*)
        case "$LAST_LEVEL" in
          FAIL) sys=vulnerable ;;
          PASS) if [[ "$sys" == "unknown" ]]; then sys=fixed; fi ;;
        esac ;;
    esac
  done < "$f"
  while IFS=' ' read -r kind a b c rest; do
    case "$kind" in
      RT)
        v=$(parse_rt_version "$a" "$rest" || true)
        [[ "$v" =~ ^[0-9]+\.[0-9] ]] || continue
        if [[ "$c" == "1" ]]; then linked=yes; else linked=no; fi
        if [[ "$b" == "1" ]]; then marker=yes; else marker=no; fi
        judge_runtime "$a" "$where" "$v" "$linked" "$marker" "$sys" ;;
      PY) py_judge "$a" "$b" "$where ${rest:-?}" "$c" ;;
    esac
  done < "$f"
  return 0
}

# Probe every listed local image with the chosen engine, networking off
function check_containers() {
  local img probe
  probe=$(probe_script)
  while IFS= read -r img; do
    [[ -n "$img" && "$img" != *"<none>"* ]] || continue
    if "$ENGINE" run --rm --network=none --pull=never --cap-drop=ALL --entrypoint sh "$img" -c "$probe" \
        > "$WORK/probe.out" 2>/dev/null < /dev/null; then
      apply_probe "$img" "$WORK/probe.out"
    else
      emit SKIP "image:$img has no shell or the probe failed, not inspected"
    fi
  done < "$WORK/images.txt"
  return 0
}

# Fail early if a core utility the checks rely on is missing
function require_tools() {
  local t
  for t in find grep sed awk tr cut head ls mktemp rm uname dirname basename; do
    command -v "$t" >/dev/null 2>&1 || die "required utility not found: $t"
  done
}

# Run a command with output discarded, killing it after the given seconds (returns 124 on timeout)
function run_timeout() {
  local secs="$1" pid ticks=0 rc=0
  shift
  "$@" >/dev/null 2>&1 < /dev/null &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if ((ticks >= secs * 10)); then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 124
    fi
    sleep 0.1
    ticks=$((ticks + 1))
  done
  wait "$pid" || rc=$?
  return "$rc"
}

# True if the engine is on PATH and its daemon or service answers "info" in time
function engine_responds() {
  have_cmd "$1" || return 1
  run_timeout "$ENGINE_TIMEOUT" "$1" info
}

# Print the first engine that responds, docker before podman
function detect_engine() {
  local e
  for e in docker podman; do
    if engine_responds "$e"; then
      echo "$e"
      return 0
    fi
  done
  return 1
}

# Choose the container engine and write the image list; ENGINE is left empty when none is usable
function preflight_containers() {
  local img
  if [[ -n "$ENGINE" ]]; then
    if ! engine_responds "$ENGINE"; then
      emit SKIP "containers [engine] $ENGINE (set with --engine) not found or not responding within ${ENGINE_TIMEOUT}s, image checks skipped"
      ENGINE=""
      return 0
    fi
    emit INFO "containers [engine] using $ENGINE (set with --engine)"
  elif ENGINE=$(detect_engine); then
    emit INFO "containers [engine] using $ENGINE (first of docker, podman to respond)"
  else
    ENGINE=""
    emit SKIP "containers [engine] neither docker nor podman found or responding within ${ENGINE_TIMEOUT}s, image checks skipped"
    return 0
  fi
  if [[ -n "$IMAGES" ]]; then
    while IFS= read -r img; do
      [[ -n "$img" ]] || continue
      "$ENGINE" image inspect "$img" >/dev/null 2>&1 || die "image not found locally in $ENGINE: $img"
    done <<< "$IMAGES"
    printf '%s' "$IMAGES" > "$WORK/images.txt"
    return 0
  fi
  "$ENGINE" images --format '{{.Repository}}:{{.Tag}}' > "$WORK/images.txt" 2>"$WORK/engine.err" ||
    die "$ENGINE images failed: $(head -1 "$WORK/engine.err")"
}

# Print the final counts and return the exit code
function summarize() {
  printf 'SUMMARY pass=%d fail=%d warn=%d info=%d skip=%d' "$N_PASS" "$N_FAIL" "$N_WARN" "$N_INFO" "$N_SKIP"
  if [[ "$DO_CONTAINERS" -eq 1 ]]; then
    printf ' engine=%s' "${ENGINE:-none}"
  fi
  printf '\n'
  if ((N_FAIL > 0)); then return 1; fi
  if ((STRICT == 1 && N_WARN > 0)); then return 1; fi
  return 0
}

# Parse command-line options into the global settings
function parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -r|--root)
        if [[ $# -lt 2 || -z "$2" ]]; then echo "Option $1 needs an argument" >&2; usage >&2; exit 2; fi
        ROOTS="${ROOTS}$2"$'\n'
        shift 2 ;;
      --root=*)
        if [[ -z "${1#--root=}" ]]; then echo "Option --root needs an argument" >&2; usage >&2; exit 2; fi
        ROOTS="${ROOTS}${1#--root=}"$'\n'
        shift ;;
      -c|--containers) DO_CONTAINERS=1; shift ;;
      -i|--image)
        if [[ $# -lt 2 || -z "$2" ]]; then echo "Option $1 needs an argument" >&2; usage >&2; exit 2; fi
        IMAGES="${IMAGES}$2"$'\n'
        DO_CONTAINERS=1
        shift 2 ;;
      -e|--engine)
        if [[ $# -lt 2 || -z "$2" ]]; then echo "Option $1 needs an argument" >&2; usage >&2; exit 2; fi
        ENGINE="$2"
        shift 2 ;;
      --engine=*)
        if [[ -z "${1#--engine=}" ]]; then echo "Option --engine needs an argument" >&2; usage >&2; exit 2; fi
        ENGINE="${1#--engine=}"
        shift ;;
      -q|--quiet) QUIET=1; shift ;;
      -s|--strict) STRICT=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1 (try --help)" >&2; usage >&2; exit 2 ;;
    esac
  done
  case "$ENGINE" in
    ""|docker|podman) ;;
    *) echo "Option --engine must be docker or podman, got: $ENGINE" >&2; usage >&2; exit 2 ;;
  esac
}

# Default the scan roots to $HOME, then resolve each to a unique absolute path
function resolve_roots() {
  local root resolved=""
  if [[ -z "$ROOTS" ]]; then
    ROOTS="$HOME"$'\n'
  fi
  while IFS= read -r root; do
    [[ -n "$root" ]] || continue
    [[ -d "$root" ]] || die "scan root is not a directory: $root"
    root=$(cd "$root" && pwd -P)
    case $'\n'"$resolved" in *$'\n'"$root"$'\n'*) continue ;; esac
    resolved="${resolved}${root}"$'\n'
  done <<< "$ROOTS"
  ROOTS="$resolved"
}

# Create the temp work directory and set the environment the checks run in
function prepare_run() {
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/brotli-check.XXXXXX") || die "cannot create a temp directory"
  trap cleanup EXIT
  INDEX="$WORK/index.txt"
  cd /
  export PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
}

# Run every host, package and container check in order
function run_checks() {
  emit INFO "CVE-2026-111497 (Brotli) check; scan roots: $(printf '%s' "$ROOTS" | tr '\n' ' ')containers=$DO_CONTAINERS"
  if [[ "$DO_CONTAINERS" -eq 1 ]]; then
    run_check 18 preflight_containers
  fi
  build_index

  run_check 01 check_os_packages
  run_check 02 check_host_runtimes
  run_check 03 check_node_version_dirs
  run_check 04 check_dotnet
  run_check 05 scan_python_dist_info
  run_check 06 scan_python_extensions
  run_check 07 scan_python_pins
  run_check 08 check_host_python_pkgs
  run_check 09 scan_npm
  run_check 10 scan_java
  run_check 11 scan_ruby
  run_check 12 scan_go_mod
  run_check 13 scan_cargo
  run_check 14 scan_decoder_sources
  run_check 15 scan_bundled_libbrotli
  run_check 16 check_curl_brotli
  run_check 17 check_proxies
  if [[ "$DO_CONTAINERS" -eq 1 && -n "$ENGINE" ]]; then
    run_check 18 check_containers
  fi
}

# Parse arguments, run the checks, print the summary
function main() {
  parse_args "$@"
  require_tools
  resolve_roots
  prepare_run
  run_checks
  summarize
}

main "$@"
