# HTTP2Shell / Node2Shell exposure check (CVE-2026-111497)

**Is your service exposed to HTTP2Shell?** It's a remote code execution bug in Google's Brotli decoder, under active attack. It affects Node.js, Bun, Python, .NET, Java, curl, Envoy and OS `libbrotli` packages.

- **Check by hand:** [read the guide](https://fieldse.github.io/brotli-node2shell-check/) for the command and fixed version for each stack. Every version it gives is sourced in the [version references](https://fieldse.github.io/brotli-node2shell-check/references.html).
- **Check automatically:** run the read-only script in [Quick start](#quick-start).

## Contents

- [Quick start](#quick-start)
- [Script checks](#script-checks)
- [Manual testing](#manual-testing): [Debian 12](#debian-12), [Ubuntu 22.04](#ubuntu-2204), [Python](#python), [Node.js](#nodejs)
- [FAQ](#faq)

## Quick start

```bash
git clone https://github.com/fieldse/brotli-node2shell-check.git
cd brotli-node2shell-check
./scripts/vuln-check-CVE2026-111497-brotli.sh -r ~/src -q    # scan a source tree, report problems only
./scripts/vuln-check-CVE2026-111497-brotli.sh -x ~/private   # default roots, skipping one directory
./scripts/vuln-check-CVE2026-111497-brotli.sh --help         # all options
```

With no `-r`, the script scans `$HOME`, the Homebrew prefix (`/opt/homebrew` or `/usr/local`) and, on macOS, `/Applications`. Homebrew formulae vendor their own Python packages and Perl modules, casks bundle PyInstaller apps, and app bundles carry their own Node.js and Electron builds, so a `$HOME`-only scan misses them. A root nested inside another root is walked once.

`-x DIR` keeps the scan out of a directory and everything under it. If `DIR` is a symlink, its target is excluded too, and no check reads a file through a symlink that leads into an excluded directory. Host tools that live inside `DIR` are reported as `SKIP` and not run: `node`, `bun`, `brew` (also when its prefix is excluded), `dotnet`, `curl`, `envoy` and `istioctl`. The host Python check leaves out `sys.path` entries inside `DIR`. On macOS the match ignores case. An exclude that resolves to `/` is a usage error.

`-d` also searches every executable and library inside `.app` bundles for an embedded decoder, which takes minutes on a full `/Applications`.

`FAIL` means a known-vulnerable version, and `WARN` needs manual review. The script exits 0 when nothing fails, 1 on any `FAIL` (or any `WARN` with `--strict`), and 2 on a usage error, so it can gate CI. See [how the script is tested](https://fieldse.github.io/brotli-node2shell-check/tests.html).

## Script checks

Each output line reads `LEVEL [NN] message`, where `NN` is the check that produced it. The numbers are stable.

In `-c` / `-i` mode the script checks only an image's OS packages, the `node` and `bun` on its PATH and the system Python's packages. It doesn't look at virtualenvs, `node_modules`, version-manager installs, .NET runtimes, jars, bundled libbrotlidec copies or vendored source inside images.

| No. | Check |
|---|---|
| 00 | Header |
| 01 | OS packages (dpkg, apk, rpm, pacman, Homebrew) |
| 02 | `node` and `bun` on PATH |
| 03 | Node.js installs from nvm, volta, asdf, fnm |
| 04 | .NET runtimes |
| 05 | Python dist-info and egg-info metadata |
| 06 | Python compiled extensions and Perl `IO::Compress::Brotli` |
| 07 | Python pins in requirements files, poetry.lock, uv.lock, pdm.lock |
| 08 | Host Python packages |
| 09 | npm middleware that decodes Brotli |
| 10 | Java brotli4j |
| 11 | Ruby brotli gem |
| 12 | Go modules |
| 13 | Rust crates |
| 14 | Vendored decoder sources (`decode.c`) |
| 15 | Bundled libbrotlidec copies (without the fix marker, the file name's version decides: FAIL from 1.0.3 up to the fix) |
| 16 | curl |
| 17 | Envoy, Istio, nginx |
| 18 | Container engine preflight and images (`-c`, `-i`) |
| 19 | Other `node` binaries bundled by apps and tools, judged by their embedded release version without running them (WARN when the release URLs in one binary disagree) |
| 20 | Electron apps, judged by the Electron version in the framework's `Info.plist` (see [Electron fixed versions](#electron-fixed-versions)) |
| 21 | Executables and libraries inside `.app` bundles (`-d`). The fix marker alone gives WARN at most, because linkers merge identical strings |

### Electron fixed versions

Every Electron release from 42.0.0 on is fixed. Every release below 42 is vulnerable and gets FAIL. Electron 46 prereleases get WARN until 46.0.0 ships.

- **Chromium's copy decides.** Electron builds its Node.js against Chromium's Brotli (`//third_party/brotli:dec`), not Node's `deps/brotli` ([`patches/node/build_add_gn_build_files.patch`](https://github.com/electron/electron/blob/42-x-y/patches/node/build_add_gn_build_files.patch)). Electron's later Node 24.22.1 bumps don't change the decoder.
- **Fix commit.** The fix is Brotli commit [0ed4268a](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b), cherry-picked into 1.0.10, 1.1.1 and 1.2.1.
- **Chromium 148.** Chromium rolled Brotli to `cfa184a` in [224140d410](https://github.com/chromium/chromium/commit/224140d410af003ca0266a3328accaabd24329f9) (`main@{#1603247}`, 2026-03-23). `cfa184a` [contains 0ed4268a](https://github.com/google/brotli/compare/0ed4268a44...cfa184a997ac19454d5a3ae97f6d600aac2445a6). Chromium 148 branched at `#1610480` ([Chromium Dash milestones](https://chromiumdash.appspot.com/fetch_milestones)).
- **Electron 42.** Electron 42.0.0 ships Chromium 148.0.7778.96 ([releases.json](https://releases.electronjs.org/releases.json)), whose [`third_party/brotli/README.chromium`](https://github.com/chromium/chromium/blob/148.0.7778.96/third_party/brotli/README.chromium) records `cfa184a`. Electron 43, 44 and 45 ship Chromium 150, 152 and 156.
- **Electron 41 and older.** Electron 41.10.7, the last 41 release, ships Chromium 146.0.7680.216, whose [Brotli revision](https://github.com/chromium/chromium/blob/146.0.7680.216/third_party/brotli/README.chromium) `9801a2c` predates the fix. The 39, 40 and 41 branches carry no Brotli patch of their own.
- **Cross-check.** Real Electron 42.4.1, 43.x and 44.x frameworks contain the `_ERROR_FORMAT_BLOCK_SWITCH` marker. Electron 30.0.1 and 39.8.7 contain only the unfixed 1.0.x error names.

## Manual testing

Run the script against a known-vulnerable container, from the repository root:

- Vulnerable build: `FAIL`, exit 1.
- After the upgrade: `PASS`, exit 0.
- `-r /root` scans the container's real home directory. Nothing is planted.

### Debian 12

```bash
docker run --rm -it -v "$PWD/scripts/vuln-check-CVE2026-111497-brotli.sh":/check.sh:ro debian:bookworm-slim bash
# inside the container
apt-get update && apt-get install -y libbrotli1=1.0.9-2+b6
bash /check.sh -r /root                        # FAIL [01] libbrotli1
apt-get install -y --only-upgrade libbrotli1   # 1.0.9-2+deb12u1
bash /check.sh -r /root                        # PASS [01] libbrotli1
```

### Ubuntu 22.04

```bash
docker run --rm -it -v "$PWD/scripts/vuln-check-CVE2026-111497-brotli.sh":/check.sh:ro ubuntu:22.04 bash
# inside the container
apt-get update && apt-get install -y libbrotli1=1.0.9-2build6
bash /check.sh -r /root                        # FAIL [01] libbrotli1
apt-get install -y --only-upgrade libbrotli1   # 1.0.9-2ubuntu0.1
bash /check.sh -r /root                        # PASS [01] libbrotli1
```

### Python

```bash
docker run --rm -it -v "$PWD/scripts/vuln-check-CVE2026-111497-brotli.sh":/check.sh:ro python:3.13-slim bash
# inside the container
pip install Brotli==1.2.0
bash /check.sh -r /root                        # FAIL [08] brotli
pip install Brotli==1.2.1
bash /check.sh -r /root                        # PASS [08] brotli
```

### Node.js

Node is fixed by moving to a newer image tag.

```bash
docker run --rm -v "$PWD/scripts/vuln-check-CVE2026-111497-brotli.sh":/check.sh:ro node:24.22.0-slim bash /check.sh -r /root   # FAIL [02] node
docker run --rm -v "$PWD/scripts/vuln-check-CVE2026-111497-brotli.sh":/check.sh:ro node:24.22.1-slim bash /check.sh -r /root   # PASS [02] node
```

## FAQ

### Can I use Podman instead of Docker?

Yes. The manual testing commands work with `podman` in place of `docker`. In `-c` mode the script uses Docker if it responds and falls back to Podman; `-e podman` forces Podman.
