# HTTP2Shell / Node2Shell exposure check (CVE-2026-111497)

**Is your service exposed to HTTP2Shell?** It's a remote code execution bug in Google's Brotli decoder, under active attack. It affects Node.js, Bun, Python, .NET, Java, curl, Envoy and OS `libbrotli` packages.

- **Check by hand:** [read the guide](https://fieldse.github.io/brotli-node2shell-check/) for the command and fixed version for each stack.
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
./scripts/vuln-check-CVE2026-111497-brotli.sh --help         # all options
```

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
| 06 | Python compiled extensions |
| 07 | Python pins in requirements files, poetry.lock, uv.lock, pdm.lock |
| 08 | Host Python packages |
| 09 | npm middleware that decodes Brotli |
| 10 | Java brotli4j |
| 11 | Ruby brotli gem |
| 12 | Go modules |
| 13 | Rust crates |
| 14 | Vendored decoder sources (`decode.c`) |
| 15 | Bundled libbrotlidec copies |
| 16 | curl |
| 17 | Envoy, Istio, nginx |
| 18 | Container engine preflight and images (`-c`, `-i`) |

## Manual testing

Each example starts a throwaway container with a known-vulnerable build, mounts `scripts/` read-only, and runs the manual check and then the script. Run them from the repository root. `-r /root` searches the container's real home directory, so no test files are planted. Every vulnerable run prints a `FAIL` line and exits 1. After the upgrade or on the fixed version, it prints `PASS` and exits 0.

### Debian 12

```bash
docker run --rm -it -v "$PWD/scripts":/scripts:ro debian:bookworm-slim bash
```

Inside the container:

```bash
apt-get update && apt-get install -y libbrotli1=1.0.9-2+b6
dpkg -l libbrotli1 | tail -1                                   # 1.0.9-2+b6
bash /scripts/vuln-check-CVE2026-111497-brotli.sh -r /root    # FAIL [01] libbrotli1 ... listed as vulnerable

apt-get install -y --only-upgrade libbrotli1                   # upgrade to 1.0.9-2+deb12u1
bash /scripts/vuln-check-CVE2026-111497-brotli.sh -r /root    # PASS [01] libbrotli1 ... fixed in 1.0.9-2+deb12u1
```

### Ubuntu 22.04

```bash
docker run --rm -it -v "$PWD/scripts":/scripts:ro ubuntu:22.04 bash
```

Inside the container:

```bash
apt-get update && apt-get install -y libbrotli1=1.0.9-2build6
dpkg -l libbrotli1 | tail -1                                   # 1.0.9-2build6
bash /scripts/vuln-check-CVE2026-111497-brotli.sh -r /root    # FAIL [01] libbrotli1 ... fixed in 1.0.9-2ubuntu0.1

apt-get install -y --only-upgrade libbrotli1                   # upgrade to 1.0.9-2ubuntu0.1
bash /scripts/vuln-check-CVE2026-111497-brotli.sh -r /root    # PASS [01] libbrotli1
```

### Python

```bash
docker run --rm -it -v "$PWD/scripts":/scripts:ro python:3.13-slim bash
```

Inside the container:

```bash
pip install Brotli==1.2.0
pip list 2>/dev/null | grep -i brotli                          # brotli 1.2.0
bash /scripts/vuln-check-CVE2026-111497-brotli.sh -r /root    # FAIL [08] brotli ... found 1.2.0, fixed 1.2.1

pip install Brotli==1.2.1                                      # fixed version
bash /scripts/vuln-check-CVE2026-111497-brotli.sh -r /root    # PASS [08] brotli ... found 1.2.1
```

### Node.js

The official image unpacks Node into `/usr/local`, so you upgrade it by changing the image tag.

```bash
docker run --rm -v "$PWD/scripts":/scripts:ro node:24.22.0-slim \
  bash -c 'node --version; bash /scripts/vuln-check-CVE2026-111497-brotli.sh -r /root'
# v24.22.0, then FAIL [02] node ... found 24.22.0, fixed 24.22.1

docker run --rm -v "$PWD/scripts":/scripts:ro node:24.22.1-slim \
  bash -c 'node --version; bash /scripts/vuln-check-CVE2026-111497-brotli.sh -r /root'
# v24.22.1, then PASS [02] node ... bundles a decoder with the fix marker
```

## FAQ

### Can I use Podman instead of Docker?

Yes. The manual testing commands work with `podman` in place of `docker`. In `-c` mode the script uses Docker if it responds and falls back to Podman; `-e podman` forces Podman.
