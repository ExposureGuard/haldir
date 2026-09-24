#!/bin/sh
# Haldir demo installer — Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/ExposureGuard/haldir/main/install.sh | sh
#
# Detects the platform, fetches the matching binary from the latest demo
# release, and tells you how to run it. Nothing is installed system-wide and
# nothing is left running: the binary is one file, and it cleans up after
# itself when you stop it.
#
# Set HALDIR_DEMO_DIR to choose where it lands (default: current directory).
# Set HALDIR_DEMO_TAG to pin a release instead of taking the latest.

set -eu

REPO="ExposureGuard/haldir"
TAG="${HALDIR_DEMO_TAG:-demo-preview-1}"
DIR="${HALDIR_DEMO_DIR:-.}"

say()  { printf '[*] %s\n' "$1"; }
good() { printf '[+] %s\n' "$1"; }
die()  { printf '[-] %s\n' "$1" >&2; exit 1; }

case "$(uname -s)" in
    Linux)  os=linux ;;
    Darwin) os=macos ;;
    *) die "unsupported system: $(uname -s). On Windows use install.ps1; on anything else, 'pip install haldir' works wherever Python 3.10+ does." ;;
esac

case "$(uname -m)" in
    x86_64|amd64)  arch=x86_64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) die "unsupported architecture: $(uname -m). 'pip install haldir' works wherever Python 3.10+ does." ;;
esac

# No Intel Mac build exists. An arm64 binary will not run on one, and
# `macos-13` — the last Intel runner GitHub offered — is retired, so there is
# nowhere to build it. Saying so here beats a 404 that reads as a broken link.
if [ "$os" = "macos" ] && [ "$arch" = "x86_64" ]; then
    die "no Intel Mac build. The pip path needs no build at all:
    pip install haldir && python3 -m haldir_probes --serve"
fi

ASSET="haldir-demo-${os}-${arch}"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"

say "platform: ${os}/${arch}"
say "fetching:  ${URL}"

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v chmod >/dev/null 2>&1 || die "chmod is required"

mkdir -p "$DIR"
TARGET="${DIR}/haldir-demo"

# -f so an HTTP error is a failure rather than a saved error page, and -L for
# the redirect GitHub serves for release assets.
curl -fSL --progress-bar -o "$TARGET" "$URL" \
  || die "download failed. If this is Linux on arm64 there is no build yet — use 'pip install haldir' instead."

chmod +x "$TARGET"

# Does the file actually look like an executable for this machine? A saved 404
# page is most of a kilobyte and would fail confusingly at run time.
SIZE=$(wc -c < "$TARGET" | tr -d ' ')
[ "$SIZE" -gt 1000000 ] || die "the downloaded file is ${SIZE} bytes, which is not the binary. The release or tag name is probably wrong."

good "downloaded to ${TARGET} ($((SIZE / 1048576)) MB)"
echo
echo "  Run the three probes:"
echo "      ${TARGET}"
echo
echo "  Or keep an instance up to poke at, printing a URL and an API key:"
echo "      ${TARGET} --keep"
echo
echo "  macOS may refuse it once — right-click, Open, or:"
echo "      xattr -d com.apple.quarantine ${TARGET}"
echo
