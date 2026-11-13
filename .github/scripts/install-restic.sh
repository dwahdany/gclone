#!/bin/sh
# Installs restic for the tests of `gclone serve restic` (tests/restic_e2e.rs): the release
# binary of the version below from github.com/restic/restic, checked against the SHA-256 of
# that release's SHA256SUMS before it is unpacked.
#
#   sh .github/scripts/install-restic.sh [DIR]
#
# DIR defaults to $RUNNER_TEMP/bin. In GitHub Actions the directory is added to the PATH of
# the following steps ($GITHUB_PATH); elsewhere the script says where the binary is.
set -eu

version=0.19.1

case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *)
        echo "install-restic: unsupported system $(uname -s)" >&2
        exit 1
        ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *)
        echo "install-restic: unsupported machine $(uname -m)" >&2
        exit 1
        ;;
esac

# From https://github.com/restic/restic/releases/download/v0.19.1/SHA256SUMS
case "${os}_${arch}" in
    linux_amd64) want=f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c ;;
    linux_arm64) want=a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465 ;;
    darwin_arm64) want=7be0a144ccc377880f294204aa271d76e4b79554b42a751151d425ce6ebac143 ;;
    darwin_amd64) want=c38d579622cf602f665234c5a8c315030b6cf70656028fe6dc29a786b60e5f35 ;;
esac

dir=${1:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/bin}
mkdir -p "$dir"
asset=restic_${version}_${os}_${arch}.bz2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl --fail --silent --show-error --location --retry 3 \
    --output "$work/$asset" \
    "https://github.com/restic/restic/releases/download/v${version}/${asset}"

if command -v sha256sum > /dev/null 2>&1; then
    have=$(sha256sum "$work/$asset" | awk '{ print $1 }')
else
    have=$(shasum -a 256 "$work/$asset" | awk '{ print $1 }')
fi
if [ "$have" != "$want" ]; then
    echo "install-restic: $asset has SHA-256 $have, expected $want" >&2
    exit 1
fi

bunzip2 "$work/$asset"
chmod +x "$work/restic_${version}_${os}_${arch}"
mv "$work/restic_${version}_${os}_${arch}" "$dir/restic"

if [ -n "${GITHUB_PATH:-}" ]; then
    echo "$dir" >> "$GITHUB_PATH"
else
    echo "restic is at $dir/restic"
fi
"$dir/restic" version
