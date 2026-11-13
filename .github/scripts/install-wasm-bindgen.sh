#!/bin/sh
# Installs the `wasm-bindgen` command in exactly the version of the wasm-bindgen crate in
# web-core/Cargo.lock (the two must be equal: the command rewrites what the crate's macros
# emit). Built from source with its own lockfile; nothing is downloaded but crates.
#
#   sh .github/scripts/install-wasm-bindgen.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
lock=$here/../../web-core/Cargo.lock
want=$(awk '$1 == "name" { name = $3 } name == "\"wasm-bindgen\"" && $1 == "version" { gsub(/"/, "", $3); print $3; exit }' "$lock")
[ -n "$want" ] || {
    echo "install-wasm-bindgen: web-core/Cargo.lock names no wasm-bindgen crate" >&2
    exit 1
}
if command -v wasm-bindgen > /dev/null 2>&1; then
    have=$(wasm-bindgen --version | awk '{ print $2 }')
    if [ "$have" = "$want" ]; then
        echo "wasm-bindgen $have is installed"
        exit 0
    fi
fi
cargo install wasm-bindgen-cli --version "$want" --locked
wasm-bindgen --version
