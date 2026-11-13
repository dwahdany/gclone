#!/bin/sh
# Builds the hosted viewer's core: web-core/pkg/{core.js, core.wasm, build.json}.
#
#   sh web-core/build.sh [<repository root> [<output directory>]]
#
# core.wasm is this crate compiled for wasm32-unknown-unknown; core.js is wasm-bindgen's glue
# for `--target no-modules`: a classic script that defines the global `wasm_bindgen`, loaded
# with importScripts() by the KDF worker, the vault worker and the Service Worker:
#
#   importScripts('core.js');
#   await wasm_bindgen({ module_or_path: <URL of core.wasm, or its bytes> });
#   wasm_bindgen.core_version();
#
# (The .wasm is renamed from wasm-bindgen's `core_bg.wasm`, so its location is always passed.)
#
# Needs: cargo and rustc with the wasm32-unknown-unknown target (the pinned toolchain of
# rust-toolchain.toml for a release build), a wasm linker, and the `wasm-bindgen` command of
# exactly the version of the wasm-bindgen crate in web-core/Cargo.lock:
#   cargo install wasm-bindgen-cli --version <that version> --locked
# With nix (a development build: nixpkgs' versions are not the pinned ones):
#   nix-shell -p cargo rustc lld wasm-bindgen-cli nodejs --run 'sh web-core/build.sh'
#
# Environment: CARGO_TARGET_DIR (default web-core/target). For the device test page of design
# package P0, which is an ES module page with a function of its own (`kdf_bench`):
#   FEATURES=bench BINDGEN_TARGET=web OUT_NAME=gclone_web_core sh web-core/build.sh . <page>/pkg
# (FEATURES: cargo features; BINDGEN_TARGET: default no-modules; OUT_NAME: default core.)
# wasm-pack and binaryen are not used.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "${1:-$here/..}" && pwd)
out=${2:-$repo/web-core/pkg}
crate=$repo/web-core
target_dir=${CARGO_TARGET_DIR:-$crate/target}
bindgen_target=${BINDGEN_TARGET:-no-modules}
name=${OUT_NAME:-core}

fail() {
    echo "build.sh: $*" >&2
    exit 1
}

# --- 1. the two lockfiles agree ------------------------------------------------------------------
# web-core/Cargo.lock was made from the CLI's Cargo.lock: every package the core shares with
# the CLI is at one of the CLI's versions.
versions() {
    awk '$1 == "name" { gsub(/"/, "", $3); name = $3 }
         $1 == "version" { gsub(/"/, "", $3); print name " " $3 }' "$1" | sort -u
}
scratch=$(mktemp -d "${TMPDIR:-/tmp}/gclone-web-core-build.XXXXXX")
trap 'rm -rf "$scratch"' EXIT INT TERM
versions "$repo/Cargo.lock" > "$scratch/cli"
versions "$crate/Cargo.lock" > "$scratch/core"
drift=$(awk 'NR == FNR { cli[$1] = cli[$1] " " $2; next }
             ($1 in cli) && index(cli[$1] " ", " " $2 " ") == 0 { print $1 " " $2 " (the CLI has" cli[$1] ")" }' \
        "$scratch/cli" "$scratch/core")
[ -z "$drift" ] || fail "web-core/Cargo.lock has versions the CLI's Cargo.lock does not: $drift"

# --- 2. the tools --------------------------------------------------------------------------------
lock_bindgen=$(awk '$1 == "name" { name = $3 } name == "\"wasm-bindgen\"" && $1 == "version" { gsub(/"/, "", $3); print $3; exit }' "$crate/Cargo.lock")
[ -n "$lock_bindgen" ] || fail "web-core/Cargo.lock names no wasm-bindgen crate."
command -v wasm-bindgen > /dev/null 2>&1 ||
    fail "the wasm-bindgen command is missing: cargo install wasm-bindgen-cli --version $lock_bindgen --locked"
have_bindgen=$(wasm-bindgen --version | awk '{ print $2 }')
[ "$have_bindgen" = "$lock_bindgen" ] ||
    fail "the wasm-bindgen command is $have_bindgen, the wasm-bindgen crate in web-core/Cargo.lock is $lock_bindgen: the two must be equal."

rustc_version=$(cd "$crate" && rustc --version)
sysroot=$(cd "$crate" && rustc --print sysroot)
host=$(cd "$crate" && rustc -vV | awk '$1 == "host:" { print $2 }')
[ -d "$sysroot/lib/rustlib/wasm32-unknown-unknown" ] ||
    fail "this Rust toolchain has no wasm32-unknown-unknown target: rustup target add wasm32-unknown-unknown"
[ -x "$sysroot/lib/rustlib/$host/bin/rust-lld" ] || command -v rust-lld > /dev/null 2>&1 ||
    command -v lld > /dev/null 2>&1 || command -v wasm-ld > /dev/null 2>&1 ||
    fail "no wasm linker: use a rustup toolchain (it brings rust-lld) or put lld on PATH."

# --- 3. compile ----------------------------------------------------------------------------------
# Absolute build paths end up in panic messages: map them away (nothing of the builder's
# machine in the module, and the same bytes from any checkout).
cargo_home=${CARGO_HOME:-$HOME/.cargo}
RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$repo=/src" \
    CARGO_TARGET_DIR="$target_dir" \
    cargo build --locked --release --target wasm32-unknown-unknown \
    --manifest-path "$crate/Cargo.toml" ${FEATURES:+--features "$FEATURES"}

# --- 4. bindings ---------------------------------------------------------------------------------
rm -rf "$out"
mkdir -p "$out"
wasm-bindgen --target "$bindgen_target" --no-typescript --remove-name-section \
    --remove-producers-section --out-name "$name" --out-dir "$out" \
    "$target_dir/wasm32-unknown-unknown/release/gclone_web_core.wasm"
if [ "$bindgen_target" = no-modules ]; then
    mv "$out/${name}_bg.wasm" "$out/$name.wasm"
    wasm=$out/$name.wasm
else
    wasm=$out/${name}_bg.wasm
fi
version=$(awk -F'"' '$1 ~ /^version *= *$/ { print $2; exit }' "$crate/Cargo.toml")
# What built it, for the bundle's manifest: a development build is visibly not the release's.
printf '{"rustc":"%s","version":"%s","wasm_bindgen":"%s"}\n' \
    "$rustc_version" "$version" "$have_bindgen" > "$out/build.json"

# --- 5. what came out ----------------------------------------------------------------------------
# Imports (wasm-bindgen's intrinsics and nothing else: no clock, no randomness, no network),
# the size limit, and the sizes on the wire.
if command -v node > /dev/null 2>&1; then
    node "$crate/test/check-module.mjs" "$wasm" "$out/$name.js"
else
    echo "build.sh: node is not on PATH: the module's imports and size were not checked." >&2
fi
if command -v shasum > /dev/null 2>&1; then
    shasum -a 256 "$wasm" "$out/$name.js"
else
    sha256sum "$wasm" "$out/$name.js"
fi
