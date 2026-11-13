#!/bin/sh
# The wasm module against the native implementation (design §11):
#
#   sh web-core/test/run.sh
#
# 1. `cargo test --test parity` in web-core/: the reader against the CLI's SQL replica, natively
#    — and, with GCLONE_WEB_CORE_EXPORT set, the same vault and the native viewer rules' answers
#    written out for step 3.
# 2. (a prerequisite, not done here) web-core/pkg/ built by web-core/build.sh, and the native
#    `gclone` binary built from this tree.
# 3. `node test/e2e.mjs`: the wasm module, loaded as the viewer's workers load it, replays the
#    export and reads directory vaults that the native binary writes during the test.
#
# Environment:
#   GCLONE_BIN            the native binary [default: target/release/gclone, else target/debug/gclone]
#   GCLONE_WEB_CORE_PKG   the built module    [default: web-core/pkg]
#   CARGO_TARGET_DIR      for step 1          [default: web-core/target]
#   SKIP_NATIVE_PARITY=1  skip step 1 and the replay (the export needs cargo)
#   GCLONE_WEB_CORE_SMOKE engines for the browser smoke test, e.g. "chrome webkit firefox"
#                         [default: none — it needs playwright-core and browsers]
#
# Nothing here uses a real vault, a login or the network: devices are temporary directories
# (GCLONE_CONFIG_DIR / GCLONE_STATE_DIR), vaults are directories (`--vault-dir`).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
crate=$(cd "$here/.." && pwd)
repo=$(cd "$crate/.." && pwd)
pkg=${GCLONE_WEB_CORE_PKG:-$crate/pkg}

fail() {
    echo "run.sh: $*" >&2
    exit 1
}

[ -f "$pkg/core.wasm" ] && [ -f "$pkg/core.js" ] ||
    fail "$pkg holds no core.wasm and core.js: run web-core/build.sh first."
bin=${GCLONE_BIN:-}
if [ -z "$bin" ]; then
    for candidate in "$repo/target/release/gclone" "$repo/target/debug/gclone"; do
        if [ -x "$candidate" ]; then
            bin=$candidate
            break
        fi
    done
fi
[ -n "$bin" ] && [ -x "$bin" ] ||
    fail "no native gclone binary: cargo build --release --locked (or set GCLONE_BIN)."
command -v node > /dev/null 2>&1 || fail "node is not on PATH."

work=$(mktemp -d "${TMPDIR:-/tmp}/gclone-web-core.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

# A test never inherits a login, an auth Worker or the switch for live tests.
unset GCLONE_AUTH_URL GCLONE_DEFAULT_AUTH_URL GCLONE_LIVE GCLONE_CONFIG_DIR GCLONE_STATE_DIR GCLONE_LOG

export_dir=
if [ "${SKIP_NATIVE_PARITY:-}" != 1 ]; then
    export_dir=$work/export
    (cd "$crate" && GCLONE_WEB_CORE_EXPORT="$export_dir" cargo test --locked --test parity)
    [ -f "$export_dir/busy/expect.json" ] || fail "tests/parity.rs exported nothing."
fi

mkdir "$work/e2e"
GCLONE_BIN="$bin" GCLONE_WEB_CORE_PKG="$pkg" GCLONE_WEB_CORE_EXPORT="$export_dir" \
    GCLONE_WEB_CORE_WORK="$work/e2e" node "$here/e2e.mjs"

# 4. On request, the module smoke test in real browsers (needs playwright-core and its
#    browsers; see test/smoke/run.mjs): GCLONE_WEB_CORE_SMOKE="chrome webkit firefox".
if [ -n "${GCLONE_WEB_CORE_SMOKE:-}" ]; then
    [ -n "$export_dir" ] || fail "the smoke test serves the exported vault: do not skip step 1."
    # shellcheck disable=SC2086
    GCLONE_WEB_CORE_PKG="$pkg" GCLONE_WEB_CORE_EXPORT="$export_dir" \
        node "$here/smoke/run.mjs" $GCLONE_WEB_CORE_SMOKE
fi
