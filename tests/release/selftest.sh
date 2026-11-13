#!/bin/bash
# The self-test of scripts/release-sign-macos.sh (also: `scripts/release-sign-macos.sh
# --selftest`).
#
#   bash tests/release/selftest.sh [--binary PATH]
#
# Runs the real script — every step, 1 to 16 — against a fake release directory and a fake
# `gh` (tests/release/fake-gh.sh), with an ad hoc signature in place of the Developer ID, and
# then the cases in which the script must refuse. It talks to no network, uses no keychain and
# no signing identity, and changes nothing outside a temporary directory.
#
# What it cannot show, because it has no Developer ID: the secure timestamp, the Developer ID
# requirement and the shape of a real designated requirement (step 7), signing through a
# keychain (step 1 and 6), notarization (step 11) and everything GitHub itself does. Those
# parts run for the first time at the first signed release; they stop the script, not the
# release, when they fail.
#
# --binary PATH: the gclone to "release" (default: target/release/gclone of this checkout). A
# binary that links a libiconv from a nix store — what the nix toolchain builds — is used for
# the case "links a library outside the system: refused", and a copy with the system's
# libiconv path stands in for the workflow's build in the other cases.

set -euo pipefail
export LC_ALL=C
# The system's own tar, sed, file and codesign, as in the script under test: inside a nix
# shell GNU tar lists an archive differently and GNU sed takes `-i` differently.
PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
export PATH

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/../.." && pwd)
script="$root/scripts/release-sign-macos.sh"

binary="$root/target/release/gclone"
while [ $# -gt 0 ]; do
    case "$1" in
        --binary)
            binary=$2
            shift 2
            ;;
        *)
            echo "selftest.sh: unknown argument '$1'" >&2
            exit 2
            ;;
    esac
done

if [ "$(uname -s)" != Darwin ]; then
    echo "SKIPPED: the release-signing self-test needs macOS (codesign)"
    exit 0
fi
[ -x "$binary" ] || {
    echo "selftest.sh: no gclone binary at $binary (cargo build --release, or --binary PATH)" >&2
    exit 2
}

work=$(mktemp -d "${TMPDIR:-/tmp}/gclone-release-selftest.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

failures=0
count=0
fail() {
    failures=$((failures + 1))
    printf 'FAIL: %s\n' "$1"
    shift
    for line in "$@"; do printf '      %s\n' "$line"; done
}
sha() { shasum -a 256 "$1" | awk '{ print $1 }'; }

# --- the binary to release ---------------------------------------------------------------------

version=$("$binary" --version | sed -n 's/^gclone \([^ ]*\) .*/\1/p')
[ -n "$version" ] || {
    echo "selftest.sh: $binary does not print a version" >&2
    exit 2
}
tag="v$version"
mkdir "$work/bin"
nix_linked=""
if otool -L "$binary" | tail -n +2 | awk '{ print $1 }' | grep -q '^/nix/store/'; then
    # The nix toolchain links its own libiconv. The release workflow's build links the
    # system's: a copy with that path rewritten (and its ad hoc signature made again) is what
    # the workflow would have built.
    nix_linked="$work/bin/gclone-nix"
    cp "$binary" "$nix_linked"
    cp "$binary" "$work/bin/gclone"
    chmod u+w "$work/bin/gclone"
    otool -L "$binary" | tail -n +2 | awk '{ print $1 }' | grep '^/nix/store/' | while read -r lib; do
        install_name_tool -change "$lib" "/usr/lib/$(basename "$lib")" "$work/bin/gclone" 2>/dev/null
    done
    codesign -f -s - "$work/bin/gclone" 2>/dev/null
    "$work/bin/gclone" --version >/dev/null || {
        echo "selftest.sh: the copy with the system's library paths does not run" >&2
        exit 2
    }
else
    cp "$binary" "$work/bin/gclone"
fi
ci_bin="$work/bin/gclone"

# --- a throw-away checkout with the tag, and its "origin" ---------------------------------------

checkout="$work/checkout"
mkdir "$checkout"
cp "$root/install.sh" "$checkout/install.sh"
printf '[package]\nname = "gclone"\nversion = "%s"\n' "$version" >"$checkout/Cargo.toml"
git_quiet() { git -C "$checkout" -c user.name=selftest -c user.email=selftest -c commit.gpgsign=false -c tag.gpgsign=false "$@" >/dev/null 2>&1; }
git -C "$checkout" init -q
git_quiet add .
git_quiet commit -m "release $tag"
git_quiet tag "$tag"
git clone -q --bare "$checkout" "$work/origin.git"
git_quiet remote add origin "$work/origin.git"
commit=$(git -C "$checkout" rev-parse HEAD)

# --- the fake GitHub ---------------------------------------------------------------------------

fakebin="$work/fakebin"
mkdir "$fakebin"
cp "$here/fake-gh.sh" "$fakebin/gh"
chmod 755 "$fakebin/gh"

linux_assets="gclone-aarch64-unknown-linux-musl.tar.gz gclone-x86_64-unknown-linux-musl.tar.gz"
mac_asset="gclone-aarch64-apple-darwin.tar.gz"
signed_asset="gclone-aarch64-apple-darwin-signed.tar.gz"
viewer_asset="gclone-viewer-$version.tar.gz"

# pack_bin BINARY ARCHIVE: one member, gclone.
pack_bin() {
    rm -rf "$work/pack"
    mkdir "$work/pack"
    cp "$1" "$work/pack/gclone"
    COPYFILE_DISABLE=1 tar -czf "$2" -C "$work/pack" gclone
}

# new_state: a fresh fake GitHub in $state, with the draft the release workflow leaves.
state=""
new_state() {
    state="$work/state-$count"
    rm -rf "$state"
    mkdir -p "$state/releases/$tag/assets"
    echo true >"$state/push"
    echo true >"$state/immutable"
    echo true >"$state/releases/$tag/draft"
    echo "$tag" >"$state/order"
    # shellcheck disable=SC2016 # the backticks are Markdown
    printf 'DRAFT until signed: this release is not published yet.\n\nHosted viewer: `%s`, build `0123456789abcdef`.\n\n## What changed\n* something\n' "$viewer_asset" >"$state/releases/$tag/body"
    : >"$state/log"
    : >"$state/attested"
    assets="$state/releases/$tag/assets"
    pack_bin "$ci_bin" "$assets/$mac_asset"
    for name in $linux_assets "$viewer_asset"; do
        printf 'not a real %s\n' "$name" >"$work/pack-file"
        tar -czf "$assets/$name" -C "$work" pack-file
    done
    write_sums
    attest_all
}
# write_sums: the workflow's SHA256SUMS for what the draft holds now.
write_sums() {
    (cd "$assets" && rm -f SHA256SUMS && shasum -a 256 gclone-*.tar.gz >"$work/sums" && mv "$work/sums" SHA256SUMS)
}
# attest_all: every archive of the draft, as it is now, has a build attestation.
attest_all() {
    : >"$state/attested"
    for file in "$assets"/gclone-*.tar.gz; do
        echo "$(sha "$file") refs/tags/$tag $commit" >>"$state/attested"
    done
}

# run NAME EXPECTED_STATUS ANSWERS…: the real script against the fake; output in $out.
out=""
current=""
run() {
    current=$1
    want=$2
    shift 2
    count=$((count + 1))
    set +e
    # shellcheck disable=SC2086 # mode is one word or none
    out=$(printf '%s\n' "$@" | PATH="${path_prefix}$fakebin:$PATH" FAKE_GH_STATE="$state" GCLONE_RELEASE_ROOT="$checkout" \
        GCLONE_REPO="acme/gclone" GCLONE_RELEASE_VERIFY_PAUSE=0 bash "$script" --run-under-selftest $mode "$tag" 2>&1)
    got=$?
    set -e
    if [ "$got" -ne "$want" ]; then
        fail "$current: exit status $got, expected $want" "$(printf '%s\n' "$out" | tail -n 12)"
    fi
}
# What `run` puts before the fake gh on PATH (with its trailing colon), and the mode it runs
# the script in ("" = sign and publish; `--verify-published`).
path_prefix=""
mode=""
lacks() {
    case "$out" in
        *"$1"*) fail "$current: the output has '$1'" "$(printf '%s\n' "$out" | tail -n 12)" ;;
    esac
}
has() {
    case "$out" in
        *"$1"*) ;;
        *) fail "$current: the output lacks '$1'" "$(printf '%s\n' "$out" | tail -n 12)" ;;
    esac
}
# Nothing on the fake GitHub was changed.
untouched() {
    [ ! -s "$state/log" ] || fail "$current: the release was changed" "$(cat "$state/log")"
    [ "$(cat "$state/releases/$tag/draft")" = true ] || fail "$current: the release was published"
}
refused() {
    has "REFUSED: $1"
    untouched
}

# --- 1. the whole procedure, first signed release -----------------------------------------------

new_state
run "the whole procedure" 0 "first-signed-release" "publish $tag"
has "== 16. The published release"
has "Release $tag is published and verified."
has "this is the FIRST signed release"
has "(self-test: ad hoc signature"
[ "$(cat "$state/releases/$tag/draft")" = false ] || fail "$current: not published"
[ "$(cat "$state/log")" = "upload $tag $signed_asset
upload $tag SHA256SUMS
publish $tag" ] || fail "$current: unexpected changes" "$(cat "$state/log")"
published="$state/releases/$tag/assets"
# shellcheck disable=SC2012 # plain names
[ "$(ls "$published" | tr '\n' ' ')" = "SHA256SUMS gclone-aarch64-apple-darwin-signed.tar.gz gclone-aarch64-apple-darwin.tar.gz gclone-aarch64-unknown-linux-musl.tar.gz $viewer_asset gclone-x86_64-unknown-linux-musl.tar.gz " ] ||
    fail "$current: the published files" "$(ls "$published")"
(cd "$published" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1) || fail "$current: SHA256SUMS does not check"
[ "$(awk '{ print $2 }' "$published/SHA256SUMS")" = "$(awk '{ print $2 }' "$published/SHA256SUMS" | sort)" ] ||
    fail "$current: SHA256SUMS is not sorted"
[ "$(wc -l <"$published/SHA256SUMS" | tr -d ' ')" = 5 ] || fail "$current: SHA256SUMS does not have five lines"
case "$(cat "$state/releases/$tag/body")" in
    *"DRAFT until signed"*) fail "$current: the notes still say draft" ;;
    *"identical apart from the signature"*"Hosted viewer"*"## What changed"*) ;;
    *) fail "$current: the notes" "$(cat "$state/releases/$tag/body")" ;;
esac
# The published signed archive: one member; the hardened runtime, no entitlements, the
# release identifier; the attested binary apart from the signature.
mkdir "$work/published"
[ "$(tar -tzf "$published/$signed_asset")" = gclone ] || fail "$current: the signed archive's members"
tar -xzf "$published/$signed_asset" -C "$work/published"
signed_bin="$work/published/gclone"
codesign --verify --strict "$signed_bin" 2>/dev/null || fail "$current: the published signature does not verify"
case "$(codesign -dv "$signed_bin" 2>&1)" in
    *"Identifier=io.github.dwahdany.gclone"*"flags=0x10002(adhoc,runtime)"*) ;;
    *) fail "$current: identifier or flags of the published binary" "$(codesign -dv "$signed_bin" 2>&1)" ;;
esac
[ -z "$(codesign -d --entitlements - --xml "$signed_bin" 2>/dev/null)" ] || fail "$current: entitlements"
"$signed_bin" --version >/dev/null || fail "$current: the published binary does not run"
# The archive carries no owner, no extended attributes.
case "$(tar -tvzf "$published/$signed_asset")" in
    *" 0 "*" gclone") ;;
    *) fail "$current: the signed archive names an owner" "$(tar -tvzf "$published/$signed_asset")" ;;
esac
first_signed_archive="$work/first-signed.tar.gz"
cp "$published/$signed_asset" "$first_signed_archive"

# Run again on the published release: it is not a draft, and nothing is touched.
: >"$state/log"
run "a published release is never touched" 1
has "REFUSED: release $tag is not a draft"
[ ! -s "$state/log" ] || fail "$current: the published release was changed"

# --- 2. continuity with a previous signed release ------------------------------------------------

# with_previous ARCHIVE: a published earlier release that carries ARCHIVE as its signed build.
with_previous() {
    mkdir -p "$state/releases/v0.0.1/assets"
    echo false >"$state/releases/v0.0.1/draft"
    echo "earlier" >"$state/releases/v0.0.1/body"
    cp "$1" "$state/releases/v0.0.1/assets/$signed_asset"
    printf '%s\nv0.0.1\n' "$tag" >"$state/order"
}
new_state
with_previous "$first_signed_archive"
run "continuity: the same designated requirement as the previous release" 0 "publish $tag"
has "the same designated requirement as v0.0.1, and the new binary satisfies it"
has "Release $tag is published and verified."

# A previous release signed otherwise (here: another binary, so another ad hoc requirement).
printf 'int main(void) { return 0; }\n' >"$work/other.c"
if cc -o "$work/other" "$work/other.c" 2>/dev/null; then
    codesign -f -s - -i io.github.dwahdany.gclone --options runtime "$work/other" 2>/dev/null
    pack_bin "$work/other" "$work/other-signed.tar.gz"
    new_state
    with_previous "$work/other-signed.tar.gz"
    run "continuity: another signer before" 1
    refused "the designated requirement differs from that of v0.0.1"
else
    echo "skipped: the case \"continuity: another signer before\" (no C compiler)"
fi
# The first signed release, not confirmed.
new_state
run "the first signed release, not confirmed" 1 "yes"
refused "not confirmed (typed 'yes', expected 'first-signed-release')"

# An earlier run got as far as the upload: the signed archive is made again, and replaced.
new_state
cp "$first_signed_archive" "$assets/$signed_asset"
write_sums
attest_all
sed -i '' "/$signed_asset/d" "$state/attested" 2>/dev/null || true
run "a second run after an interrupted one" 0 "first-signed-release" "publish $tag"
has "an earlier run uploaded $signed_asset; it will be replaced"
has "Release $tag is published and verified."

# An upload of step 13 that is cut off. `gh release upload --clobber` deletes the old asset and
# then uploads: a failure in between leaves the draft without the file. Both states used to
# be refused by every later run ("the draft does not hold exactly the files …", "SHA256SUMS
# lists …, which the draft does not hold"), with nothing left but repairing the draft by hand.
#
# A1: the signed archive is there, SHA256SUMS is gone.
new_state
echo SHA256SUMS >"$state/cut-upload"
run "the upload of SHA256SUMS is cut off after the old one was deleted" 1 "first-signed-release"
has "REFUSED: cannot upload SHA256SUMS to the draft"
if [ -e "$assets/SHA256SUMS" ] || [ ! -e "$assets/$signed_asset" ]; then
    fail "$current: not the state it is meant to leave" "$(ls "$assets")"
fi
run "the run after it: a draft without SHA256SUMS" 0 "first-signed-release" "publish $tag"
has "the draft has no SHA256SUMS"
has "an earlier run uploaded $signed_asset; it will be replaced"
has "Release $tag is published and verified."
(cd "$assets" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1) || fail "$current: SHA256SUMS does not check"
[ "$(wc -l <"$assets/SHA256SUMS" | tr -d ' ')" = 5 ] || fail "$current: SHA256SUMS does not have five lines"

# A2: SHA256SUMS lists the signed archive, which is gone (a second run's upload was cut off).
new_state
run "a run that is not confirmed at the end" 1 "first-signed-release" "no"
if [ ! -e "$assets/$signed_asset" ] || ! grep -q "$signed_asset" "$assets/SHA256SUMS"; then
    fail "$current: nothing was uploaded"
fi
echo "$signed_asset" >"$state/cut-upload"
run "the upload of the signed archive is cut off after the old one was deleted" 1 "first-signed-release"
has "REFUSED: cannot upload $signed_asset to the draft"
if [ -e "$assets/$signed_asset" ] || ! grep -q "$signed_asset" "$assets/SHA256SUMS"; then
    fail "$current: not the state it is meant to leave" "$(ls "$assets")"
fi
run "the run after it: SHA256SUMS lists a signed archive the draft does not hold" 0 "first-signed-release" "publish $tag"
has "that line is dropped"
has "Release $tag is published and verified."
(cd "$assets" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1) || fail "$current: SHA256SUMS does not check"

# Both gone: the workflow's archives alone.
new_state
rm "$assets/SHA256SUMS"
run "a draft with the attested archives and nothing else" 0 "first-signed-release" "publish $tag"
has "the draft has no SHA256SUMS"
has "Release $tag is published and verified."
[ "$(wc -l <"$assets/SHA256SUMS" | tr -d ' ')" = 5 ] || fail "$current: SHA256SUMS does not have five lines"
# What is derived is still held to the attestations: an archive without one is refused,
# SHA256SUMS or not.
new_state
rm "$assets/SHA256SUMS"
printf 'more\n' >>"$assets/$viewer_asset"
run "no SHA256SUMS, and an archive that is not what the workflow built" 1
refused "$viewer_asset has no valid build-provenance attestation"

# The system's own tools are used whatever PATH says: with a tar, a file, an otool, a lipo and
# a codesign of somebody else's first on PATH (a nix shell's GNU tar and `file` made step 5
# refuse an attested binary, and step 12 could not pack), the whole procedure runs.
mkdir "$work/hostile"
for tool in tar file otool lipo codesign security sed awk; do
    printf '#!/bin/sh\necho "this is not the system tool %s" >&2\nexit 64\n' "$tool" >"$work/hostile/$tool"
    chmod 755 "$work/hostile/$tool"
done
new_state
path_prefix="$work/hostile:"
run "other tools of the same names first on PATH" 0 "first-signed-release" "publish $tag"
path_prefix=""
has "Release $tag is published and verified."
lacks "this is not the system tool"

# --- 2b. continuity fails closed -------------------------------------------------------------------

# "No earlier signed release" has to be GitHub's answer, not the absence of one: with a
# previous release signed by another signer and a `gh release list` (or the `gh release view`
# of that release) that fails, the script used to announce the FIRST signed release — and the
# typed confirmation published what the case above refuses.
if [ -e "$work/other-signed.tar.gz" ]; then
    for failing in "release list" "release view v0.0.1"; do
        new_state
        with_previous "$work/other-signed.tar.gz"
        cat >"$state/hook" <<EOF
#!/bin/bash
case "\$*" in
    "$failing"*) echo "error connecting to api.github.com" >&2; exit 1 ;;
esac
EOF
        chmod 755 "$state/hook"
        run "continuity: gh $failing fails" 1 "first-signed-release" "publish $tag"
        lacks "this is the FIRST signed release"
        case "$failing" in
            "release list") refused "cannot list the releases of acme/gclone" ;;
            *) refused "cannot read the files of release v0.0.1" ;;
        esac
    done
fi

# --- 2c. step 16 and --verify-published --------------------------------------------------------------

# One failed answer of GitHub after publishing is not a verdict. `gh release verify` fails
# once with a server error: asked again, the release verifies.
new_state
cat >"$state/hook" <<EOF
#!/bin/bash
case "\$*" in
    "release verify $tag"*)
        [ -e "$state/failed-once" ] && exit 0
        : >"$state/failed-once"
        echo "HTTP 503: Service Unavailable (https://api.github.com/…)" >&2
        exit 1
        ;;
esac
EOF
chmod 755 "$state/hook"
run "step 16: one transient error of gh release verify" 0 "first-signed-release" "publish $tag"
has "Release $tag is published and verified."
[ -e "$state/failed-once" ] || fail "$current: the hook did not fire"

# It keeps failing: the release IS published, and what the script says is that it could not
# verify — with gh's own words, and with the way to ask again. Not "publish a new patch
# release": that sentence is for a file that differs.
new_state
cat >"$state/hook" <<EOF
#!/bin/bash
case "\$*" in
    "release verify $tag"*)
        echo "HTTP 503: Service Unavailable (https://api.github.com/…)" >&2
        exit 1
        ;;
esac
EOF
chmod 755 "$state/hook"
run "step 16: gh release verify keeps failing" 3 "first-signed-release" "publish $tag"
has "THE PUBLISHED RELEASE COULD NOT BE VERIFIED YET"
has "HTTP 503: Service Unavailable"
has "scripts/release-sign-macos.sh --verify-published $tag"
lacks "publish a new patch release"
lacks "DOES NOT VERIFY"
[ "$(cat "$state/releases/$tag/draft")" = false ] || fail "$current: not published"
# A second run of the signing procedure is refused (the release is published) and names the
# other mode; that mode needs no draft and no state, and is run again at will.
: >"$state/log"
run "after it: the signing procedure names --verify-published" 1
has "REFUSED: release $tag is not a draft"
has "--verify-published $tag"
mode="--verify-published"
run "--verify-published while gh release verify still fails" 3
has "THE PUBLISHED RELEASE COULD NOT BE VERIFIED YET"
lacks "publish a new patch release"
rm "$state/hook"
run "--verify-published once GitHub answers" 0
has "Release $tag verifies"
has "identical to the attested one after removing both signatures"
[ ! -s "$state/log" ] || fail "$current: --verify-published changed the release" "$(cat "$state/log")"
# A published file that is another one than SHA256SUMS names: definite, on the file itself.
printf 'x' >>"$state/releases/$tag/assets/gclone-x86_64-unknown-linux-musl.tar.gz"
run "--verify-published: a published file differs" 1
has "REFUSED: gclone-x86_64-unknown-linux-musl.tar.gz does not match its line in SHA256SUMS"
# A draft is not a published release.
new_state
run "--verify-published on a draft" 1
has "REFUSED: release $tag is not published"
mode=""

# --- 3. what must be refused ----------------------------------------------------------------------

new_state
echo false >"$state/immutable"
run "immutable releases are off" 1
refused "immutable releases are not enabled for acme/gclone"

new_state
echo false >"$state/push"
run "no write access" 1
refused "this GitHub login may not write to acme/gclone"

new_state
git_quiet tag -f "$tag" "$(git -C "$checkout" commit-tree -m other "$(git -C "$checkout" rev-parse 'HEAD^{tree}')")"
run "the tag is elsewhere on GitHub" 1
refused "the tag $tag is at"
git_quiet tag -f "$tag" "$commit"

new_state
printf 'x\n' >"$assets/extra.txt"
run "a file the workflow does not make" 1
refused "the draft does not hold exactly the files the release workflow makes"

new_state
rm "$assets/gclone-x86_64-unknown-linux-musl.tar.gz"
run "a file is missing" 1
refused "the draft does not hold exactly the files the release workflow makes"

# The archive and its line in SHA256SUMS were replaced together: the checksum agrees with
# itself, no attestation exists for the new bytes.
new_state
cp "$ci_bin" "$work/tampered"
chmod u+w "$work/tampered"
printf 'x' >>"$work/tampered"
pack_bin "$work/tampered" "$assets/$mac_asset"
write_sums
run "an archive that is not what the workflow built" 1
refused "$mac_asset has no valid build-provenance attestation"
has "Nothing was signed and nothing was changed."

new_state
printf 'more\n' >>"$assets/$viewer_asset"
run "the viewer bundle was replaced" 1
refused "$viewer_asset has no valid build-provenance attestation"

new_state
sed -i '' "s/^[0-9a-f]\{8\}\(.*$mac_asset\)$/00000000\1/" "$assets/SHA256SUMS"
run "a wrong line in SHA256SUMS" 1
refused "$mac_asset does not match its line in SHA256SUMS"

new_state
grep -v "$viewer_asset" "$assets/SHA256SUMS" >"$work/sums" && mv "$work/sums" "$assets/SHA256SUMS"
run "SHA256SUMS lists fewer files" 1
refused "SHA256SUMS lists other files than the release holds"

# Attested bytes that are not what the script may sign.
attested_archive() {
    cp "$1" "$assets/$mac_asset"
    write_sums
    attest_all
}
new_state
rm -rf "$work/pack" && mkdir "$work/pack"
cp "$ci_bin" "$work/pack/gclone"
printf 'x\n' >"$work/pack/README"
tar -czf "$work/two.tar.gz" -C "$work/pack" gclone README
attested_archive "$work/two.tar.gz"
run "an archive with two members" 1
refused "$mac_asset holds more than one member"

new_state
rm -rf "$work/pack" && mkdir "$work/pack"
ln -s /bin/ls "$work/pack/gclone"
tar -czf "$work/link.tar.gz" -C "$work/pack" gclone
attested_archive "$work/link.tar.gz"
run "the member is a symbolic link" 1
refused "the one member of $mac_asset is not a regular file called gclone"

new_state
rm -rf "$work/pack" && mkdir "$work/pack"
printf '#!/bin/sh\necho "gclone %s (aarch64-apple-darwin, no auth URL built in)"\n' "$version" >"$work/pack/gclone"
chmod 755 "$work/pack/gclone"
tar -czf "$work/script.tar.gz" -C "$work/pack" gclone
attested_archive "$work/script.tar.gz"
run "the member is not a Mach-O executable" 1
refused "the binary is not an arm64 Mach-O executable"

if [ -n "$nix_linked" ]; then
    new_state
    pack_bin "$nix_linked" "$work/nix.tar.gz"
    attested_archive "$work/nix.tar.gz"
    run "the binary links a library outside the system" 1
    refused "the binary links libraries outside the system"
else
    echo "skipped: the case \"links a library outside the system\" (the binary links system libraries only)"
fi

# The binary of another version than the tag: the smoke test notices.
if cc -o "$work/liar" -x c - 2>/dev/null <<EOF; then
#include <stdio.h>
int main(void) { puts("gclone 0.0.0 (aarch64-apple-darwin, no auth URL built in)"); return 0; }
EOF
    codesign -f -s - "$work/liar" 2>/dev/null
    new_state
    pack_bin "$work/liar" "$work/liar.tar.gz"
    attested_archive "$work/liar.tar.gz"
    run "a binary of another version" 1 "first-signed-release"
    refused "the signed binary says 'gclone 0.0.0"
fi

# Not confirmed at the end: uploaded to the draft, never published.
new_state
run "publishing is not confirmed" 1 "first-signed-release" "publish"
has "REFUSED: not confirmed (typed 'publish', expected 'publish $tag')"
[ "$(cat "$state/releases/$tag/draft")" = true ] || fail "$current: the release was published"

# A file of the draft is replaced after it was checked, before it is published: the digests
# are compared once more immediately before.
new_state
cat >"$state/hook" <<EOF
#!/bin/bash
# The script reads the digests of the draft three times: in step 4, in step 14 and immediately
# before publishing. The swap happens right before the third look.
case "\$*" in
    *"release view"*".assets[] | "*)
        n=\$(cat "$state/views" 2>/dev/null || echo 0)
        n=\$((n + 1))
        echo "\$n" >"$state/views"
        if [ "\$n" = 3 ]; then
            printf 'swapped\n' >>"$state/releases/$tag/assets/gclone-x86_64-unknown-linux-musl.tar.gz"
        fi
        ;;
esac
EOF
chmod 755 "$state/hook"
run "a file is replaced between the check and the publishing" 1 "first-signed-release" "publish $tag"
has "REFUSED: the draft changed after it was checked — nothing was published"
[ "$(cat "$state/releases/$tag/draft")" = true ] || fail "$current: the release was published"
[ "$(cat "$state/views")" = 3 ] || fail "$current: the swap was not at the last look (look $(cat "$state/views"))"

# GitHub reports other digests for the published release than those of the checked files:
# it cannot be repaired in place, and the script says so.
new_state
printf '%s  %s\n' "0000000000000000000000000000000000000000000000000000000000000000" "$mac_asset" >"$state/lie-after-publish"
run "the published release does not verify" 1 "first-signed-release" "publish $tag"
has "THE PUBLISHED RELEASE DOES NOT VERIFY"
has "publish a new patch release"

# --- 4. the checks themselves, on prepared binaries ----------------------------------------------

# check NAME EXPECTED_STATUS FUNCTION ARGS…: one function of the script, as the self-test mode
# runs it. `WORK` is where the function may put its files.
check() {
    current=$1
    want=$2
    shift 2
    count=$((count + 1))
    set +e
    out=$(GCLONE_RELEASE_LIB=1 WORK_DIR="$work/fn-$count" bash -c '
        set -euo pipefail
        . "$0"
        SELFTEST=1
        WORK=$WORK_DIR
        mkdir -p "$WORK"
        "$@"' "$script" "$@" 2>&1)
    got=$?
    set -e
    if [ "$got" -ne "$want" ]; then
        fail "$current: status $got, expected $want" "$out"
    fi
}

resign() {
    cp "$ci_bin" "$1"
    chmod u+w "$1"
    shift
    codesign -f -s - -i io.github.dwahdany.gclone "$@" 2>/dev/null
}
resign "$work/good" --options runtime "$work/good"
check "step 7 accepts the hardened runtime without entitlements" 0 verify_signed "$work/good" "the binary"

cat >"$work/entitlements.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.cs.disable-library-validation</key><true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
</dict></plist>
EOF
resign "$work/entitled" --options runtime --entitlements "$work/entitlements.plist" "$work/entitled"
check "step 7 refuses a signature with entitlements" 1 verify_signed "$work/entitled" "the binary"
has "the signature carries entitlements; a release binary has none"

# "No entitlements" is what codesign SAID, not what it failed to say: a codesign that cannot
# answer (one that does not know `--xml`) printed nothing as well, and the entitled binary
# passed. (A shell function stands in for that codesign: the script takes the system's own.)
count=$((count + 1))
current="step 7 refuses when the entitlements cannot be read"
set +e
out=$(GCLONE_RELEASE_LIB=1 WORK_DIR="$work/fn-$count" bash -c '
    set -euo pipefail
    . "$0"
    SELFTEST=1
    WORK=$WORK_DIR
    mkdir -p "$WORK"
    codesign() {
        case " $* " in *" --entitlements "*)
            echo "codesign: unrecognized option" >&2
            return 1
            ;;
        esac
        command codesign "$@"
    }
    verify_signed "$1" "the binary"' "$script" "$work/good" 2>&1)
got=$?
set -e
[ "$got" = 1 ] || fail "$current: status $got" "$out"
has "the entitlements cannot be read"

resign "$work/no-runtime" "$work/no-runtime"
check "step 7 refuses a signature without the hardened runtime" 1 verify_signed "$work/no-runtime" "the binary"
has "the code-signing flags are '0x2(adhoc)', not exactly '0x10002(adhoc,runtime)'"

resign "$work/more-flags" --options runtime,library "$work/more-flags"
check "step 7 refuses any flag beside the runtime" 1 verify_signed "$work/more-flags" "the binary"
has "not exactly '0x10002(adhoc,runtime)'"

cp "$ci_bin" "$work/other-identifier"
chmod u+w "$work/other-identifier"
codesign -f -s - -i com.example.other --options runtime "$work/other-identifier" 2>/dev/null
check "step 7 refuses another identifier" 1 verify_signed "$work/other-identifier" "the binary"
has "the signing identifier is 'com.example.other'"

cp "$work/good" "$work/appended"
printf 'x' >>"$work/appended"
check "step 7 refuses appended bytes" 1 verify_signed "$work/appended" "the binary"
has "the signature does not verify"

# Step 9. A pair that is equal apart from the signature; a pair that differs by one byte of
# code; and what the comparison cannot see (which is why step 7 exists).
check "step 9: equal apart from the signature" 0 same_apart_from_signature "$ci_bin" "$work/good"
cp "$ci_bin" "$work/one-byte"
chmod u+w "$work/one-byte"
# One byte in the middle of the file — code or data, not the signature at its end.
size=$(wc -c <"$work/one-byte" | tr -d ' ')
old_byte=$(dd if="$work/one-byte" bs=1 skip=$((size / 2)) count=1 2>/dev/null | od -An -tx1 | tr -d ' ')
if [ "$old_byte" = 00 ]; then new_byte='\001'; else new_byte='\000'; fi
# shellcheck disable=SC2059 # the format IS the byte
printf "$new_byte" | dd of="$work/one-byte" bs=1 seek=$((size / 2)) conv=notrunc 2>/dev/null
codesign -f -s - -i io.github.dwahdany.gclone --options runtime "$work/one-byte" 2>/dev/null
check "step 9: one changed byte is a difference" 1 same_apart_from_signature "$ci_bin" "$work/one-byte"
check "step 9 is blind to entitlements (step 7 is not)" 0 same_apart_from_signature "$ci_bin" "$work/entitled"

# The shape of a Developer ID designated requirement (the team here is a made-up one).
shape='identifier "io.github.dwahdany.gclone" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = '
check "the expected designated requirement" 0 requirement_has_expected_shape "${shape}ABCDE12345"
check "the expected designated requirement, team quoted" 0 requirement_has_expected_shape "${shape}\"1BCDE12345\""
check "a requirement without a team" 1 requirement_has_expected_shape "${shape% and certificate leaf\[subject.OU\] = }"
check "a requirement for another identifier" 1 requirement_has_expected_shape "$(printf '%s' "${shape}ABCDE12345" | sed 's/io.github.dwahdany.gclone/com.example.other/')"
check "a requirement with an alternative" 1 requirement_has_expected_shape "(${shape}ABCDE12345) or identifier \"x\""
check "an ad hoc requirement" 1 requirement_has_expected_shape 'cdhash H"cc737e7fc42747ac2d8acf073906367a7a3778b3"'

# Without the self-test switch the script wants a real Developer ID: the flags of an ad hoc
# signature are refused outright.
count=$((count + 1))
current="outside the self-test an ad hoc signature is refused"
set +e
out=$(GCLONE_RELEASE_LIB=1 bash -c '. "$0"; verify_signed "$1" "the binary"' "$script" "$work/good" 2>&1)
got=$?
set -e
[ "$got" = 1 ] || fail "$current: status $got" "$out"
has "not exactly '0x10000(runtime)'"

# The self-test mode cannot be had against the real gh.
count=$((count + 1))
current="the self-test mode refuses a gh that is not the fake"
mkdir "$work/realish"
printf '#!/bin/sh\necho "gh version 2.0.0 (not the fake)"\n' >"$work/realish/gh"
chmod 755 "$work/realish/gh"
set +e
out=$(PATH="$work/realish:$PATH" GCLONE_RELEASE_ROOT="$checkout" bash "$script" --run-under-selftest "$tag" 2>&1 </dev/null)
got=$?
set -e
[ "$got" = 1 ] || fail "$current: status $got" "$out"
has "the self-test runs against the fake gh only"

if [ "$failures" -ne 0 ]; then
    printf '%s failed checks in %s cases\n' "$failures" "$count"
    exit 1
fi
printf 'ok: %s cases (release-sign-macos.sh self-test, %s, ad hoc signature, fake gh)\n' "$count" "$tag"
