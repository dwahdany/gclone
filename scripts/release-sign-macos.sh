#!/bin/bash
# Signs the macOS build of a gclone release with a Developer ID and publishes the release.
#
#   scripts/release-sign-macos.sh <tag>          sign and publish the draft release <tag>
#   scripts/release-sign-macos.sh --verify-published <tag>
#                                                verify the PUBLISHED release <tag> from nothing
#                                                but GitHub: every file, its attestation, the
#                                                signature, `gh release verify`, install.sh.
#                                                Changes nothing; can be run again at any time.
#   scripts/release-sign-macos.sh --selftest     run the whole procedure against a fake release
#                                                directory, a fake `gh` and an ad hoc signature
#
# The release workflow (.github/workflows/release.yml) stops at a DRAFT release that holds the
# attested archives. This script, run by the owner on an Apple-silicon Mac,
#
#   1. checks its preconditions (this Mac, `gh` with write access, immutable releases switched
#      on, the tag at the same commit here and on GitHub, exactly one Developer ID Application
#      identity);
#   2. checks that the release is a draft with exactly the files the workflow makes;
#   3. downloads them;
#   4. verifies every archive against its build-provenance attestation and against SHA256SUMS
#      — nothing from an archive runs before this;
#   5. unpacks the macOS archive after listing it (one member, the file `gclone`: a thin arm64
#      Mach-O with an ad hoc signature that links only system libraries);
#   6. signs a copy (hardened runtime, secure timestamp, NO entitlements);
#   7. verifies the signature: flags exactly `0x10000(runtime)`, no entitlements, a timestamp,
#      an Apple-issued Developer ID, the expected shape of the designated requirement;
#   8. continuity: the designated requirement equals that of the previous signed release (the
#      first signed release asks for a typed confirmation instead);
#   9. proves that the signed binary is the attested one apart from the signature;
#  10. runs the signed binary (version, a directory vault, `keystore check`) in a temp home;
#  11. notarizes it (only if GCLONE_NOTARY_PROFILE names a notarytool keychain profile);
#  12. packs gclone-aarch64-apple-darwin-signed.tar.gz;
#  13. extends SHA256SUMS and uploads both;
#  14. downloads the whole draft again and checks it as a whole;
#  15. publishes after a typed confirmation — the draft's digests must still be the checked
#      ones — and rewrites the first line of the notes;
#  16. verifies the published release (digests, `gh release verify`, `verify-asset` for every
#      checked file, install.sh from the release).
#
# Everything that can fail comes before step 15; until then the script can simply be run again
# — also after an upload of step 13 that was cut off: `gh release upload --clobber` deletes
# the old file before it sends the new one, so a draft can be left without SHA256SUMS, or
# without the signed archive that its SHA256SUMS still lists. SHA256SUMS is derived from the
# attested archives, never an input that has to be there.
# It refuses to go on as soon as anything does not verify, and it changes nothing on GitHub
# before step 13. After step 15 nothing can be changed any more: a step 16 that could not ASK
# GitHub (a network error, an attestation that is not served yet) says so and is repeated
# with `--verify-published <tag>`; only a published file that differs from the checked one is
# reported as a release that cannot be repaired.
#
# The system's own tools are used, whatever PATH says: /usr/bin and /bin come first (a GNU tar
# or another `file` from a nix shell or Homebrew answers differently, and a `codesign` planted
# earlier on PATH has no business in a signing run). `gh` and `git` are found after them.
#
# Environment:
#   GCLONE_SIGN_KEYCHAIN    a keychain file that holds the signing identity and is locked except
#                           while this script runs: it is unlocked at the start (the password is
#                           asked for on the terminal) and locked again on every way out.
#                           Recommended: with the identity in the login keychain, every program
#                           of this user can sign as you, silently.
#   GCLONE_SIGN_IDENTITY    the SHA-1 hash of the identity to use, if the keychain holds more
#                           than one of type "Developer ID Application".
#   GCLONE_NOTARY_PROFILE   a `xcrun notarytool store-credentials` profile: also notarize.
#   GCLONE_REPO             OWNER/NAME (default: the repository this script belongs to).
#
# The identity, the team and the certificate's name are read from the keychain at run time.
# They are shown on the terminal and written to no file of the repository — but they are IN
# the signed binary, which this script publishes: anyone reads them with `codesign -dvv`.

set -euo pipefail
export LC_ALL=C
# The system's tar, file, otool, lipo, sed, awk, codesign and security — not whatever a
# development shell put before them.
PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
export PATH

REPO=${GCLONE_REPO:-dwahdany/gclone}
# Reserved for what this script signs: nothing else that the same team signs uses it.
IDENTIFIER="io.github.dwahdany.gclone"
WORKFLOW=".github/workflows/release.yml"
MAC_TARGET="aarch64-apple-darwin"
MAC_ASSET="gclone-$MAC_TARGET.tar.gz"
SIGNED_ASSET="gclone-$MAC_TARGET-signed.tar.gz"
LINUX_ASSETS="gclone-aarch64-unknown-linux-musl.tar.gz gclone-x86_64-unknown-linux-musl.tar.gz"
SUMS="SHA256SUMS"
# An Apple-issued Developer ID Application certificate, of whatever team.
DEVELOPER_ID_REQUIREMENT='anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
DRAFT_MARK="DRAFT until signed"

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/.." && pwd)

WORK=""
KEYCHAIN_TO_LOCK=""
SELFTEST=0
# In the self-test: `-` (ad hoc). Otherwise the hash of the Developer ID Application identity.
IDENTITY=""

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() {
    printf '\nrelease-sign-macos.sh: REFUSED: %s\n' "$1" >&2
    shift
    for line in "$@"; do printf '  %s\n' "$line" >&2; done
    exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }
# Lines as one line, for messages.
one_line() { tr '\n' ' ' | sed 's/ $//'; }

cleanup() {
    status=$?
    if [ -n "$KEYCHAIN_TO_LOCK" ]; then
        security lock-keychain "$KEYCHAIN_TO_LOCK" >/dev/null 2>&1 ||
            printf 'release-sign-macos.sh: WARNING: could not lock %s again — lock it by hand: security lock-keychain <file>\n' "the signing keychain" >&2
    fi
    if [ -n "$WORK" ] && [ -d "$WORK" ]; then
        if [ "$status" -eq 0 ] || [ "${GCLONE_RELEASE_KEEP_WORK:-0}" != 1 ]; then
            rm -rf "$WORK"
        else
            printf 'release-sign-macos.sh: the work directory was kept: %s\n' "$WORK" >&2
        fi
    fi
    return 0
}

sha256_of() { shasum -a 256 "$1" | awk '{ print $1 }'; }

# confirm_typed QUESTION EXPECTED: the answer has to be typed exactly.
confirm_typed() {
    printf '%s\n' "$1"
    printf 'Type %s to go on: ' "$2"
    answer=""
    IFS= read -r answer || true
    [ "$answer" = "$2" ] || die "not confirmed (typed '$answer', expected '$2')" "Nothing was published."
}

# ---------------------------------------------------------------------------------------------
# What codesign says about a binary
# ---------------------------------------------------------------------------------------------

# The flags field of the code directory: `0x10000(runtime)`.
sig_flags() { codesign -dv "$1" 2>&1 | sed -n 's/^CodeDirectory .* flags=\([^ ]*\) .*$/\1/p'; }
sig_identifier() { codesign -dv "$1" 2>&1 | sed -n 's/^Identifier=//p'; }
sig_team() { codesign -dv "$1" 2>&1 | sed -n 's/^TeamIdentifier=//p'; }
# The designated requirement as text: `identifier "…" and anchor apple generic and …`.
sig_requirement() { codesign -d -r- "$1" 2>/dev/null | sed -n 's/^\(# \)\{0,1\}designated => //p'; }
# The entitlements as XML; nothing at all for a binary without any. The exit status is
# codesign's: "nothing printed" means "no entitlements" only when the question was answered.
sig_entitlements() { codesign -d --entitlements - --xml "$1" 2>/dev/null; }

# What a release binary's designated requirement looks like, whoever the team is.
requirement_has_expected_shape() {
    printf '%s\n' "$1" | grep -Eq "^identifier \"?$(printf '%s' "$IDENTIFIER" | sed 's/\./\\./g')\"? and anchor apple generic and certificate 1\[field\.1\.2\.840\.113635\.100\.6\.2\.6\] /\* exists \*/ and certificate leaf\[field\.1\.2\.840\.113635\.100\.6\.1\.13\] /\* exists \*/ and certificate leaf\[subject\.OU\] = \"?[A-Z0-9]{10}\"?\$"
}

# The flags a signed release binary must have, exactly.
expected_flags() {
    if [ "$SELFTEST" = 1 ]; then echo "0x10002(adhoc,runtime)"; else echo "0x10000(runtime)"; fi
}

# verify_signed BINARY WHAT: step 7. Everything a signed release binary must be, checked on
# the file. Dies on the first thing that is not so.
verify_signed() {
    bin=$1
    what=$2
    codesign --verify --strict "$bin" 2>/dev/null ||
        die "$what: the signature does not verify (codesign --verify --strict)"
    flags=$(sig_flags "$bin")
    [ "$flags" = "$(expected_flags)" ] ||
        die "$what: the code-signing flags are '$flags', not exactly '$(expected_flags)'" \
            "A release binary has the hardened runtime and nothing else."
    entitlements=$(sig_entitlements "$bin") ||
        die "$what: the entitlements cannot be read (codesign -d --entitlements - --xml failed)" \
            "A release binary has none, and that has to be checked, not assumed."
    [ -z "$entitlements" ] ||
        die "$what: the signature carries entitlements; a release binary has none" \
            "An entitlement such as disable-library-validation would let other code run under gclone's identity."
    identifier=$(sig_identifier "$bin")
    [ "$identifier" = "$IDENTIFIER" ] ||
        die "$what: the signing identifier is '$identifier', not '$IDENTIFIER'"
    if [ "$SELFTEST" = 1 ]; then
        say "   (self-test: ad hoc signature — no timestamp, no Developer ID, no team to check)"
        return 0
    fi
    codesign -dvv "$bin" 2>&1 | grep -q '^Timestamp=' ||
        die "$what: the signature has no secure timestamp"
    codesign --verify -R="$DEVELOPER_ID_REQUIREMENT" "$bin" 2>/dev/null ||
        die "$what: the signature is not from an Apple-issued Developer ID Application certificate"
    requirement=$(sig_requirement "$bin")
    requirement_has_expected_shape "$requirement" ||
        die "$what: the designated requirement has an unexpected shape:" "$requirement"
}

# normalised IN OUT: the binary without its signature, re-signed ad hoc under one fixed name.
# Two binaries that differ only in their signature give the same bytes.
normalised() {
    cp "$1" "$2"
    chmod u+w "$2"
    codesign --remove-signature "$2" 2>/dev/null || die "cannot remove the signature of a copy of $1"
    codesign -f -s - -i gclone-compare "$2" 2>/dev/null || die "cannot re-sign a copy of $1"
}

# same_apart_from_signature A B: step 9. (Flags and entitlements are invisible to this
# comparison — a binary signed with an entitlement normalises to the same bytes; that is what
# `verify_signed` is for.)
same_apart_from_signature() {
    normalised "$1" "$WORK/compare-a"
    normalised "$2" "$WORK/compare-b"
    cmp -s "$WORK/compare-a" "$WORK/compare-b"
}

# ---------------------------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------------------------

release_field() { gh release view "$TAG" --repo "$REPO" --json "$1" --jq "$2"; }
# `<sha256>  <name>` lines of the release's assets as GitHub reports them, sorted by name.
release_digests() {
    gh release view "${1:-$TAG}" --repo "$REPO" --json assets \
        --jq '.assets[] | "\(.digest | sub("^sha256:"; ""))  \(.name)"' | sort -k 2
}
release_names() { gh release view "${1:-$TAG}" --repo "$REPO" --json assets --jq '.assets[].name' | sort; }

attested() {
    gh attestation verify "$1" --repo "$REPO" --signer-workflow "$REPO/$WORKFLOW" \
        --source-ref "refs/tags/$TAG" --source-digest "$COMMIT" --deny-self-hosted-runners >/dev/null 2>"$WORK/attest.err"
}

# asked WHAT CMD…: a question to GitHub that is asked up to VERIFY_TRIES times, VERIFY_PAUSE
# seconds apart. 0 = answered yes. Otherwise the last answer's stderr is in $WORK/asked.err
# and WHAT is appended to UNANSWERED: a failure here is "not confirmed", never "refuted" — gh
# exits the same way for a network error, for an attestation that is not served yet and for a
# file that is not in the release.
VERIFY_TRIES=${GCLONE_RELEASE_VERIFY_TRIES:-4}
VERIFY_PAUSE=${GCLONE_RELEASE_VERIFY_PAUSE:-5}
UNANSWERED=""
asked() {
    what=$1
    shift
    try=1
    while ! "$@" >"$WORK/asked.out" 2>"$WORK/asked.err"; do
        if [ "$try" -ge "$VERIFY_TRIES" ]; then
            UNANSWERED="$UNANSWERED
  - $what: $(tail -n 2 "$WORK/asked.err" | one_line)"
            return 1
        fi
        try=$((try + 1))
        sleep "$VERIFY_PAUSE"
    done
    return 0
}

# `<sha256>  <name>` lines of the files in DIR, sorted by name.
local_digests() {
    (cd "$1" && for f in *; do printf '%s  %s\n' "$(sha256_of "$f")" "$f"; done) | sort -k 2
}

# ---------------------------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------------------------

# This Mac, the tools, a gh that is signed in; the tag at the same commit here and on GitHub.
# Sets COMMIT, VERSION and VIEWER_ASSET. Needs no write access and no signing identity.
basics() {
    [ "$(uname -s)" = Darwin ] || die "this script runs on macOS (codesign, the Developer ID identity)"
    arch=$(uname -m)
    if [ "$arch" != arm64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" != 1 ]; then
        die "this script runs on an Apple-silicon Mac: it runs the arm64 binary it signs"
    fi
    for tool in gh git codesign shasum tar otool file lipo cmp awk sed security; do
        have "$tool" || die "'$tool' is needed and not installed"
    done
    if [ "$SELFTEST" = 1 ]; then
        gh --version | grep -q 'fake-gh' ||
            die "the self-test runs against the fake gh only (tests/release/fake-gh.sh first on PATH)"
    fi
    gh auth status >/dev/null 2>&1 || die "the GitHub CLI is not signed in (gh auth login)"
    resolve_tag
}

preconditions() {
    step "1. Preconditions"
    basics
    [ "$(gh api "repos/$REPO" --jq .permissions.push 2>/dev/null)" = true ] ||
        die "this GitHub login may not write to $REPO"
    [ "$(gh api "repos/$REPO/immutable-releases" --jq .enabled 2>/dev/null)" = true ] ||
        die "immutable releases are not enabled for $REPO" \
            "Switch them on first: Settings → General → Releases → \"Enable release immutability\"." \
            "Without them a published file can be replaced, and step 16 cannot verify anything."
    signing_identity
}

resolve_tag() {
    COMMIT=$(git -C "$ROOT" rev-parse -q --verify "refs/tags/$TAG^{commit}" 2>/dev/null) ||
        die "the tag $TAG does not exist in this checkout ($ROOT)" "git fetch --tags"
    remote=$(git -C "$ROOT" ls-remote --tags origin "refs/tags/$TAG" "refs/tags/$TAG^{}" 2>/dev/null |
        awk '{ commit = $1 } END { print commit }')
    [ -n "$remote" ] || die "the tag $TAG does not exist on GitHub (origin)"
    [ "$remote" = "$COMMIT" ] ||
        die "the tag $TAG is at $COMMIT here and at $remote on GitHub"
    version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -n 1)
    VERSION=${TAG#v}
    say "   tag $TAG = commit $COMMIT (this checkout's Cargo.toml says $version)"
    VIEWER_ASSET="gclone-viewer-$VERSION.tar.gz"
}

signing_identity() {
    if [ "$SELFTEST" = 1 ]; then
        IDENTITY="-"
        say "   (self-test: signing ad hoc; no keychain and no identity is used)"
        return 0
    fi
    keychain_args=""
    if [ -n "${GCLONE_SIGN_KEYCHAIN:-}" ]; then
        [ -f "$GCLONE_SIGN_KEYCHAIN" ] || die "GCLONE_SIGN_KEYCHAIN names no file"
        say "   unlocking the signing keychain (it is locked again when this script ends)"
        KEYCHAIN_TO_LOCK=$GCLONE_SIGN_KEYCHAIN
        security unlock-keychain "$GCLONE_SIGN_KEYCHAIN" || die "the signing keychain was not unlocked"
        keychain_args=$GCLONE_SIGN_KEYCHAIN
    else
        say "   WARNING: GCLONE_SIGN_KEYCHAIN is not set. With the identity in the login keychain,"
        say "   every program of this user can sign as you without being asked (README, \"Publishing a release\")."
    fi
    # Only identities of type "Developer ID Application" count; an "Apple Distribution" or
    # "Apple Development" identity beside it is ignored.
    # shellcheck disable=SC2086 # keychain_args is one word or none
    identities=$(security find-identity -v -p codesigning $keychain_args 2>/dev/null |
        sed -n 's/^ *[0-9]*) \([0-9A-F]\{40\}\) "Developer ID Application: .*$/\1/p')
    if [ -n "${GCLONE_SIGN_IDENTITY:-}" ]; then
        printf '%s\n' "$identities" | grep -qx "$GCLONE_SIGN_IDENTITY" ||
            die "GCLONE_SIGN_IDENTITY names no identity of type \"Developer ID Application\" in the keychain"
        IDENTITY=$GCLONE_SIGN_IDENTITY
    else
        count=$(printf '%s\n' "$identities" | grep -c . || true)
        [ "$count" = 1 ] ||
            die "the keychain holds $count identities of type \"Developer ID Application\"; exactly one is needed" \
                "Name one with GCLONE_SIGN_IDENTITY=<its SHA-1 hash> (security find-identity -v -p codesigning)."
        IDENTITY=$identities
    fi
    say "   one Developer ID Application identity found"
}

check_draft() {
    step "2. The draft release"
    [ "$(release_field isDraft .isDraft)" = true ] ||
        die "release $TAG is not a draft" \
            "A published release is never touched. If it was published by mistake, make a new patch release." \
            "To verify a published release: scripts/release-sign-macos.sh --verify-published $TAG"
    # What the workflow makes — four attested archives and SHA256SUMS — and what an earlier run
    # of this script may have added or, with an upload that was cut off, taken away: the
    # signed archive and SHA256SUMS are this script's to make (again). `gh release upload
    # --clobber` deletes the old asset before it uploads the new one, so each of the two can
    # be missing after an interrupted step 13.
    # shellcheck disable=SC2086 # LINUX_ASSETS is a list of names
    archives=$(printf '%s\n' $LINUX_ASSETS "$MAC_ASSET" "$VIEWER_ASSET" | sort)
    names=$(release_names) || die "cannot read the files of the draft $TAG"
    others=$(printf '%s\n' "$names" | grep -vx -e "$SIGNED_ASSET" -e "$SUMS" || true)
    [ "$others" = "$archives" ] ||
        die "the draft does not hold exactly the files the release workflow makes" \
            "expected: $(printf '%s\n' "$archives" "$SUMS" | sort | one_line)" \
            "found:    $(printf '%s\n' "$names" | one_line)"
    HAS_SUMS=0
    HAS_SIGNED=0
    ! printf '%s\n' "$names" | grep -qx "$SUMS" || HAS_SUMS=1
    ! printf '%s\n' "$names" | grep -qx "$SIGNED_ASSET" || HAS_SIGNED=1
    if [ "$HAS_SIGNED" = 1 ]; then
        # An earlier run got as far as the upload. The signed archive is made again from the
        # attested one; nothing of that run is trusted.
        say "   an earlier run uploaded $SIGNED_ASSET; it will be replaced"
    fi
    if [ "$HAS_SUMS" = 0 ]; then
        say "   the draft has no $SUMS (an upload of an earlier run was cut off after the old"
        say "   file was removed): the list is made again from the attested archives"
    fi
    say "   a draft with: $(printf '%s\n' "$names" | one_line)"
}

download() {
    step "3. Download"
    mkdir "$WORK/ci"
    wanted="$LINUX_ASSETS $MAC_ASSET $VIEWER_ASSET"
    [ "$HAS_SUMS" = 0 ] || wanted="$wanted $SUMS"
    for name in $wanted; do
        gh release download "$TAG" --repo "$REPO" --pattern "$name" --dir "$WORK/ci" >/dev/null ||
            die "cannot download $name of the draft"
        [ -f "$WORK/ci/$name" ] || die "the download of $name left no file"
    done
    local_digests "$WORK/ci" | sed 's/^/   /'
}

# check_sums LIST DIR NAMES…: the checksum list LIST names exactly NAMES, and every file in
# DIR has the hash the list gives it.
check_sums() {
    list=$1
    dir=$2
    shift 2
    listed=$(awk '{ name = $2; sub(/^\*/, "", name); print name }' "$list" | sort)
    wanted=$(printf '%s\n' "$@" | sort)
    [ "$listed" = "$wanted" ] ||
        die "$SUMS lists other files than the release holds" \
            "listed: $(printf '%s\n' "$listed" | one_line)" "wanted: $(printf '%s\n' "$wanted" | one_line)"
    awk 'NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ { bad = 1 } END { exit bad }' "$list" ||
        die "$SUMS has a line that is not \"<sha256>  <name>\""
    for name in "$@"; do
        want=$(awk -v name="$name" '{ n = $2; sub(/^\*/, "", n); if (n == name) print $1 }' "$list")
        [ "$(sha256_of "$dir/$name")" = "$want" ] ||
            die "$name does not match its line in $SUMS" "listed: $want" "file:   $(sha256_of "$dir/$name")"
    done
}

verify_ci_assets() {
    step "4. Attestations and checksums of the workflow's files"
    for name in $LINUX_ASSETS "$MAC_ASSET" "$VIEWER_ASSET"; do
        attested "$WORK/ci/$name" ||
            die "$name has no valid build-provenance attestation for $REPO/$WORKFLOW on refs/tags/$TAG at $COMMIT" \
                "$(tail -n 3 "$WORK/attest.err" 2>/dev/null)" \
                "It is not what the release workflow built. Nothing was signed and nothing was changed."
        say "   attested: $name"
    done
    # The workflow's list: `ci-sums`. It is DERIVED — a line per attested archive — and what
    # the draft holds under that name is only compared with it:
    #  - the draft's list as the workflow made it: the same lines;
    #  - the draft's list with the signed archive's line as well (an earlier run of this
    #    script got as far as the upload, whether or not the signed archive is still there):
    #    that line is this script's own and is made again;
    #  - no list in the draft (the upload of an earlier run removed the old one and did not
    #    get to send the new one): made from the four archives that were just verified.
    # shellcheck disable=SC2086
    (cd "$WORK/ci" && shasum -a 256 $LINUX_ASSETS "$MAC_ASSET" "$VIEWER_ASSET") | sort -k 2 >"$WORK/ci-sums"
    if [ "$HAS_SUMS" = 1 ]; then
        grep -v "  $SIGNED_ASSET\$" "$WORK/ci/$SUMS" >"$WORK/draft-sums" || true
        if ! cmp -s "$WORK/ci/$SUMS" "$WORK/draft-sums" && [ "$HAS_SIGNED" = 0 ]; then
            say "   $SUMS of the draft lists $SIGNED_ASSET, which the draft does not hold (an upload of"
            say "   an earlier run was cut off after the old archive was removed): that line is dropped"
        fi
        # Everything else in the draft's list has to be the workflow's, line for line.
        # shellcheck disable=SC2086
        check_sums "$WORK/draft-sums" "$WORK/ci" $LINUX_ASSETS "$MAC_ASSET" "$VIEWER_ASSET"
        rm -f "$WORK/ci/$SUMS"
    fi
    # What GitHub reports for the draft's archives is what was downloaded.
    reported=$(release_digests | grep -v -e "  $SIGNED_ASSET\$" -e "  $SUMS\$" || true)
    [ "$reported" = "$(local_digests "$WORK/ci")" ] ||
        die "the digests GitHub reports for the draft's files are not those of the downloads"
    say "   the attested archives agree with $SUMS and with the digests GitHub reports"
}

# The attested macOS archive is at ${MAC_ARCHIVE:-$WORK/ci/$MAC_ASSET}.
unpack() {
    step "5. Unpack the attested macOS archive"
    archive=${MAC_ARCHIVE:-$WORK/ci/$MAC_ASSET}
    listing=$(tar -tvzf "$archive")
    [ "$(printf '%s\n' "$listing" | grep -c .)" = 1 ] ||
        die "$MAC_ASSET holds more than one member:" "$listing"
    printf '%s\n' "$listing" | grep -Eq '^-[rwx-]{9} .* gclone$' ||
        die "the one member of $MAC_ASSET is not a regular file called gclone:" "$listing"
    mkdir "$WORK/attested"
    tar -xzf "$archive" -C "$WORK/attested" gclone
    CI_BIN="$WORK/attested/gclone"
    [ -f "$CI_BIN" ] && [ ! -L "$CI_BIN" ] || die "unpacking $MAC_ASSET gave no regular file"
    file "$CI_BIN" | grep -q 'Mach-O 64-bit executable arm64' ||
        die "the binary is not an arm64 Mach-O executable: $(file -b "$CI_BIN")"
    [ "$(lipo -archs "$CI_BIN")" = arm64 ] || die "the binary is not thin arm64: $(lipo -archs "$CI_BIN")"
    codesign --verify --strict "$CI_BIN" 2>/dev/null ||
        die "the attested binary's own (ad hoc) signature does not verify: bytes were appended or changed"
    flags=$(sig_flags "$CI_BIN")
    case "$flags" in
        *adhoc*) ;;
        *) die "the attested binary is not ad hoc signed (flags $flags): it is not what the workflow links" ;;
    esac
    foreign=$(otool -L "$CI_BIN" | tail -n +2 | awk '{ print $1 }' | grep -Ev '^(/usr/lib/|/System/Library/)' || true)
    [ -z "$foreign" ] ||
        die "the binary links libraries outside the system; it would not start under the hardened runtime:" "$foreign"
    say "   one member, gclone: thin arm64, ad hoc signed ($flags), system libraries only"
}

sign() {
    step "6. Sign a copy"
    mkdir "$WORK/signed"
    SIGNED_BIN="$WORK/signed/gclone"
    cp "$CI_BIN" "$SIGNED_BIN"
    chmod 755 "$SIGNED_BIN"
    if [ "$SELFTEST" = 1 ]; then
        codesign --force --sign - --identifier "$IDENTIFIER" --options runtime "$SIGNED_BIN" 2>/dev/null ||
            die "codesign failed"
    elif [ -n "${GCLONE_SIGN_KEYCHAIN:-}" ]; then
        codesign --force --sign "$IDENTITY" --keychain "$GCLONE_SIGN_KEYCHAIN" --identifier "$IDENTIFIER" \
            --options runtime --timestamp "$SIGNED_BIN" || die "codesign failed"
    else
        codesign --force --sign "$IDENTITY" --identifier "$IDENTIFIER" --options runtime --timestamp "$SIGNED_BIN" ||
            die "codesign failed"
    fi
    say "   signed: identifier $IDENTIFIER, hardened runtime, no entitlements"
}

check_signature() {
    step "7. The signature"
    verify_signed "$SIGNED_BIN" "the signed binary"
    say "   flags $(sig_flags "$SIGNED_BIN"), no entitlements, identifier $(sig_identifier "$SIGNED_BIN")"
    if [ "$SELFTEST" != 1 ]; then
        say "   signed by team $(sig_team "$SIGNED_BIN") — this is public in every copy of the binary"
    fi
}

continuity() {
    step "8. Continuity with the previous signed release"
    new_requirement=$(sig_requirement "$SIGNED_BIN")
    previous=""
    # Both questions fail CLOSED. "No earlier signed release" must be something GitHub said:
    # a `gh release list` that failed inside `for … in $(…)` gave an empty list, and a `gh
    # release view` that failed in a pipeline read as "that release has no signed archive" —
    # either way the script announced the FIRST signed release, and a typed confirmation
    # published a release whose designated requirement nobody compared with the previous one.
    tags=$(gh release list --repo "$REPO" --exclude-drafts --limit 50 --json tagName --jq '.[].tagName') ||
        die "cannot list the releases of $REPO" \
            "Whether an earlier release is signed could not be asked. Nothing was changed; run again."
    for tag in $tags; do
        [ "$tag" != "$TAG" ] || continue
        names=$(release_names "$tag") ||
            die "cannot read the files of release $tag" \
                "Whether it carries $SIGNED_ASSET could not be asked. Nothing was changed; run again."
        if printf '%s\n' "$names" | grep -qx "$SIGNED_ASSET"; then
            previous=$tag
            break
        fi
    done
    if [ -z "$previous" ]; then
        say "   No published release carries $SIGNED_ASSET: this is the FIRST signed release."
        say "   Every later release will have to satisfy this designated requirement:"
        say "     $new_requirement"
        say "   It names the team that signs gclone from now on. A change needs every user to pass"
        say "   --allow-signer-change to install.sh."
        confirm_typed "   Is this the requirement gclone releases are to be held to?" "first-signed-release"
        return 0
    fi
    mkdir "$WORK/previous"
    gh release download "$previous" --repo "$REPO" --pattern "$SIGNED_ASSET" --dir "$WORK/previous" >/dev/null ||
        die "cannot download $SIGNED_ASSET of $previous"
    [ "$(tar -tzf "$WORK/previous/$SIGNED_ASSET")" = gclone ] ||
        die "$SIGNED_ASSET of $previous does not hold exactly one member called gclone"
    tar -xzf "$WORK/previous/$SIGNED_ASSET" -C "$WORK/previous" gclone
    verify_signed "$WORK/previous/gclone" "the signed binary of $previous"
    old_requirement=$(sig_requirement "$WORK/previous/gclone")
    [ "$new_requirement" = "$old_requirement" ] ||
        die "the designated requirement differs from that of $previous" \
            "$previous: $old_requirement" "$TAG: $new_requirement" \
            "A release signed by another identity or under another identifier is not published by this script."
    codesign --verify -R="$old_requirement" "$SIGNED_BIN" 2>/dev/null ||
        die "the new binary does not satisfy the designated requirement of $previous"
    say "   the same designated requirement as $previous, and the new binary satisfies it"
}

equality() {
    step "9. The signed binary is the attested one apart from the signature"
    same_apart_from_signature "$CI_BIN" "$SIGNED_BIN" ||
        die "the signed binary differs from the attested one in more than its signature"
    say "   identical after removing both signatures"
}

smoke() {
    step "10. Run the signed binary"
    home="$WORK/home"
    mkdir -p "$home/src"
    printf 'release smoke test\n' >"$home/src/a.txt"
    printf 'a passphrase for the smoke test only\n' >"$home/pass"
    run() {
        HOME="$home" GCLONE_CONFIG_DIR="$home/config" GCLONE_STATE_DIR="$home/state" \
            GCLONE_KEYSTORE_TRIAL=0 "$SIGNED_BIN" "$@"
    }
    shown=$(run --version) || die "the signed binary does not start"
    case "$shown" in
        "gclone $VERSION ($MAC_TARGET, "*) ;;
        *) die "the signed binary says '$shown', not gclone $VERSION for $MAC_TARGET" ;;
    esac
    say "   $shown"
    run login --vault-dir "$home/vault" --passphrase-file "$home/pass" >/dev/null 2>"$WORK/smoke.err" ||
        die "the signed binary cannot create a directory vault" "$(tail -n 3 "$WORK/smoke.err")"
    run copy "$home/src" :smoke >/dev/null 2>"$WORK/smoke.err" ||
        die "the signed binary cannot copy" "$(tail -n 3 "$WORK/smoke.err")"
    [ "$(run cat :smoke/a.txt 2>/dev/null)" = "release smoke test" ] ||
        die "the signed binary does not read back what it copied"
    # The Secure Enclave of this Mac, from the signed binary: a key is made and discarded.
    if run keystore check >"$WORK/smoke.out" 2>&1; then
        say "   login, copy, cat and \`keystore check\` work"
    elif [ "$SELFTEST" = 1 ] && [ "${GCLONE_REQUIRE_ENCLAVE:-0}" != 1 ] && grep -q '^New key .*FAILED' "$WORK/smoke.out"; then
        # A machine without a Secure Enclave (a hosted CI runner) can run the self-test; the
        # owner's Mac, where releases are signed, cannot skip this.
        say "   login, copy and cat work"
        say "   SKIPPED: \`keystore check\` — no Secure Enclave on this machine (self-test only)"
    else
        die "\`gclone keystore check\` fails with the signed binary:" "$(tail -n 6 "$WORK/smoke.out")"
    fi
}

notarize() {
    step "11. Notarization"
    if [ -z "${GCLONE_NOTARY_PROFILE:-}" ] || [ "$SELFTEST" = 1 ]; then
        say "   skipped: GCLONE_NOTARY_PROFILE is not set. Gatekeeper will call a browser download"
        say "   \"Unnotarized Developer ID\"; installs through install.sh are not affected."
        return 0
    fi
    have xcrun || die "xcrun is needed for notarization"
    ditto -c -k "$SIGNED_BIN" "$WORK/notarize.zip"
    xcrun notarytool submit "$WORK/notarize.zip" --keychain-profile "$GCLONE_NOTARY_PROFILE" --wait \
        >"$WORK/notary.out" 2>&1 || die "notarytool failed:" "$(tail -n 5 "$WORK/notary.out")"
    grep -q 'status: Accepted' "$WORK/notary.out" ||
        die "the notary service did not accept the binary:" "$(tail -n 5 "$WORK/notary.out")"
    # A bare executable cannot be stapled: Gatekeeper asks Apple online.
    say "   accepted by the notary service"
}

pack() {
    step "12. Pack"
    mkdir "$WORK/out"
    COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata --uid 0 --gid 0 --numeric-owner \
        -czf "$WORK/out/$SIGNED_ASSET" -C "$WORK/signed" gclone
    [ "$(tar -tzf "$WORK/out/$SIGNED_ASSET")" = gclone ] || die "the packed archive is not one member called gclone"
    # What comes out of the archive is what was verified.
    mkdir "$WORK/repacked"
    tar -xzf "$WORK/out/$SIGNED_ASSET" -C "$WORK/repacked" gclone
    cmp -s "$WORK/repacked/gclone" "$SIGNED_BIN" || die "the archive does not give back the signed binary"
    verify_signed "$WORK/repacked/gclone" "the binary in $SIGNED_ASSET"
    say "   $SIGNED_ASSET: $(sha256_of "$WORK/out/$SIGNED_ASSET")"
}

upload() {
    step "13. SHA256SUMS and upload"
    # The workflow's list — every line was checked in step 4 — plus the signed archive's line.
    {
        cat "$WORK/ci-sums"
        printf '%s  %s\n' "$(sha256_of "$WORK/out/$SIGNED_ASSET")" "$SIGNED_ASSET"
    } | sort -k 2 >"$WORK/out/$SUMS"
    sed 's/^/   /' "$WORK/out/$SUMS"
    gh release upload "$TAG" --repo "$REPO" --clobber "$WORK/out/$SIGNED_ASSET" >/dev/null ||
        die "cannot upload $SIGNED_ASSET to the draft"
    gh release upload "$TAG" --repo "$REPO" --clobber "$WORK/out/$SUMS" >/dev/null ||
        die "cannot upload $SUMS to the draft"
    say "   uploaded to the draft"
}

check_whole_draft() {
    step "14. The draft as a whole"
    mkdir "$WORK/final"
    # shellcheck disable=SC2086
    wanted=$(printf '%s\n' $LINUX_ASSETS "$MAC_ASSET" "$SIGNED_ASSET" "$VIEWER_ASSET" "$SUMS" | sort)
    [ "$(release_names)" = "$wanted" ] ||
        die "the draft does not hold exactly the expected files" "found: $(release_names | one_line)"
    [ "$(release_field isDraft .isDraft)" = true ] || die "the release is no longer a draft"
    for name in $wanted; do
        gh release download "$TAG" --repo "$REPO" --pattern "$name" --dir "$WORK/final" >/dev/null ||
            die "cannot download $name of the draft"
    done
    # shellcheck disable=SC2086
    check_sums "$WORK/final/$SUMS" "$WORK/final" $LINUX_ASSETS "$MAC_ASSET" "$SIGNED_ASSET" "$VIEWER_ASSET"
    for name in $LINUX_ASSETS "$MAC_ASSET" "$VIEWER_ASSET"; do
        attested "$WORK/final/$name" || die "$name of the draft no longer verifies against its attestation"
    done
    cmp -s "$WORK/final/$SIGNED_ASSET" "$WORK/out/$SIGNED_ASSET" ||
        die "$SIGNED_ASSET of the draft is not the archive this run made"
    cmp -s "$WORK/final/$SUMS" "$WORK/out/$SUMS" || die "$SUMS of the draft is not the list this run made"
    # L: the files that were checked, and their hashes. Everything from here on is held to it.
    local_digests "$WORK/final" >"$WORK/L"
    [ "$(release_digests)" = "$(cat "$WORK/L")" ] ||
        die "the digests GitHub reports for the draft are not those of the checked files"
    say "   every file downloaded again and checked:"
    sed 's/^/   /' "$WORK/L"
}

publish() {
    step "15. Publish"
    say "   release $TAG of $REPO, commit $COMMIT"
    sed 's/^/   /' "$WORK/out/$SUMS"
    say "   Publishing cannot be undone: with immutable releases, a published file cannot be"
    say "   replaced or withdrawn, and the signed binary carries the signing certificate."
    confirm_typed "   Publish this release?" "publish $TAG"
    # Immediately before: the draft is still exactly what was checked.
    [ "$(release_digests)" = "$(cat "$WORK/L")" ] ||
        die "the draft changed after it was checked — nothing was published" \
            "Somebody or something with write access replaced a file. Find out what before running again."
    [ "$(release_field isDraft .isDraft)" = true ] || die "the release is no longer a draft"
    # The notes without the workflow's "draft until signed" paragraph; the team is not named.
    release_field body .body | awk -v mark="$DRAFT_MARK" '
        index($0, mark) == 1 { skipping = 1; next }
        skipping && $0 == "" { skipping = 0; next }
        { skipping = 0; print }' >"$WORK/notes.md"
    {
        # shellcheck disable=SC2016 # the backticks are Markdown
        printf 'macOS: `%s` is the build of `%s` with a Developer ID signature, identical apart from the signature; `install.sh` installs it and checks both. `%s` is the unsigned, attested build.\n\n' \
            "$SIGNED_ASSET" "$MAC_ASSET" "$MAC_ASSET"
        cat "$WORK/notes.md"
    } >"$WORK/notes-final.md"
    gh release edit "$TAG" --repo "$REPO" --draft=false --latest --notes-file "$WORK/notes-final.md" >/dev/null ||
        die "publishing failed; the release may still be a draft — look at it before running again"
    say "   published"
}

# verify_published_files DIR: what steps 16 and --verify-published ask GitHub about a
# published release whose files are in DIR, each question with retries. Fills UNANSWERED.
verify_published_files() {
    asked "\`gh release verify $TAG\`" gh release verify "$TAG" --repo "$REPO" || true
    for path in "$1"/*; do
        asked "\`gh release verify-asset\` for $(basename "$path")" gh release verify-asset "$TAG" "$path" --repo "$REPO" || true
    done
}

# install_from_release DIR: install.sh installs the release (the files of DIR in the
# self-test, which has no GitHub to download from) and the installed binary runs.
install_from_release() {
    if [ "$SELFTEST" = 1 ]; then
        asked "install.sh" env GCLONE_TEST_ACCEPT_ADHOC_SIGNATURE=1 sh "$ROOT/install.sh" --base-url "$1" --dir "$WORK/installed" || return 0
    else
        asked "install.sh --require-attestation" sh "$ROOT/install.sh" --repo "$REPO" --version "$TAG" --dir "$WORK/installed" --require-attestation || return 0
    fi
    cat "$WORK/asked.out" "$WORK/asked.err" >"$WORK/install.out"
    "$WORK/installed/gclone" --version >/dev/null 2>&1 ||
        UNANSWERED="$UNANSWERED
  - the binary that install.sh installed does not run"
}

# The two ways a published release can fail to verify are told apart: a file that IS another
# one than the checked one (GitHub's own digest of it differs: nothing repairs that), and a
# question that could not be ASKED or was answered with an error (which says nothing yet).
cannot_be_repaired() {
    printf '\nrelease-sign-macos.sh: THE PUBLISHED RELEASE DOES NOT VERIFY: %s\n' "$1" >&2
    shift
    for line in "$@"; do printf '  %s\n' "$line" >&2; done
    printf '  This cannot be repaired in place: publish a new patch release and tell users not\n' >&2
    printf '  to install %s.\n' "$TAG" >&2
    exit 1
}
not_verified_yet() {
    printf '\nrelease-sign-macos.sh: THE PUBLISHED RELEASE COULD NOT BE VERIFIED YET. Not answered, or answered with an error:%s\n' "$UNANSWERED" >&2
    printf '  The release IS published, and the files in it are the ones this script checked (their\n' >&2
    printf '  digests were compared). This is not a verdict about the release: a network error, a rate\n' >&2
    printf '  limit or an attestation GitHub does not serve yet looks the same. Run\n' >&2
    printf '      scripts/release-sign-macos.sh --verify-published %s\n' "$TAG" >&2
    printf '  again — it needs no draft and changes nothing — before concluding anything.\n' >&2
    exit 3
}

after_publishing() {
    step "16. The published release"
    UNANSWERED=""
    draft=""
    asked "whether the release is published" release_field isDraft .isDraft && draft=$(cat "$WORK/asked.out")
    digests=""
    asked "the digests of the published files" release_digests && digests=$(cat "$WORK/asked.out")
    # The one definite failure: GitHub names other bytes than the checked ones.
    if [ -n "$digests" ] && [ "$digests" != "$(cat "$WORK/L")" ]; then
        cannot_be_repaired "the published digests are not those of the checked files." \
            "A file was replaced in the seconds before publishing, or GitHub reports something else than it serves."
    fi
    [ -z "$draft" ] || [ "$draft" = false ] ||
        UNANSWERED="$UNANSWERED
  - the release is still a draft (isDraft: $draft)"
    # The files of L, not fresh downloads: what was checked is what must be attested.
    verify_published_files "$WORK/final"
    install_from_release "$WORK/final"
    [ -z "$UNANSWERED" ] || not_verified_yet
    sed 's/^/   /' "$WORK/install.out"
    say ""
    say "Release $TAG is published and verified. Next: deploy the viewer (worker/README.md), then"
    say "push main (git push origin main): until now it served the install.sh of the release before."
}

# --verify-published <tag>: the published release, from nothing but GitHub and this checkout's
# tag. No draft, no state of an earlier run, no signing identity; changes nothing.
verify_published() {
    step "The published release $TAG, verified from GitHub"
    basics
    [ "$(release_field isDraft .isDraft)" = false ] ||
        die "release $TAG is not published (it is a draft, or it does not exist)"
    # shellcheck disable=SC2086
    wanted=$(printf '%s\n' $LINUX_ASSETS "$MAC_ASSET" "$SIGNED_ASSET" "$VIEWER_ASSET" "$SUMS" | sort)
    names=$(release_names) || die "cannot read the files of release $TAG"
    [ "$names" = "$wanted" ] ||
        die "release $TAG does not hold exactly the files of a signed release" \
            "expected: $(printf '%s\n' "$wanted" | one_line)" "found:    $(printf '%s\n' "$names" | one_line)"
    mkdir "$WORK/final"
    for name in $wanted; do
        gh release download "$TAG" --repo "$REPO" --pattern "$name" --dir "$WORK/final" >/dev/null ||
            die "cannot download $name of release $TAG" "Nothing is concluded from that; run again."
    done
    say "   downloaded:"
    local_digests "$WORK/final" | sed 's/^/   /'
    # What the files are — checked on the files themselves; a difference here is definite.
    # shellcheck disable=SC2086
    check_sums "$WORK/final/$SUMS" "$WORK/final" $LINUX_ASSETS "$MAC_ASSET" "$SIGNED_ASSET" "$VIEWER_ASSET"
    say "   $SUMS lists exactly these files with these hashes"
    MAC_ARCHIVE="$WORK/final/$MAC_ASSET"
    unpack
    [ "$(tar -tzf "$WORK/final/$SIGNED_ASSET")" = gclone ] ||
        die "$SIGNED_ASSET does not hold exactly one member called gclone"
    mkdir "$WORK/signed"
    tar -xzf "$WORK/final/$SIGNED_ASSET" -C "$WORK/signed" gclone
    verify_signed "$WORK/signed/gclone" "the binary in $SIGNED_ASSET"
    same_apart_from_signature "$CI_BIN" "$WORK/signed/gclone" ||
        die "the signed binary differs from the attested one in more than its signature"
    say "   the signed binary: $(sig_flags "$WORK/signed/gclone"), no entitlements, identifier $(sig_identifier "$WORK/signed/gclone");"
    say "   identical to the attested one after removing both signatures"
    # What GitHub says about them — each question asked several times; an error is not a no.
    UNANSWERED=""
    digests=""
    asked "the digests of the published files" release_digests && digests=$(cat "$WORK/asked.out")
    if [ -n "$digests" ] && [ "$digests" != "$(local_digests "$WORK/final")" ]; then
        cannot_be_repaired "GitHub reports other digests for the published files than the downloads have."
    fi
    for name in $LINUX_ASSETS "$MAC_ASSET" "$VIEWER_ASSET"; do
        asked "the build-provenance attestation of $name" attested "$WORK/final/$name" || true
    done
    verify_published_files "$WORK/final"
    install_from_release "$WORK/final"
    [ -z "$UNANSWERED" ] || not_verified_yet
    sed 's/^/   /' "$WORK/install.out"
    say ""
    say "Release $TAG verifies: every file is attested (the four archives by the release workflow,"
    say "all of them as files of the published release), the signed binary is the attested one with"
    say "a signature, and install.sh installs it."
}

# start TAG: the tag is one, the traps are set, the work directory exists.
start() {
    TAG=$1
    case "$TAG" in
        v[0-9]*) ;;
        *) die "'$TAG' is not a release tag (v<version>)" ;;
    esac
    HAS_SUMS=1
    HAS_SIGNED=0
    MAC_ARCHIVE=""
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/gclone-release.XXXXXXXX")
    chmod 700 "$WORK"
}

run_release() {
    start "$1"
    preconditions
    check_draft
    download
    verify_ci_assets
    unpack
    sign
    check_signature
    continuity
    equality
    smoke
    notarize
    pack
    upload
    check_whole_draft
    publish
    after_publishing
}

usage() {
    cat <<'EOF'
Usage: scripts/release-sign-macos.sh <tag>
       scripts/release-sign-macos.sh --verify-published <tag>
       scripts/release-sign-macos.sh --selftest [--binary PATH]

Signs the macOS build of the draft release <tag> with the Developer ID identity of this Mac and
publishes the release, after verifying every file. See the head of the script and the README
("Publishing a release") for the procedure and the environment variables.

--verify-published verifies a release that IS published, from GitHub alone: every file against
SHA256SUMS, the four attestations, the signature and its equality with the attested build,
`gh release verify`, `gh release verify-asset` for every file, and install.sh. It needs no
draft and no signing identity, changes nothing, and can be repeated: the way to find out what
a step 16 that could not reach GitHub left open.

--selftest runs the same code against a fake release directory, a fake `gh` and an ad hoc
signature, including the cases that must be refused. It touches neither GitHub nor a keychain.
--binary PATH: the gclone binary to release in the self-test (default: target/release/gclone).
EOF
}

main() {
    case "${1:-}" in
        "" | -h | --help)
            usage
            [ -n "${1:-}" ] || exit 2
            exit 0
            ;;
        --selftest)
            shift
            exec bash "$ROOT/tests/release/selftest.sh" "$@"
            ;;
        --run-under-selftest)
            # Only tests/release/selftest.sh starts the script this way, with its fake gh (the
            # preconditions refuse any other) and its own throw-away checkout.
            SELFTEST=1
            ROOT=${GCLONE_RELEASE_ROOT:?the self-test names its own checkout}
            shift
            ;;
    esac
    case "${1:-}" in
        --verify-published)
            [ $# -eq 2 ] || die "--verify-published takes one argument: the tag of the published release"
            start "$2"
            verify_published
            return 0
            ;;
        -*) die "unknown option '$1'" ;;
    esac
    [ $# -eq 1 ] || die "one argument: the tag of the draft release"
    run_release "$1"
}

# The self-test sources this file for its functions (GCLONE_RELEASE_LIB=1) instead of running it.
if [ "${GCLONE_RELEASE_LIB:-0}" != 1 ]; then
    main "$@"
fi
