#!/bin/sh
# gclone installer.
#
# Downloads the prebuilt gclone binary for this machine from the repository's GitHub Releases,
# checks it and puts it into ~/.local/bin. No sudo, nothing else is touched. Updating = running
# it again.
#
#   sh install.sh [--version vX.Y.Z] [--dir DIR]
#
# What "checks it" means. Always: the archive against the release's SHA256SUMS — which shows a
# damaged download and nothing more, because the list comes from the same release as the
# archive. With the GitHub CLI installed and signed in (`gh auth login`), also the archive's
# build-provenance attestation (`gh attestation verify`): GitHub's signed statement, kept
# outside the release's files, that these bytes were built by this repository's release
# workflow on this release's tag. Then a release whose files were replaced is refused. Without
# `gh` the script says in one line that only the checksum was checked.
#
# macOS: a release may also carry gclone-<target>-signed.tar.gz, the same binary with a
# Developer ID signature. Where SHA256SUMS lists it, that is what gets installed, after these
# checks: the signature verifies and is from an Apple-issued Developer ID certificate; it has
# the hardened runtime and nothing else (no entitlements, no other flag); and the signed
# binary is the unsigned one of the same release apart from the signature. With `gh`, the
# unsigned archive's attestation and the signed archive's place in the published release
# (`gh release verify-asset`) are verified as well. And continuity, for whatever is about to
# be installed: if the gclone already in place is Developer ID signed, the new one must be
# signed by the same team under the same identifier — replacing a signed gclone with an
# unsigned one, or with one signed by somebody else, stops. The first signed install trusts
# the signer it finds (trust on first use). What this is worth: it holds for someone who runs
# a saved copy of this script; whoever can publish a release can normally change the script
# that the README pipes into `sh`.
#
# Options (each has an environment variable of the same meaning):
#   --version vX.Y.Z   GCLONE_VERSION       the release to install (default: the latest)
#   --dir DIR          GCLONE_INSTALL_DIR   where the binary goes (default: ~/.local/bin)
#   --repo OWNER/NAME  GCLONE_REPO          the GitHub repository that holds the releases
#   --target TRIPLE    GCLONE_TARGET        do not detect the machine, take this build
#   --base-url URL     GCLONE_BASE_URL      take gclone-<target>.tar.gz and SHA256SUMS from this
#                                           directory (https://…, file:///…, or the path of a
#                                           local directory) instead of GitHub
#   --no-attestation   GCLONE_ATTESTATION=skip      check against SHA256SUMS only (releases
#                                           before 0.5.0 carry no attestation of the binaries)
#   --require-attestation  GCLONE_ATTESTATION=require   install nothing that `gh` did not verify
#   --unsigned         GCLONE_UNSIGNED=1    macOS: install the unsigned, attested build although
#                                           the release has a signed one
#   --allow-signer-change  GCLONE_ALLOW_SIGNER_CHANGE=1   macOS: replace a Developer ID signed
#                                           gclone by one that is unsigned or signed by another
#                                           team or under another identifier
#
# A private repository needs a login: set GITHUB_TOKEN (or GH_TOKEN) to a token that may read
# the repository's contents, or be signed in with the GitHub CLI (`gh auth login`). The token
# is sent to the GitHub API only. A login that GitHub refuses does not stop the install from a
# public repository: the script says so and downloads without it.
#
# Needs: curl (wget is enough for a public repository), tar, gzip, and one of sha256sum,
# shasum, openssl. Optional: gh (the GitHub CLI), for the attestation. macOS: codesign (part of
# the system) for the signed build.

set -eu

# The repository whose releases are installed; override with --repo or GCLONE_REPO.
DEFAULT_REPO="dwahdany/gclone"

SUMS="SHA256SUMS"
API_DEFAULT="https://api.github.com"
WEB_DEFAULT="https://github.com"
# The workflow whose attestation counts, below the repository.
SIGNER_WORKFLOW=".github/workflows/release.yml"
# An Apple-issued Developer ID Application certificate, whoever the team is: no team is named
# in this script.
DEVELOPER_ID_REQUIREMENT='anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'

TMP=""
STAGED=""

say() { printf '%s\n' "$*"; }
note() { printf '%s\n' "$*" >&2; }
die() {
    printf 'install.sh: error: %s\n' "$1" >&2
    shift
    for line in "$@"; do printf '  %s\n' "$line" >&2; done
    exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
    [ -z "$STAGED" ] || rm -f "$STAGED"
    [ -z "$TMP" ] || rm -rf "$TMP"
}

usage() {
    cat <<'EOF'
Usage: sh install.sh [--version vX.Y.Z] [--dir DIR]

Installs the prebuilt gclone binary for this machine from the repository's GitHub Releases,
after checking it against the release's SHA256SUMS and — with the GitHub CLI signed in — its
build-provenance attestation. No sudo. Updating = running it again.

Options (each has an environment variable of the same meaning):
  --version vX.Y.Z   GCLONE_VERSION       the release to install (default: the latest)
  --dir DIR          GCLONE_INSTALL_DIR   where the binary goes (default: ~/.local/bin)
  --repo OWNER/NAME  GCLONE_REPO          the GitHub repository that holds the releases
  --target TRIPLE    GCLONE_TARGET        do not detect the machine, take this build
  --base-url URL     GCLONE_BASE_URL      take gclone-<target>.tar.gz and SHA256SUMS from this
                                          directory (https://..., file:///..., or the path of a
                                          local directory) instead of GitHub
  --no-attestation        GCLONE_ATTESTATION=skip     check against SHA256SUMS only (releases
                                          before 0.5.0 carry no attestation of the binaries)
  --require-attestation   GCLONE_ATTESTATION=require  install nothing that gh did not verify
  --unsigned              GCLONE_UNSIGNED=1   macOS: install the unsigned, attested build although
                                          the release has a Developer ID signed one
  --allow-signer-change   GCLONE_ALLOW_SIGNER_CHANGE=1  macOS: replace a Developer ID signed
                                          gclone by an unsigned one or one of another signer

macOS: where a release carries gclone-<target>-signed.tar.gz, that build is installed, after its
Developer ID signature was verified and it was shown to be the unsigned build of the same release
apart from the signature.

A private repository needs a login: set GITHUB_TOKEN (or GH_TOKEN) to a token that may read
the repository's contents, or be signed in with the GitHub CLI (gh auth login).
EOF
}

# --- which build -------------------------------------------------------------------------------

# Sets TARGET from `uname` unless it is given.
detect_target() {
    [ -z "$TARGET" ] || return 0
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
        Linux)
            # Android reports Linux too, but the Linux builds look for the DNS and certificate
            # configuration where Android has none.
            if [ "$(uname -o 2>/dev/null || true)" = "Android" ] || [ -n "${TERMUX_VERSION:-}" ]; then
                die "no prebuilt gclone for Android/Termux" \
                    "Build from source inside Termux (README, \"Building from source\")."
            fi
            os_part="unknown-linux-musl"
            ;;
        Darwin)
            os_part="apple-darwin"
            case "$arch" in
                x86_64 | amd64)
                    # A shell that runs under Rosetta reports x86_64 on Apple silicon.
                    if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ]; then
                        arch="arm64"
                    else
                        # The releases carry one macOS build, for Apple silicon.
                        die "no prebuilt gclone for Intel Macs" \
                            "The macOS build of a release is for Apple silicon (arm64) only." \
                            "Build from source instead (README, \"Building from source\")."
                    fi
                    ;;
            esac
            ;;
        MINGW* | MSYS* | CYGWIN* | Windows_NT)
            die "gclone does not run on Windows itself" \
                "Use it inside WSL2: open the WSL shell and run this script there."
            ;;
        *)
            die "no prebuilt gclone for the operating system '$os'" \
                "Prebuilt: Linux and macOS. Otherwise build from source (README, \"Building from source\")."
            ;;
    esac
    case "$arch" in
        x86_64 | amd64) arch_part="x86_64" ;;
        aarch64 | arm64) arch_part="aarch64" ;;
        *)
            die "no prebuilt gclone for the CPU architecture '$arch'" \
                "Prebuilt: x86_64 and aarch64 (arm64). Otherwise build from source (README, \"Building from source\")."
            ;;
    esac
    TARGET="$arch_part-$os_part"
}

# --- downloads ---------------------------------------------------------------------------------

# fetch URL OUT: an anonymous download. 0 on success.
fetch() {
    if have curl; then
        # shellcheck disable=SC2086 # CURL_PROTO is several words or none
        curl -fsSL $CURL_PROTO --retry 2 -o "$2" "$1"
    elif have wget; then
        # -nv, not -q: the reason of a failure is worth showing; a success stays silent.
        if ! wget_said=$(wget -nv -O "$2" "$1" 2>&1); then
            [ -z "$wget_said" ] || note "$wget_said"
            return 1
        fi
    else
        die "neither curl nor wget is installed" "Install curl and run this script again."
    fi
}

# api_fetch URL OUT ACCEPT: a download from the GitHub API with the token. The token goes to
# curl on its standard input, not on its command line, where other users could read it. curl
# does not pass the Authorization header on to the storage host a download redirects to.
api_fetch() {
    # shellcheck disable=SC2086 # CURL_PROTO is several words or none
    printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" |
        curl -fsSL $CURL_PROTO --retry 2 -K - -H "Accept: $3" -o "$2" "$1"
}

# asset_api_url RELEASE_JSON NAME: the API URL of the release asset of that name ("" if the
# release has none). In the API's answer an asset's "url" comes before its "name".
asset_api_url() {
    tr ',' '\n' <"$1" | awk -v name="$2" '
        match($0, /"url":[ \t]*"[^"]*\/releases\/assets\/[0-9]+"/) {
            url = substr($0, RSTART, RLENGTH)
            sub(/^"url":[ \t]*"/, "", url)
            sub(/"$/, "", url)
        }
        match($0, /"name":[ \t]*"[^"]*"/) {
            found = substr($0, RSTART, RLENGTH)
            sub(/^"name":[ \t]*"/, "", found)
            sub(/"$/, "", found)
            if (found == name && url != "") {
                print url
                exit
            }
        }'
}

# json_string FILE KEY: the first string value of that key.
json_string() {
    tr ',' '\n' <"$1" | awk -v key="$2" '
        {
            pattern = "\"" key "\":[ \t]*\"[^\"]*\""
            if (match($0, pattern)) {
                value = substr($0, RSTART, RLENGTH)
                sub(/^"[^"]*":[ \t]*"/, "", value)
                sub(/"$/, "", value)
                print value
                exit
            }
        }'
}

# Downloads the archive and the checksum list into $TMP and sets RELEASE (what to call it).
download_from_base_url() {
    base=${BASE_URL%/}
    RELEASE="$base"
    MODE=base
    for file in "$ASSET" "$SUMS"; do
        from_base_url "$file"
    done
}

# from_base_url NAME: one file of the --base-url directory into $TMP.
from_base_url() {
    base=${BASE_URL%/}
    # A local directory (file:///dir, or a path) is copied: no downloader is needed for it, and
    # wget cannot read file:// at all.
    local_dir=""
    case "$base" in
        file://localhost/*) local_dir=${base#file://localhost} ;;
        file:///*) local_dir=${base#file://} ;;
        *://*) ;;
        *) local_dir=$base ;;
    esac
    if [ -n "$local_dir" ]; then
        cp "$local_dir/$1" "$TMP/$1" ||
            die "cannot read $local_dir/$1"
    else
        fetch "$base/$1" "$TMP/$1" ||
            die "cannot download $base/$1"
    fi
}

# fetch_more NAME: one more file of the release that the archive came from, the same way.
fetch_more() {
    case "$MODE" in
        base) from_base_url "$1" ;;
        api)
            url=$(asset_api_url "$TMP/release.json" "$1")
            [ -n "$url" ] || die "release $RELEASE of $REPO has no $1, although its $SUMS lists it"
            api_fetch "$url" "$TMP/$1" "application/octet-stream" ||
                die "cannot download $1 of release $RELEASE from the GitHub API"
            ;;
        *)
            fetch "$ANON_BASE/$1" "$TMP/$1" ||
                die "cannot download $ANON_BASE/$1"
            ;;
    esac
}

# With the login. A login that gets no answer about the release (stale, expired, for another
# repository; or no curl to send it with) must not stand in the way of a public repository:
# then the download is tried without it. A release that the login does see is taken as it is.
download_with_token() {
    if [ -n "$TAG" ]; then
        release_url="$API/repos/$REPO/releases/tags/$TAG"
        what="release $TAG"
    else
        release_url="$API/repos/$REPO/releases/latest"
        what="the latest release"
    fi
    if ! have curl; then
        note "install.sh: curl is needed to use the GitHub login ($TOKEN_SOURCE); trying without the login"
        try_anonymous ||
            die "cannot download $what of $REPO without a login" \
                "If $REPO is a private repository: install curl and run this script again." \
                "Otherwise check the version and that the release has a build for $TARGET."
        return 0
    fi
    if ! api_fetch "$release_url" "$TMP/release.json" "application/vnd.github+json"; then
        note "install.sh: the GitHub API did not give $what of $REPO to the login ($TOKEN_SOURCE); trying without the login"
        try_anonymous ||
            die "cannot read $what of $REPO from the GitHub API (login: $TOKEN_SOURCE), and cannot download it without a login" \
                "Check that the repository name is right, that the release exists and that the" \
                "login may read the repository (a fine-grained token needs \"Contents: Read-only\")."
        return 0
    fi
    RELEASE=$(json_string "$TMP/release.json" tag_name)
    [ -n "$RELEASE" ] || die "the GitHub API's answer for $what of $REPO names no release"
    MODE=api
    for file in "$ASSET" "$SUMS"; do
        url=$(asset_api_url "$TMP/release.json" "$file")
        if [ -z "$url" ]; then
            if [ "$file" = "$ASSET" ]; then
                die "release $RELEASE of $REPO has no build for this machine ($ASSET)" \
                    "Build from source instead (README, \"Building from source\")."
            fi
            die "release $RELEASE of $REPO has no $file; refusing to install an unchecked download"
        fi
        api_fetch "$url" "$TMP/$file" "application/octet-stream" ||
            die "cannot download $file of release $RELEASE from the GitHub API"
    done
}

# try_anonymous: the archive and the checksum list without a login. 1 if one cannot be had;
# FAILED_URL is that one.
try_anonymous() {
    if [ -n "$TAG" ]; then
        base="$WEB/$REPO/releases/download/$TAG"
        RELEASE="$TAG"
    else
        base="$WEB/$REPO/releases/latest/download"
        RELEASE="latest"
    fi
    for file in "$ASSET" "$SUMS"; do
        if ! fetch "$base/$file" "$TMP/$file"; then
            FAILED_URL="$base/$file"
            return 1
        fi
    done
    MODE=anon
    ANON_BASE=$base
}

download_anonymous() {
    try_anonymous ||
        die "cannot download $FAILED_URL" \
            "If $REPO is a private repository: set GITHUB_TOKEN to a token that may read it," \
            "or sign in with the GitHub CLI (gh auth login), and run this script again." \
            "Otherwise check the version and that the release has a build for $TARGET."
}

# --- checksum ----------------------------------------------------------------------------------

sha256_of() {
    if have sha256sum; then
        sha256sum "$1" | awk '{ print $1 }'
    elif have shasum; then
        shasum -a 256 "$1" | awk '{ print $1 }'
    elif have openssl; then
        openssl dgst -sha256 -r "$1" | awk '{ print $1 }'
    else
        die "no tool to compute SHA-256 (sha256sum, shasum or openssl); refusing to install an unchecked download"
    fi
}

# sums_line NAME: the SHA-256 that SHA256SUMS lists for NAME ("" if it lists none).
sums_line() {
    awk -v name="$1" '
        {
            file = $2
            sub(/^\*/, "", file)
            if (file == name) {
                print tolower($1)
                exit
            }
        }' "$TMP/$SUMS"
}

# verify_checksum NAME: the downloaded NAME against its line in SHA256SUMS.
verify_checksum() {
    want=$(sums_line "$1")
    case "$want" in
        "") die "$SUMS of $RELEASE does not list $1; refusing to install an unchecked download" ;;
        *[!0-9a-f]*) die "$SUMS of $RELEASE holds no SHA-256 for $1" ;;
    esac
    [ "${#want}" -eq 64 ] || die "$SUMS of $RELEASE holds no SHA-256 for $1"
    got=$(sha256_of "$TMP/$1")
    if [ "$got" != "$want" ]; then
        die "checksum mismatch for $1 — nothing was installed" \
            "expected $want" \
            "got      $got" \
            "The download is damaged or is not what the release published. Try again."
    fi
}

# --- provenance --------------------------------------------------------------------------------

# Why the GitHub CLI cannot verify an attestation here ("" = it can): it has to be installed,
# new enough for what this script asks of it, and signed in with a login GitHub accepts.
#
# "New enough" is probed, not assumed: `gh attestation verify` exists since gh 2.49.0, but its
# `--source-ref` — without which an attestation of ANY build of the repository would do — only
# since 2.68.0. A gh in between answered "unknown flag", which this script used to report as
# "GitHub holds no statement that this file was built by …": the release accused for the
# tool's age, on every install.
GH_MINIMUM="2.68.0"
gh_unusable() {
    if ! have gh; then
        echo "the GitHub CLI (gh) is not installed"
    elif ! gh attestation verify --help 2>/dev/null | grep -q -e '--source-ref'; then
        echo "this GitHub CLI (gh) is too old to verify attestations: it needs gh $GH_MINIMUM or newer"
    elif ! gh auth status >/dev/null 2>&1; then
        echo "the GitHub CLI (gh) is not signed in"
    fi
}

checksum_only() {
    note "install.sh: note: $ASSET was checked against the release's $SUMS only ($1). That shows a damaged download, not a replaced release: the list comes from the same place as the archive."
}

# The archive's build-provenance attestation, when it can be asked for. An attestation that is
# asked for and does not verify stops the install: "no attestation" is exactly what a replaced
# archive looks like, so it is never taken for "nothing to check". Sets PROVENANCE to
# `verified` (and PROV_TAG to the release's tag) or to `unverified` (and PROV_WHY to why).
verify_provenance() {
    case "$ATTESTATION" in
        auto | require | skip) ;;
        *) die "GCLONE_ATTESTATION is '$ATTESTATION'; it is one of auto, require, skip" ;;
    esac
    PROVENANCE=unverified
    why=""
    if [ "$ATTESTATION" = skip ]; then
        why="--no-attestation"
    elif [ -n "$BASE_URL" ]; then
        why="--base-url names a directory, not a GitHub release"
    else
        why=$(gh_unusable)
    fi
    tag=$RELEASE
    if [ -z "$why" ] && [ "$tag" = latest ]; then
        # The archive came from .../releases/latest/download: which release is that?
        tag=$(gh release view --repo "$REPO" --json tagName --jq .tagName 2>/dev/null || true)
        [ -n "$tag" ] || why="the GitHub CLI could not name the latest release of $REPO"
    fi
    if [ -n "$why" ]; then
        [ "$ATTESTATION" != require ] ||
            die "the build-provenance attestation of $ASSET was not verified ($why) — nothing was installed" \
                "--require-attestation needs the GitHub CLI, signed in: https://cli.github.com, then gh auth login."
        PROV_WHY=$why
        return 0
    fi
    if ! gh_said=$(gh attestation verify "$TMP/$ASSET" --repo "$REPO" \
        --signer-workflow "$REPO/$SIGNER_WORKFLOW" --source-ref "refs/tags/$tag" \
        --deny-self-hosted-runners 2>&1); then
        die "the build-provenance attestation of $ASSET could not be verified — nothing was installed" \
            "$gh_said" \
            "GitHub holds no statement that this file was built by $REPO/$SIGNER_WORKFLOW on the tag $tag:" \
            "it is not what that release's build produced, or the release has no attestations." \
            "Releases before 0.5.0 carry none for the binaries; to install one of those, checked against" \
            "its $SUMS only, add --no-attestation."
    fi
    PROVENANCE=verified
    PROV_TAG=$tag
    note "install.sh: verified the build-provenance attestation of $ASSET (built by $REPO/$SIGNER_WORKFLOW on refs/tags/$tag)"
}

# --- the Developer ID signature (macOS) --------------------------------------------------------

# The flags field of a binary's code directory, e.g. `0x10000(runtime)`.
code_flags() { codesign -dv "$1" 2>&1 | sed -n 's/^CodeDirectory .* flags=\([^ ]*\) .*$/\1/p'; }

# The flags a signed release binary has, exactly: the hardened runtime and nothing else.
signed_flags() {
    if [ "$ADHOC_TEST" = 1 ]; then echo "0x10002(adhoc,runtime)"; else echo "0x10000(runtime)"; fi
}

# is_developer_id BINARY: signed with an Apple-issued Developer ID certificate.
is_developer_id() {
    if [ "$ADHOC_TEST" = 1 ]; then
        # Tests have no Developer ID: an ad hoc signature with the runtime flag stands in.
        case "$(code_flags "$1")" in
            *adhoc*runtime*) return 0 ;;
            *) return 1 ;;
        esac
    else
        codesign --verify -R="$DEVELOPER_ID_REQUIREMENT" "$1" >/dev/null 2>&1
    fi
}

# The designated requirement of a signed binary, as text.
designated_requirement() {
    codesign -d -r- "$1" 2>/dev/null | sed -n 's/^# designated => //p; s/^designated => //p' | head -n 1
}

# verify_signature BINARY: what the signed build of a release must be. Sets SIGNER.
verify_signature() {
    codesign --verify --strict "$1" >/dev/null 2>&1 ||
        die "the signature of $SIGNED does not verify — nothing was installed"
    is_developer_id "$1" ||
        die "$SIGNED is not signed with an Apple-issued Developer ID certificate — nothing was installed"
    flags=$(code_flags "$1")
    [ "$flags" = "$(signed_flags)" ] ||
        die "$SIGNED is signed with the flags '$flags' — nothing was installed" \
            "A release binary has the hardened runtime and nothing else: $(signed_flags)."
    # The exit status counts: a codesign that cannot answer the question (one that does not
    # know `--xml`, a failure of any kind) prints nothing either, and "nothing printed" must
    # mean "no entitlements" and nothing else.
    entitlements=$(codesign -d --entitlements - --xml "$1" 2>/dev/null) ||
        die "cannot read the entitlements of $SIGNED (codesign -d --entitlements - --xml failed) — nothing was installed" \
            "A release binary has none, and that could not be checked on this system. The unsigned," \
            "attested build installs with --unsigned."
    [ -z "$entitlements" ] ||
        die "$SIGNED is signed with entitlements — nothing was installed" \
            "A release binary has none: an entitlement can let other code run under its identity."
    team=$(codesign -dv "$1" 2>&1 | sed -n 's/^TeamIdentifier=//p')
    identifier=$(codesign -dv "$1" 2>&1 | sed -n 's/^Identifier=//p')
    SIGNER="Developer ID team $team, identifier $identifier"
}

# normalised IN OUT: IN without its signature, signed again ad hoc under one fixed name. Two
# binaries that differ only in their signature give the same bytes.
normalised() {
    cp "$1" "$2" && chmod u+w "$2" &&
        codesign --remove-signature "$2" >/dev/null 2>&1 &&
        codesign -f -s - -i gclone-compare "$2" >/dev/null 2>&1
}

# The signed build is the unsigned build of the same release apart from the signature. (Flags
# and entitlements are invisible to this comparison; verify_signature looks at those.)
verify_same_build() {
    if ! normalised "$TMP/unpacked/gclone" "$TMP/compare-unsigned" ||
        ! normalised "$TMP/signed/gclone" "$TMP/compare-signed"; then
        die "cannot compare the signed build with the unsigned one — nothing was installed"
    fi
    cmp -s "$TMP/compare-unsigned" "$TMP/compare-signed" ||
        die "$SIGNED is not $ASSET with a signature: the two binaries differ — nothing was installed" \
            "The signed build of a release is the attested build, signed. This one is something else."
}

# With gh: the signed archive is a file of the published release (an immutable release's own
# attestation). The unsigned archive's build provenance was verified before. Sets
# RELEASE_ASSET to `verified`, or to `unchecked` where this gh has no `release verify-asset`
# (it came with gh 2.75.0; an older one answered "unknown command", which is not "this file
# is not in the release").
GH_VERIFY_ASSET_MINIMUM="2.75.0"
verify_release_asset() {
    if ! gh release verify-asset --help >/dev/null 2>&1; then
        [ "$ATTESTATION" != require ] ||
            die "whether $SIGNED is a file of the published release $PROV_TAG was not verified — nothing was installed" \
                "This GitHub CLI (gh) has no \`gh release verify-asset\`: it needs gh $GH_VERIFY_ASSET_MINIMUM or newer." \
                "--require-attestation needs that; without it, or with --unsigned, the install goes on."
        RELEASE_ASSET=unchecked
        return 0
    fi
    if ! gh_said=$(gh release verify-asset "$PROV_TAG" "$TMP/$SIGNED" --repo "$REPO" 2>&1); then
        die "$SIGNED is not a file of the published release $PROV_TAG — nothing was installed" \
            "$gh_said"
    fi
    RELEASE_ASSET=verified
}

# Continuity, for whatever is about to be installed: a Developer ID signed gclone in place is
# replaced only by a binary that satisfies its designated requirement (the same team, the
# same identifier).
check_continuity() {
    have codesign || return 0
    [ -f "$DIR/gclone" ] || return 0
    is_developer_id "$DIR/gclone" || return 0
    requirement=$(designated_requirement "$DIR/gclone")
    if [ -n "$requirement" ] && codesign --verify -R="$requirement" "$1" >/dev/null 2>&1; then
        note "install.sh: the new binary is signed by the same signer as the installed one"
        return 0
    fi
    if is_developer_id "$1"; then
        problem="the installed gclone and this one are signed by different Developer ID signers"
    else
        problem="the installed gclone is signed; this one is not"
    fi
    if [ "$ALLOW_SIGNER_CHANGE" = 1 ]; then
        note "install.sh: warning: $problem; installing all the same (--allow-signer-change)"
        return 0
    fi
    die "$problem — nothing was installed" \
        "installed: $DIR/gclone, which requires: $requirement" \
        "An update is signed by the same Developer ID team under the same identifier. If the project" \
        "announced a change of its signing identity, or you want the unsigned build: --allow-signer-change."
}

# --- PATH --------------------------------------------------------------------------------------

# Says how $DIR gets onto PATH: in the file the login shell reads, and from when it applies.
path_hint() {
    say ""
    case "${SHELL:-}" in
        */zsh) rc=".zshrc" ;;
        */bash) rc=".bashrc" ;;
        *) rc=".profile" ;;
    esac
    # Debian's and Ubuntu's ~/.profile adds ~/.local/bin by itself, but only if the directory
    # exists at login. (bash reads ~/.profile only without ~/.bash_profile and ~/.bash_login.)
    if [ "$rc" != ".zshrc" ] && [ -n "${HOME:-}" ] && [ "$DIR" = "$HOME/.local/bin" ] &&
        [ ! -e "$HOME/.bash_profile" ] && [ ! -e "$HOME/.bash_login" ] &&
        grep -q '\.local/bin' "$HOME/.profile" 2>/dev/null; then
        say "$DIR is not on your PATH yet. Your ~/.profile adds it at login, now that the"
        say "directory exists: log out and in again. Until then, run $DIR/gclone."
        return 0
    fi
    say "$DIR is not on your PATH. Add it with this line in ~/$rc:"
    say "  export PATH=\"$DIR:\$PATH\""
    if [ "$rc" = ".profile" ]; then
        say "then log out and in again. Until then, run $DIR/gclone."
    else
        say "then open a new terminal. Until then, run $DIR/gclone."
    fi
}

# --- main --------------------------------------------------------------------------------------

main() {
    VERSION=${GCLONE_VERSION:-}
    DIR=${GCLONE_INSTALL_DIR:-}
    REPO=${GCLONE_REPO:-$DEFAULT_REPO}
    TARGET=${GCLONE_TARGET:-}
    BASE_URL=${GCLONE_BASE_URL:-}
    ATTESTATION=${GCLONE_ATTESTATION:-auto}
    UNSIGNED=${GCLONE_UNSIGNED:-0}
    ALLOW_SIGNER_CHANGE=${GCLONE_ALLOW_SIGNER_CHANGE:-0}
    # For tests: other hosts in place of api.github.com and github.com.
    API=${GCLONE_GITHUB_API:-$API_DEFAULT}
    WEB=${GCLONE_GITHUB_WEB:-$WEB_DEFAULT}

    while [ $# -gt 0 ]; do
        case "$1" in
            --version | --dir | --repo | --target | --base-url)
                [ $# -ge 2 ] || die "$1 needs a value"
                case "$1" in
                    --version) VERSION=$2 ;;
                    --dir) DIR=$2 ;;
                    --repo) REPO=$2 ;;
                    --target) TARGET=$2 ;;
                    --base-url) BASE_URL=$2 ;;
                esac
                shift 2
                ;;
            --no-attestation)
                ATTESTATION=skip
                shift
                ;;
            --require-attestation)
                ATTESTATION=require
                shift
                ;;
            --unsigned)
                UNSIGNED=1
                shift
                ;;
            --allow-signer-change)
                ALLOW_SIGNER_CHANGE=1
                shift
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                die "unknown argument '$1'" "Usage: sh install.sh [--version vX.Y.Z] [--dir DIR]"
                ;;
        esac
    done

    if [ -z "$DIR" ]; then
        [ -n "${HOME:-}" ] || die "HOME is not set; say where to install with --dir DIR"
        DIR="$HOME/.local/bin"
    fi
    TAG=""
    case "$VERSION" in
        "" | latest) ;;
        v*) TAG="$VERSION" ;;
        *) TAG="v$VERSION" ;;
    esac

    [ ! -d "$DIR/gclone" ] ||
        die "$DIR/gclone is a directory; remove it or choose another --dir"

    detect_target
    ASSET="gclone-$TARGET.tar.gz"

    for tool in tar gzip awk tr; do
        have "$tool" || die "'$tool' is needed and not installed"
    done

    # Real GitHub: https only, also across redirects.
    CURL_PROTO=""
    # For tests, which have no Developer ID: an ad hoc signature with the runtime flag stands
    # in for one. Never for a download from the real GitHub.
    ADHOC_TEST=0
    if [ -z "$BASE_URL" ] && [ "$API" = "$API_DEFAULT" ] && [ "$WEB" = "$WEB_DEFAULT" ]; then
        CURL_PROTO="--proto =https --proto-redir =https"
    elif [ "${GCLONE_TEST_ACCEPT_ADHOC_SIGNATURE:-0}" = 1 ]; then
        ADHOC_TEST=1
    fi
    MODE=""
    ANON_BASE=""

    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    TMP=$(mktemp -d 2>/dev/null || mktemp -d -t gclone-install)

    if [ -n "$BASE_URL" ]; then
        [ -z "$TAG" ] || die "--version cannot be combined with --base-url (the URL names the directory of one release)"
        download_from_base_url
    else
        case "$REPO" in
            OWNER/* | "")
                die "the repository is not set" \
                    "Run with GCLONE_REPO=<owner>/<repository> (or --repo), or edit DEFAULT_REPO at the top of install.sh."
                ;;
            */*) ;;
            *) die "'$REPO' is not a repository name of the form <owner>/<repository>" ;;
        esac
        TOKEN=${GITHUB_TOKEN:-}
        TOKEN_SOURCE="GITHUB_TOKEN"
        if [ -z "$TOKEN" ]; then
            TOKEN=${GH_TOKEN:-}
            TOKEN_SOURCE="GH_TOKEN"
        fi
        if [ -z "$TOKEN" ] && have gh; then
            TOKEN=$(gh auth token 2>/dev/null || true)
            TOKEN_SOURCE="the GitHub CLI's login"
        fi
        if [ -n "$TOKEN" ]; then
            download_with_token
        else
            download_anonymous
        fi
    fi

    verify_checksum "$ASSET"

    # macOS: the signed build, where the release has one.
    SIGNED=""
    SIGNER=""
    case "$TARGET" in
        *-apple-darwin)
            candidate="gclone-$TARGET-signed.tar.gz"
            if [ -n "$(sums_line "$candidate")" ]; then
                if [ "$UNSIGNED" = 1 ]; then
                    note "install.sh: --unsigned: installing $ASSET although the release has $candidate"
                elif ! have codesign; then
                    note "install.sh: note: the release has $candidate, but codesign is not on this system to check a signature with; installing $ASSET"
                else
                    SIGNED=$candidate
                    fetch_more "$SIGNED"
                    verify_checksum "$SIGNED"
                fi
            fi
            ;;
    esac

    PROVENANCE=unverified
    PROV_WHY=""
    PROV_TAG=""
    verify_provenance

    mkdir "$TMP/unpacked"
    (cd "$TMP/unpacked" && gzip -dc "../$ASSET" | tar -xf - gclone) ||
        die "cannot unpack $ASSET"
    [ -f "$TMP/unpacked/gclone" ] || die "$ASSET holds no gclone binary"
    NEW_BIN="$TMP/unpacked/gclone"

    if [ -n "$SIGNED" ]; then
        mkdir "$TMP/signed"
        (cd "$TMP/signed" && gzip -dc "../$SIGNED" | tar -xf - gclone) ||
            die "cannot unpack $SIGNED"
        [ -f "$TMP/signed/gclone" ] && [ ! -h "$TMP/signed/gclone" ] || die "$SIGNED holds no gclone binary"
        verify_signature "$TMP/signed/gclone"
        verify_same_build
        if [ "$PROVENANCE" = verified ]; then
            RELEASE_ASSET=""
            verify_release_asset
            if [ "$RELEASE_ASSET" = verified ]; then
                note "install.sh: verified: $SIGNED is the build of $REPO/$SIGNER_WORKFLOW on refs/tags/$PROV_TAG, signed by $SIGNER; identical apart from the signature"
            else
                note "install.sh: note: $SIGNED is the build of $REPO/$SIGNER_WORKFLOW on refs/tags/$PROV_TAG apart from the signature (verified), signed by $SIGNER; whether the signed archive itself is a file of the published release was NOT checked (this GitHub CLI (gh) is older than $GH_VERIFY_ASSET_MINIMUM and has no \`gh release verify-asset\`)."
            fi
        else
            note "install.sh: note: $SIGNED was checked against the release's $SUMS, its signature ($SIGNER) was verified and it is $ASSET of the same release apart from the signature; the build provenance was NOT checked ($PROV_WHY)."
        fi
        NEW_BIN="$TMP/signed/gclone"
    elif [ "$PROVENANCE" != verified ]; then
        checksum_only "$PROV_WHY"
    fi

    mkdir -p "$DIR" || die "cannot create the directory $DIR"
    # Absolute and without a trailing slash: for the messages and for the comparison with PATH.
    DIR=$(CDPATH='' cd -- "$DIR" && pwd) || die "cannot enter the directory $DIR"
    old=""
    if [ -x "$DIR/gclone" ]; then
        old=$("$DIR/gclone" --version 2>/dev/null || true)
    fi
    was_signed=0
    if have codesign && [ -f "$DIR/gclone" ] && is_developer_id "$DIR/gclone"; then
        was_signed=1
    fi
    check_continuity "$NEW_BIN"
    # Staged next to its final place (the temporary directory may be mounted noexec, and a
    # rename within one directory replaces a running binary safely), run once, then renamed.
    STAGED="$DIR/.gclone-install-$$"
    cp "$NEW_BIN" "$STAGED" || die "cannot write into $DIR"
    chmod 755 "$STAGED"
    if ! new=$("$STAGED" --version 2>&1); then
        die "the downloaded binary ($TARGET) does not run on this machine — nothing was installed" \
            "$new" \
            "If the machine was detected wrongly, pick the build with --target; otherwise build from source."
    fi
    mv -f "$STAGED" "$DIR/gclone" || die "cannot replace $DIR/gclone"
    STAGED=""

    if [ -z "$old" ]; then
        say "Installed $new"
    elif [ "$old" = "$new" ]; then
        say "Reinstalled $new"
    else
        say "Updated $old"
        say "     to $new"
    fi
    say "     in $DIR/gclone"
    if [ -n "$SIGNED" ] && [ "$was_signed" = 0 ]; then
        # Trust on first use: nothing on this machine said who signs gclone.
        say "     signed by $SIGNER (first signed install: later updates must come from the same signer)"
    elif [ -n "$SIGNED" ]; then
        say "     signed by $SIGNER"
    fi

    case ":$PATH:" in
        *":$DIR:"*) ;;
        *) path_hint ;;
    esac
    if [ -z "$old" ]; then
        say ""
        case "$new" in
            *"no auth URL built in"*) say "Next: gclone login https://<your auth Worker>" ;;
            *) say "Next: gclone login" ;;
        esac
    fi
}

# Nothing runs before the whole script has arrived (curl … | sh).
main "$@"
