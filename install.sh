#!/bin/sh
# gclone installer.
#
# Downloads the prebuilt gclone binary for this machine from the repository's GitHub Releases,
# checks it against the release's SHA256SUMS and puts it into ~/.local/bin. No sudo, nothing
# else is touched. Updating = running it again.
#
#   sh install.sh [--version vX.Y.Z] [--dir DIR]
#
# Options (each has an environment variable of the same meaning):
#   --version vX.Y.Z   GCLONE_VERSION       the release to install (default: the latest)
#   --dir DIR          GCLONE_INSTALL_DIR   where the binary goes (default: ~/.local/bin)
#   --repo OWNER/NAME  GCLONE_REPO          the GitHub repository that holds the releases
#   --target TRIPLE    GCLONE_TARGET        do not detect the machine, take this build
#   --base-url URL     GCLONE_BASE_URL      take gclone-<target>.tar.gz and SHA256SUMS from this
#                                           directory (https://…, file:///…, or the path of a
#                                           local directory) instead of GitHub
#
# A private repository needs a login: set GITHUB_TOKEN (or GH_TOKEN) to a token that may read
# the repository's contents, or be signed in with the GitHub CLI (`gh auth login`). The token
# is sent to the GitHub API only. A login that GitHub refuses does not stop the install from a
# public repository: the script says so and downloads without it.
#
# Needs: curl (wget is enough for a public repository), tar, gzip, and one of sha256sum,
# shasum, openssl.

set -eu

# The repository whose releases are installed; override with --repo or GCLONE_REPO.
DEFAULT_REPO="dwahdany/gclone"

SUMS="SHA256SUMS"
API_DEFAULT="https://api.github.com"
WEB_DEFAULT="https://github.com"

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
after checking it against the release's SHA256SUMS. No sudo. Updating = running it again.

Options (each has an environment variable of the same meaning):
  --version vX.Y.Z   GCLONE_VERSION       the release to install (default: the latest)
  --dir DIR          GCLONE_INSTALL_DIR   where the binary goes (default: ~/.local/bin)
  --repo OWNER/NAME  GCLONE_REPO          the GitHub repository that holds the releases
  --target TRIPLE    GCLONE_TARGET        do not detect the machine, take this build
  --base-url URL     GCLONE_BASE_URL      take gclone-<target>.tar.gz and SHA256SUMS from this
                                          directory (https://..., file:///..., or the path of a
                                          local directory) instead of GitHub

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
    # A local directory (file:///dir, or a path) is copied: no downloader is needed for it, and
    # wget cannot read file:// at all.
    local_dir=""
    case "$base" in
        file://localhost/*) local_dir=${base#file://localhost} ;;
        file:///*) local_dir=${base#file://} ;;
        *://*) ;;
        *) local_dir=$base ;;
    esac
    for file in "$ASSET" "$SUMS"; do
        if [ -n "$local_dir" ]; then
            cp "$local_dir/$file" "$TMP/$file" ||
                die "cannot read $local_dir/$file"
        else
            fetch "$base/$file" "$TMP/$file" ||
                die "cannot download $base/$file"
        fi
    done
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

verify_checksum() {
    want=$(awk -v name="$ASSET" '
        {
            file = $2
            sub(/^\*/, "", file)
            if (file == name) {
                print tolower($1)
                exit
            }
        }' "$TMP/$SUMS")
    case "$want" in
        "") die "$SUMS of $RELEASE does not list $ASSET; refusing to install an unchecked download" ;;
        *[!0-9a-f]*) die "$SUMS of $RELEASE holds no SHA-256 for $ASSET" ;;
    esac
    [ "${#want}" -eq 64 ] || die "$SUMS of $RELEASE holds no SHA-256 for $ASSET"
    got=$(sha256_of "$TMP/$ASSET")
    if [ "$got" != "$want" ]; then
        die "checksum mismatch for $ASSET — nothing was installed" \
            "expected $want" \
            "got      $got" \
            "The download is damaged or is not what the release published. Try again."
    fi
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
    if [ -z "$BASE_URL" ] && [ "$API" = "$API_DEFAULT" ] && [ "$WEB" = "$WEB_DEFAULT" ]; then
        CURL_PROTO="--proto =https --proto-redir =https"
    fi

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

    verify_checksum

    mkdir "$TMP/unpacked"
    (cd "$TMP/unpacked" && gzip -dc "../$ASSET" | tar -xf - gclone) ||
        die "cannot unpack $ASSET"
    [ -f "$TMP/unpacked/gclone" ] || die "$ASSET holds no gclone binary"

    mkdir -p "$DIR" || die "cannot create the directory $DIR"
    # Absolute and without a trailing slash: for the messages and for the comparison with PATH.
    DIR=$(CDPATH='' cd -- "$DIR" && pwd) || die "cannot enter the directory $DIR"
    old=""
    if [ -x "$DIR/gclone" ]; then
        old=$("$DIR/gclone" --version 2>/dev/null || true)
    fi
    # Staged next to its final place (the temporary directory may be mounted noexec, and a
    # rename within one directory replaces a running binary safely), run once, then renamed.
    STAGED="$DIR/.gclone-install-$$"
    cp "$TMP/unpacked/gclone" "$STAGED" || die "cannot write into $DIR"
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
