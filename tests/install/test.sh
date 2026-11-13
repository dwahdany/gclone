#!/bin/sh
# Tests of install.sh against a fake release: a local directory (file://) and a fake GitHub
# (tests/install/fake_github.py: API with a token, anonymous downloads, a storage host that
# refuses a forwarded Authorization header). No network, nothing outside a temporary directory.
#
#   sh tests/install/test.sh            # with /bin/sh
#   TEST_SHELL=dash sh tests/install/test.sh
#
# Needs python3 and curl; the wget case runs where wget is installed.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
script="$here/../../install.sh"
shell=${TEST_SHELL:-sh}

work=$(mktemp -d 2>/dev/null || mktemp -d -t gclone-install-test)
server_pid=""
finish() {
    [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
    rm -rf "$work"
}
trap finish EXIT
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

unset GITHUB_TOKEN GH_TOKEN GCLONE_VERSION GCLONE_INSTALL_DIR GCLONE_REPO GCLONE_TARGET \
    GCLONE_BASE_URL GCLONE_GITHUB_API GCLONE_GITHUB_WEB TERMUX_VERSION GCLONE_UNSIGNED \
    GCLONE_ALLOW_SIGNER_CHANGE GCLONE_TEST_ACCEPT_ADHOC_SIGNATURE GCLONE_ATTESTATION 2>/dev/null || true

# --- fixtures ----------------------------------------------------------------------------------

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{ print $1 }'
    else
        openssl dgst -sha256 -r "$1" | awk '{ print $1 }'
    fi
}

# What a release holds (.github/workflows/release.yml): no build for Intel Macs.
targets="x86_64-unknown-linux-musl aarch64-unknown-linux-musl aarch64-apple-darwin"

# make_release DIR VERSION: one archive per target; each fake binary names its target.
make_release() {
    mkdir -p "$1"
    for target in $targets broken-target; do
        mkdir -p "$work/build"
        if [ "$target" = "broken-target" ]; then
            printf '#!/bin/sh\necho "cannot execute binary file" >&2\nexit 126\n' >"$work/build/gclone"
        else
            printf '#!/bin/sh\necho "gclone %s (%s, no auth URL built in)"\n' "$2" "$target" >"$work/build/gclone"
        fi
        chmod 755 "$work/build/gclone"
        (cd "$work/build" && tar -cf - gclone | gzip >"$1/gclone-$target.tar.gz")
        rm -rf "$work/build"
    done
    (
        cd "$1"
        : >SHA256SUMS
        for file in gclone-*.tar.gz; do
            printf '%s  %s\n' "$(sha256_of "$file")" "$file" >>SHA256SUMS
        done
    )
}

make_release "$work/v9/dist" 9.9.9
make_release "$work/v8/dist" 8.0.0

# A PATH on which `gh` is "not signed in" and `uname` can be told what to say.
#
# The stand-in for the GitHub CLI: `auth token` gives FAKE_GH_TOKEN. With FAKE_GH_ATTEST set it
# is a gh that is signed in and knows attestations: `attestation verify FILE …` succeeds when
# the SHA-256 of FILE, the repository, the signer workflow and the source ref of its command
# line are a line of the file FAKE_GH_ATTEST names — what the real one binds together — and
# `release view` names FAKE_GH_LATEST as the latest release, and `release verify-asset TAG FILE`
# succeeds for the lines of the file FAKE_GH_RELEASE names. FAKE_GH_ATTEST=old is a gh from
# before attestations, FAKE_GH_ATTEST=signed-out one without a login. FAKE_GH_AGE makes it an
# older gh that does know attestations: `2.67` has no `--source-ref` for `attestation verify`
# (it came with 2.68.0), `2.74` has no `release verify-asset` (2.75.0); both answer as the real
# ones do — "unknown flag", "unknown command". Calls go to $work/gh.log.
mkdir "$work/bin"
cat >"$work/bin/gh" <<EOF
#!/bin/sh
echo "\$*" >>"$work/gh.log"
if [ "\$1 \$2" = "auth token" ] && [ -n "\${FAKE_GH_TOKEN:-}" ]; then
    echo "\$FAKE_GH_TOKEN"
    exit 0
fi
attest=\${FAKE_GH_ATTEST:-}
case "\$1 \$2" in
    "attestation verify")
        [ -n "\$attest" ] && [ "\$attest" != old ] || { echo "unknown command \"attestation\" for \"gh\"" >&2; exit 1; }
        if [ "\$3" = "--help" ]; then
            echo "Verify the integrity and provenance of an artifact using its associated cryptographically signed attestations."
            echo "FLAGS"
            echo "      --deny-self-hosted-runners   Fail verification for attestations generated on self-hosted runners"
            echo "  -R, --repo string                Repository name in the format <owner>/<repo>"
            echo "      --signer-workflow string     Enforce that the workflow that signed the attestation matches"
            [ "\${FAKE_GH_AGE:-}" = 2.67 ] || echo "      --source-ref string          Enforce that the artifact's source ref matches the provided value"
            exit 0
        fi
        if [ "\${FAKE_GH_AGE:-}" = 2.67 ]; then
            case " \$* " in *" --source-ref "*) echo "unknown flag: --source-ref" >&2; exit 1 ;; esac
        fi
        file=\$3
        shift 3
        repo="" workflow="" ref="" runners=""
        while [ \$# -gt 0 ]; do
            case "\$1" in
                --repo) repo=\$2; shift 2 ;;
                --signer-workflow) workflow=\$2; shift 2 ;;
                --source-ref) ref=\$2; shift 2 ;;
                --deny-self-hosted-runners) runners=denied; shift ;;
                *) echo "fake gh: unexpected \$1" >&2; exit 2 ;;
            esac
        done
        if command -v sha256sum >/dev/null 2>&1; then
            digest=\$(sha256sum "\$file" | awk '{ print \$1 }')
        else
            digest=\$(shasum -a 256 "\$file" | awk '{ print \$1 }')
        fi
        if [ "\$runners" = denied ] && grep -qxF "\$digest \$repo \$workflow \$ref" "\$attest" 2>/dev/null; then
            echo "Loaded digest sha256:\$digest"
            echo "✓ Verification succeeded!"
            exit 0
        fi
        echo "Error: HTTP 404: Not Found (https://api.github.com/repos/\$repo/attestations/sha256:\$digest)" >&2
        exit 1
        ;;
    "auth status")
        [ -n "\$attest" ] && [ "\$attest" != signed-out ] && exit 0
        echo "You are not logged into any GitHub hosts." >&2
        exit 1
        ;;
    "release view")
        [ -n "\${FAKE_GH_LATEST:-}" ] || exit 1
        echo "\$FAKE_GH_LATEST"
        exit 0
        ;;
    "release verify-asset")
        # release verify-asset TAG FILE --repo REPO: succeeds when the SHA-256 of FILE, the
        # repository and the tag are a line of the file FAKE_GH_RELEASE names (a file of that
        # published, immutable release).
        [ -n "\$attest" ] && [ "\$attest" != old ] || { echo "unknown command \"verify-asset\" for \"gh release\"" >&2; exit 1; }
        case "\${FAKE_GH_AGE:-}" in 2.67 | 2.74) echo "unknown command \"verify-asset\" for \"gh release\"" >&2; exit 1 ;; esac
        [ "\$3" != "--help" ] || { echo "Verify that a given asset file originated from a specific GitHub Release."; exit 0; }
        tag=\$3
        file=\$4
        [ "\$5" = "--repo" ] || { echo "fake gh: unexpected \$5" >&2; exit 2; }
        if command -v sha256sum >/dev/null 2>&1; then
            digest=\$(sha256sum "\$file" | awk '{ print \$1 }')
        else
            digest=\$(shasum -a 256 "\$file" | awk '{ print \$1 }')
        fi
        if grep -qxF "\$digest \$6 \$tag" "\${FAKE_GH_RELEASE:-/dev/null}" 2>/dev/null; then
            echo "✓ Verification succeeded!"
            exit 0
        fi
        echo "Error: no attestation of release \$tag names sha256:\$digest" >&2
        exit 1
        ;;
esac
echo "no oauth token found for github.com" >&2
exit 1
EOF
real_uname=$(command -v uname)
cat >"$work/bin/uname" <<EOF
#!/bin/sh
case "\$1" in
    -s) [ -z "\${FAKE_UNAME_S:-}" ] || { echo "\$FAKE_UNAME_S"; exit 0; } ;;
    -m) [ -z "\${FAKE_UNAME_M:-}" ] || { echo "\$FAKE_UNAME_M"; exit 0; } ;;
    -o) [ -z "\${FAKE_UNAME_O:-}" ] || { echo "\$FAKE_UNAME_O"; exit 0; } ;;
esac
exec "$real_uname" "\$@"
EOF
cat >"$work/bin/sysctl" <<'EOF'
#!/bin/sh
# `sysctl -n sysctl.proc_translated`: 1 under Rosetta.
echo "${FAKE_PROC_TRANSLATED:-0}"
EOF
chmod 755 "$work/bin/gh" "$work/bin/uname" "$work/bin/sysctl"
PATH="$work/bin:$PATH"
export PATH

# run NAME EXPECTED_STATUS [VAR=VALUE…] -- ARGS…: runs install.sh; output in $out.
out=""
run() {
    name=$1
    want=$2
    shift 2
    count=$((count + 1))
    set +e
    out=$(
        while [ "$1" != "--" ]; do
            # shellcheck disable=SC2163 # the argument is VAR=VALUE
            export "$1"
            shift
        done
        shift
        "$shell" "$script" "$@" 2>&1
    )
    got=$?
    set -e
    current=$name
    if [ "$got" -ne "$want" ]; then
        fail "$name: exit status $got, expected $want" "$out"
    fi
}

has() {
    case "$out" in
        *"$1"*) ;;
        *) fail "$current: the output lacks '$1'" "$out" ;;
    esac
}

lacks() {
    case "$out" in
        *"$1"*) fail "$current: the output contains '$1'" "$out" ;;
        *) ;;
    esac
}

# installed DIR EXPECTED: what `DIR/gclone --version` prints.
installed() {
    actual=$("$1/gclone" --version 2>&1 || true)
    [ "$actual" = "$2" ] || fail "$current: $1/gclone --version printed '$actual', expected '$2'"
}

no_leftovers() {
    for entry in "$1"/* "$1"/.[!.]*; do
        case "$entry" in
            "$1/gclone" | "$1/*" | "$1/.[!.]*") ;;
            *) fail "$current: left behind: $entry" ;;
        esac
    done
}

host_target() {
    # shellcheck disable=SC2016 # the script is for the inner shell
    FAKE_UNAME_S="" "$shell" -c '
        os=$(uname -s); arch=$(uname -m)
        case "$arch" in x86_64 | amd64) a=x86_64 ;; aarch64 | arm64) a=aarch64 ;; *) a=unknown ;; esac
        case "$os" in Linux) echo "$a-unknown-linux-musl" ;; Darwin) echo "$a-apple-darwin" ;; *) echo "$a-unknown" ;; esac'
}
host=$(host_target)

v9="file://$work/v9/dist"
v8="file://$work/v8/dist"

# --- a local directory -------------------------------------------------------------------------

d="$work/dest1"
run "first install" 0 -- --base-url "$v8" --dir "$d"
has "Installed gclone 8.0.0 ($host, no auth URL built in)"
has "in $d/gclone"
has "is not on your PATH"
has "Next: gclone login https://<your auth Worker>"
installed "$d" "gclone 8.0.0 ($host, no auth URL built in)"
no_leftovers "$d"

run "update" 0 -- --base-url "$v9" --dir "$d"
has "Updated gclone 8.0.0"
has "to gclone 9.9.9"
lacks "Next:"
installed "$d" "gclone 9.9.9 ($host, no auth URL built in)"

run "reinstall, directory on PATH, by environment" 0 "GCLONE_BASE_URL=$v9" "GCLONE_INSTALL_DIR=$d" "PATH=$d:$PATH" --
has "Reinstalled gclone 9.9.9"
lacks "is not on your PATH"

run "default directory is ~/.local/bin" 0 "HOME=$work/home" -- --base-url "$v9"
installed "$work/home/.local/bin" "gclone 9.9.9 ($host, no auth URL built in)"

run "a local directory by its path" 0 -- --base-url "$work/v9/dist/" --dir "$work/bypath"
installed "$work/bypath" "gclone 9.9.9 ($host, no auth URL built in)"

# The PATH hint: an absolute directory whatever was typed, and the file the login shell reads.
cd "$work"
run "a relative directory" 0 SHELL=/bin/zsh -- --base-url "$v9" --dir rel/bin
cd "$here"
has "in $work/rel/bin/gclone"
has "$work/rel/bin is not on your PATH. Add it with this line in ~/.zshrc:"
has "export PATH=\"$work/rel/bin:\$PATH\""
has "then open a new terminal"
installed "$work/rel/bin" "gclone 9.9.9 ($host, no auth URL built in)"

run "a trailing slash, directory on PATH" 0 "PATH=$work/rel/bin:$PATH" -- --base-url "$v9" --dir "$work/rel/bin/"
has "in $work/rel/bin/gclone"
lacks "is not on your PATH"

run "PATH hint for bash" 0 SHELL=/usr/bin/bash -- --base-url "$v9" --dir "$work/hint"
has "this line in ~/.bashrc:"
has "then open a new terminal"
run "PATH hint for another shell" 0 SHELL=/bin/dash -- --base-url "$v9" --dir "$work/hint"
has "this line in ~/.profile:"
has "then log out and in again"

# Debian's ~/.profile puts ~/.local/bin on PATH at login if it exists: nothing to add.
mkdir "$work/debian"
# shellcheck disable=SC2016 # the text of a ~/.profile
printf '%s\n' 'if [ -d "$HOME/.local/bin" ] ; then' '    PATH="$HOME/.local/bin:$PATH"' 'fi' >"$work/debian/.profile"
run "the .profile already adds ~/.local/bin" 0 "HOME=$work/debian" SHELL=/bin/bash -- --base-url "$v9"
has "Your ~/.profile adds it at login"
has "log out and in again"
lacks "export PATH"
: >"$work/debian/.bash_profile"
run "the .profile is hidden by a .bash_profile" 0 "HOME=$work/debian" SHELL=/bin/bash -- --base-url "$v9"
has "this line in ~/.bashrc:"
run "the .profile is not read by zsh" 0 "HOME=$work/debian" SHELL=/bin/zsh -- --base-url "$v9"
has "this line in ~/.zshrc:"

count=$((count + 1))
current="piped into the shell"
if ! out=$("$shell" -s -- --base-url "$v9" --dir "$work/piped" <"$script" 2>&1); then
    fail "$current: failed" "$out"
fi
installed "$work/piped" "gclone 9.9.9 ($host, no auth URL built in)"

# --- which build -------------------------------------------------------------------------------

detects() {
    run "detect $1/$2 (translated: ${4:-0})" 0 "FAKE_UNAME_S=$1" "FAKE_UNAME_M=$2" "FAKE_PROC_TRANSLATED=${4:-0}" -- \
        --base-url "$v9" --dir "$work/detect"
    has "Installed gclone 9.9.9 ($3, " || true
    rm -rf "$work/detect"
}
detects Linux x86_64 x86_64-unknown-linux-musl
detects Linux amd64 x86_64-unknown-linux-musl
detects Linux aarch64 aarch64-unknown-linux-musl
detects Linux arm64 aarch64-unknown-linux-musl
detects Darwin arm64 aarch64-apple-darwin
# Apple silicon, from a shell that runs under Rosetta
detects Darwin x86_64 aarch64-apple-darwin 1

# An Intel Mac: the releases have no build for it, and the script says so before it downloads
# anything — not "cannot download gclone-x86_64-apple-darwin.tar.gz".
run "an Intel Mac" 1 FAKE_UNAME_S=Darwin FAKE_UNAME_M=x86_64 FAKE_PROC_TRANSLATED=0 -- --base-url "$v9" --dir "$work/none"
has "install.sh: error: no prebuilt gclone for Intel Macs"
has "Apple silicon (arm64) only"
has "Build from source instead (README, \"Building from source\")"
lacks "cannot"
run "an Intel Mac, from GitHub" 1 FAKE_UNAME_S=Darwin FAKE_UNAME_M=x86_64 FAKE_PROC_TRANSLATED=0 GCLONE_REPO=acme/gclone -- --dir "$work/none"
has "no prebuilt gclone for Intel Macs"

run "32-bit ARM" 1 FAKE_UNAME_S=Linux FAKE_UNAME_M=armv7l -- --base-url "$v9" --dir "$work/none"
has "no prebuilt gclone for the CPU architecture 'armv7l'"
run "Windows shell" 1 FAKE_UNAME_S=MINGW64_NT-10.0-19045 FAKE_UNAME_M=x86_64 -- --base-url "$v9" --dir "$work/none"
has "WSL2"
run "another system" 1 FAKE_UNAME_S=FreeBSD FAKE_UNAME_M=amd64 -- --base-url "$v9" --dir "$work/none"
has "no prebuilt gclone for the operating system 'FreeBSD'"
run "Android (uname -o)" 1 FAKE_UNAME_S=Linux FAKE_UNAME_M=aarch64 FAKE_UNAME_O=Android -- --base-url "$v9" --dir "$work/none"
has "no prebuilt gclone for Android/Termux"
has "Build from source inside Termux"
run "Termux (TERMUX_VERSION)" 1 FAKE_UNAME_S=Linux FAKE_UNAME_M=aarch64 FAKE_UNAME_O=GNU/Linux TERMUX_VERSION=0.118.0 -- --base-url "$v9" --dir "$work/none"
has "no prebuilt gclone for Android/Termux"
run "--target overrides on Android" 0 FAKE_UNAME_S=Linux FAKE_UNAME_O=Android -- --base-url "$v9" --dir "$work/forced-android" --target aarch64-unknown-linux-musl
has "(aarch64-unknown-linux-musl, "
run "--target overrides" 0 FAKE_UNAME_S=FreeBSD -- --base-url "$v9" --dir "$work/forced" --target aarch64-apple-darwin
has "(aarch64-apple-darwin, "
# Asked for by name, the Intel build is looked for (a release of one's own may have it); the
# releases here do not.
run "--target x86_64-apple-darwin on an Intel Mac" 1 FAKE_UNAME_S=Darwin FAKE_UNAME_M=x86_64 -- --base-url "$v9" --dir "$work/none" --target x86_64-apple-darwin
has "gclone-x86_64-apple-darwin.tar.gz"
lacks "no prebuilt gclone for Intel Macs"
[ ! -e "$work/none" ] || fail "a refused install created its directory"

# --- refusals ----------------------------------------------------------------------------------

d="$work/dest2"
run "install before the refusals" 0 -- --base-url "$v8" --dir "$d"

cp -R "$work/v9" "$work/damaged"
printf 'x' >>"$work/damaged/dist/gclone-$host.tar.gz"
run "checksum mismatch" 1 -- --base-url "file://$work/damaged/dist" --dir "$d"
has "checksum mismatch for gclone-$host.tar.gz"
has "nothing was installed"
installed "$d" "gclone 8.0.0 ($host, no auth URL built in)"
no_leftovers "$d"

cp -R "$work/v9" "$work/unlisted"
grep -v "gclone-$host.tar.gz" "$work/v9/dist/SHA256SUMS" >"$work/unlisted/dist/SHA256SUMS"
run "archive missing from SHA256SUMS" 1 -- --base-url "file://$work/unlisted/dist" --dir "$d"
has "does not list gclone-$host.tar.gz"
installed "$d" "gclone 8.0.0 ($host, no auth URL built in)"

cp -R "$work/v9" "$work/nosums"
rm "$work/nosums/dist/SHA256SUMS"
run "no SHA256SUMS" 1 -- --base-url "file://$work/nosums/dist" --dir "$d"
has "cannot read $work/nosums/dist/SHA256SUMS"
installed "$d" "gclone 8.0.0 ($host, no auth URL built in)"

mkdir -p "$work/blocked/gclone"
run "a directory where the binary goes" 1 -- --base-url "$v9" --dir "$work/blocked"
has "$work/blocked/gclone is a directory; remove it or choose another --dir"
no_leftovers "$work/blocked/gclone"

run "a binary that does not run" 1 -- --base-url "$v9" --dir "$d" --target broken-target
has "does not run on this machine"
has "cannot execute binary file"
installed "$d" "gclone 8.0.0 ($host, no auth URL built in)"
no_leftovers "$d"

run "no build for the target" 1 -- --base-url "$v9" --dir "$d" --target riscv64gc-unknown-linux-musl
has "cannot read $work/v9/dist/gclone-riscv64gc-unknown-linux-musl.tar.gz"

run "unknown argument" 1 -- --frobnicate
has "unknown argument '--frobnicate'"
run "missing value" 1 -- --dir
has "--dir needs a value"
run "--version with --base-url" 1 -- --base-url "$v9" --version v9.9.9 --dir "$d"
has "cannot be combined"
run "placeholder repository" 1 -- --repo OWNER/gclone --dir "$d"
has "the repository is not set"
has "GCLONE_REPO"
run "help" 0 -- --help
has "Usage: sh install.sh"
has "GCLONE_INSTALL_DIR"

# --- fake GitHub -------------------------------------------------------------------------------

# The release the fake GitHub serves (its requests.log is written beside the directory).
served="$work/v9/dist"
start_server() {
    [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
    rm -f "$work/ports" "$work/v9/requests.log"
    python3 "$here/fake_github.py" "$served" "$work/ports" "$@" &
    server_pid=$!
    tries=0
    while [ ! -s "$work/ports" ]; do
        tries=$((tries + 1))
        [ "$tries" -lt 100 ] || {
            echo "the fake GitHub did not start" >&2
            exit 1
        }
        sleep 0.1
    done
    read -r main_port _ <"$work/ports"
    github="http://127.0.0.1:$main_port"
}
requests() { cat "$work/v9/requests.log" 2>/dev/null || true; }
requested() {
    case "$(requests)" in
        *"$1"*) ;;
        *) fail "$current: no request '$1'" "$(requests)" ;;
    esac
}
not_requested() {
    case "$(requests)" in
        *"$1"*) fail "$current: a request '$1' was made" "$(requests)" ;;
        *) ;;
    esac
}

for mode in pretty compact; do
    if [ "$mode" = compact ]; then start_server --compact --private; else start_server --private; fi
    api_env="GCLONE_GITHUB_API=$github GCLONE_GITHUB_WEB=$github GCLONE_REPO=acme/gclone"

    d="$work/api-$mode"
    # shellcheck disable=SC2086 # api_env is three VAR=VALUE words
    run "private repository, GITHUB_TOKEN, latest ($mode JSON)" 0 $api_env GITHUB_TOKEN=good-token -- --dir "$d"
    has "Installed gclone 9.9.9 ($host, "
    installed "$d" "gclone 9.9.9 ($host, no auth URL built in)"
    requested "main /repos/acme/gclone/releases/latest auth=yes"
    requested "storage /blob/gclone-$host.tar.gz auth=no"
    requested "storage /blob/SHA256SUMS auth=no"
    not_requested "storage /blob/gclone-$host.tar.gz auth=yes"
    not_requested "/releases/latest/download/"

    : >"$work/v9/requests.log"
    # shellcheck disable=SC2086
    run "private repository, GH_TOKEN, a version without v ($mode JSON)" 0 $api_env GH_TOKEN=good-token -- --dir "$d" --version 9.9.9
    has "Reinstalled gclone 9.9.9"
    requested "main /repos/acme/gclone/releases/tags/v9.9.9 auth=yes"

    # shellcheck disable=SC2086
    run "private repository, the GitHub CLI's login ($mode JSON)" 0 $api_env FAKE_GH_TOKEN=good-token -- --dir "$d" --version v9.9.9
    has "Reinstalled gclone 9.9.9"

    # shellcheck disable=SC2086
    run "GITHUB_TOKEN goes before GH_TOKEN and gh ($mode JSON)" 0 $api_env GITHUB_TOKEN=good-token GH_TOKEN=bad FAKE_GH_TOKEN=bad -- --dir "$d"

    # shellcheck disable=SC2086
    run "no build for the target in the release ($mode JSON)" 1 $api_env GITHUB_TOKEN=good-token -- --dir "$d" --target riscv64gc-unknown-linux-musl
    has "release v9.9.9 of acme/gclone has no build for this machine (gclone-riscv64gc-unknown-linux-musl.tar.gz)"
done

# shellcheck disable=SC2086
run "a token that is refused" 1 $api_env GITHUB_TOKEN=bad-token -- --dir "$work/refused"
has "cannot read the latest release of acme/gclone from the GitHub API (login: GITHUB_TOKEN)"
has "trying without the login"
lacks "bad-token"
[ ! -e "$work/refused/gclone" ] || fail "$current: something was installed"

# shellcheck disable=SC2086
run "a release that does not exist" 1 $api_env GITHUB_TOKEN=good-token -- --dir "$work/refused" --version v1.2.3
has "cannot read release v1.2.3 of acme/gclone"

# shellcheck disable=SC2086
run "private repository without a login" 1 $api_env -- --dir "$work/refused"
has "cannot download $github/acme/gclone/releases/latest/download/gclone-$host.tar.gz"
has "GITHUB_TOKEN"
has "gh auth login"

start_server
web_env="GCLONE_GITHUB_API=$github GCLONE_GITHUB_WEB=$github"
d="$work/public"
# shellcheck disable=SC2086 # web_env is two VAR=VALUE words
run "public repository, latest" 0 $web_env -- --dir "$d" --repo acme/gclone
has "Installed gclone 9.9.9 ($host, "
requested "main /acme/gclone/releases/latest/download/gclone-$host.tar.gz auth=no"
not_requested "/repos/"
: >"$work/v9/requests.log"
# shellcheck disable=SC2086
run "public repository, a version" 0 $web_env GCLONE_VERSION=v9.9.9 GCLONE_REPO=acme/gclone -- --dir "$d"
has "Reinstalled gclone 9.9.9"
requested "main /acme/gclone/releases/download/v9.9.9/SHA256SUMS auth=no"
not_requested "latest"
# A stale or unrelated token in the environment must not break a public repository.
: >"$work/v9/requests.log"
# shellcheck disable=SC2086
run "public repository, a token that is refused" 0 $web_env GITHUB_TOKEN=bad-token -- --dir "$work/stale" --repo acme/gclone
has "did not give the latest release of acme/gclone to the login (GITHUB_TOKEN); trying without the login"
has "Installed gclone 9.9.9 ($host, "
lacks "bad-token"
requested "main /repos/acme/gclone/releases/latest auth=yes"
requested "main /acme/gclone/releases/latest/download/gclone-$host.tar.gz auth=no"
# shellcheck disable=SC2086
run "public repository, a refused gh login, a version" 0 $web_env FAKE_GH_TOKEN=expired -- --dir "$work/stale" --repo acme/gclone --version v9.9.9
has "(the GitHub CLI's login); trying without the login"
has "Reinstalled gclone 9.9.9"
# shellcheck disable=SC2086
run "public repository, a version that does not exist" 1 $web_env -- --dir "$d" --repo acme/gclone --version 1.2.3
has "cannot download $github/acme/gclone/releases/download/v1.2.3/"

# --- the build-provenance attestation ----------------------------------------------------------
#
# SHA256SUMS comes from the release it describes: whoever can replace an archive can replace
# its line too. With the GitHub CLI signed in, the archive must be what the release workflow
# attested for that tag; without it the script says, in one line, that only the checksum was
# checked.

gh_calls() { cat "$work/gh.log" 2>/dev/null || true; }
attested="$work/attested"
workflow="acme/gclone/.github/workflows/release.yml"
printf '%s acme/gclone %s refs/tags/v9.9.9\n' "$(sha256_of "$work/v9/dist/gclone-$host.tar.gz")" "$workflow" >"$attested"

# (the public release of the cases above is still being served)
d="$work/attest"
: >"$work/gh.log"
# shellcheck disable=SC2086
run "attested: verified with gh, the API names the tag" 0 $web_env FAKE_GH_TOKEN=good-token "FAKE_GH_ATTEST=$attested" -- --dir "$d" --repo acme/gclone
has "install.sh: verified the build-provenance attestation of gclone-$host.tar.gz (built by $workflow on refs/tags/v9.9.9)"
has "Installed gclone 9.9.9 ($host, "
lacks "SHA256SUMS only"
case "$(gh_calls)" in
    *"attestation verify "*"/gclone-$host.tar.gz --repo acme/gclone --signer-workflow $workflow --source-ref refs/tags/v9.9.9 --deny-self-hosted-runners"*) ;;
    *) fail "$current: gh was not asked as documented" "$(gh_calls)" ;;
esac

# Without a token the archive comes from …/releases/latest/download: gh names the release.
# shellcheck disable=SC2086
run "attested: the latest release, named by gh" 0 $web_env "FAKE_GH_ATTEST=$attested" FAKE_GH_LATEST=v9.9.9 -- --dir "$d" --repo acme/gclone
has "verified the build-provenance attestation of gclone-$host.tar.gz (built by $workflow on refs/tags/v9.9.9)"
has "Reinstalled gclone 9.9.9"
# shellcheck disable=SC2086
run "attested: a version, by the environment" 0 $web_env "FAKE_GH_ATTEST=$attested" GCLONE_ATTESTATION=require -- --dir "$d" --repo acme/gclone --version 9.9.9
has "verified the build-provenance attestation"
# … which gh cannot do: then only the checksum was checked, and the script says so.
# shellcheck disable=SC2086
run "the latest release, which gh cannot name" 0 $web_env "FAKE_GH_ATTEST=$attested" -- --dir "$d" --repo acme/gclone
has "was checked against the release's SHA256SUMS only (the GitHub CLI could not name the latest release of acme/gclone)"
has "Reinstalled gclone 9.9.9"

# No usable gh: the install goes on with the checksum, and says in ONE line what that is worth.
for reason in "old:this GitHub CLI (gh) is too old to verify attestations: it needs gh 2.68.0 or newer" "signed-out:the GitHub CLI (gh) is not signed in"; do
    # shellcheck disable=SC2086
    run "no usable gh (${reason%%:*})" 0 $web_env "FAKE_GH_ATTEST=${reason%%:*}" -- --dir "$d" --repo acme/gclone
    has "install.sh: note: gclone-$host.tar.gz was checked against the release's SHA256SUMS only (${reason#*:}). That shows a damaged download, not a replaced release: the list comes from the same place as the archive."
    has "Reinstalled gclone 9.9.9"
    lacks "verified the build-provenance attestation"
    notes=$(printf '%s\n' "$out" | grep -c "SHA256SUMS only" || true)
    [ "$notes" -eq 1 ] || fail "$current: the note is printed $notes times"
    # shellcheck disable=SC2086
    run "--require-attestation, no usable gh (${reason%%:*})" 1 $web_env "FAKE_GH_ATTEST=${reason%%:*}" -- --dir "$work/required" --repo acme/gclone --require-attestation
    has "the build-provenance attestation of gclone-$host.tar.gz was not verified (${reason#*:}) — nothing was installed"
    [ ! -e "$work/required/gclone" ] || fail "$current: something was installed"
done

# A gh that knows `attestation verify` but not its `--source-ref` (gh 2.49 to 2.67): it is
# too old, and the script says THAT — it used to pass the flag, get "unknown flag", and tell
# every user that GitHub holds no attestation for the release.
: >"$work/gh.log"
# shellcheck disable=SC2086
run "a gh without --source-ref (2.49 to 2.67)" 0 $web_env "FAKE_GH_ATTEST=$attested" FAKE_GH_AGE=2.67 -- --dir "$d" --repo acme/gclone --version v9.9.9
has "install.sh: note: gclone-$host.tar.gz was checked against the release's SHA256SUMS only (this GitHub CLI (gh) is too old to verify attestations: it needs gh 2.68.0 or newer)."
has "Reinstalled gclone 9.9.9"
lacks "GitHub holds no statement"
lacks "unknown flag"
case "$(gh_calls)" in
    *"--source-ref"*) fail "$current: the flag this gh does not know was passed to it" "$(gh_calls)" ;;
esac
# shellcheck disable=SC2086
run "--require-attestation, a gh without --source-ref" 1 $web_env "FAKE_GH_ATTEST=$attested" FAKE_GH_AGE=2.67 -- --dir "$work/required" --repo acme/gclone --version v9.9.9 --require-attestation
has "the build-provenance attestation of gclone-$host.tar.gz was not verified (this GitHub CLI (gh) is too old to verify attestations: it needs gh 2.68.0 or newer) — nothing was installed"
lacks "GitHub holds no statement"
[ ! -e "$work/required/gclone" ] || fail "$current: something was installed"
# A gh from 2.68 to 2.74 verifies the attestation as before (no signed build is involved here).
# shellcheck disable=SC2086
run "a gh without release verify-asset (2.68 to 2.74), no signed build" 0 $web_env "FAKE_GH_ATTEST=$attested" FAKE_GH_AGE=2.74 -- --dir "$d" --repo acme/gclone --version v9.9.9
has "install.sh: verified the build-provenance attestation of gclone-$host.tar.gz"

# A directory of one's own is no GitHub release; asked to skip, the script skips. Both say so.
run "--base-url has no attestation" 0 "FAKE_GH_ATTEST=$attested" -- --base-url "$v9" --dir "$d"
has "SHA256SUMS only (--base-url names a directory, not a GitHub release)"
run "--base-url with --require-attestation" 1 "FAKE_GH_ATTEST=$attested" -- --base-url "$v9" --dir "$work/required" --require-attestation
has "was not verified (--base-url names a directory, not a GitHub release)"
# shellcheck disable=SC2086
run "--no-attestation" 0 $web_env "FAKE_GH_ATTEST=$attested" -- --dir "$d" --repo acme/gclone --no-attestation
has "SHA256SUMS only (--no-attestation)"
lacks "verified the build-provenance attestation"
# shellcheck disable=SC2086
run "an unknown GCLONE_ATTESTATION" 1 $web_env GCLONE_ATTESTATION=maybe -- --dir "$work/required" --repo acme/gclone
has "GCLONE_ATTESTATION is 'maybe'; it is one of auto, require, skip"

# The attestation is of another ref (a build on a branch), of another workflow, of another
# repository: not this release's build.
for other in "acme/gclone $workflow refs/heads/main" "acme/gclone acme/gclone/.github/workflows/ci.yml refs/tags/v9.9.9" "evil/gclone evil/gclone/.github/workflows/release.yml refs/tags/v9.9.9"; do
    printf '%s %s\n' "$(sha256_of "$work/v9/dist/gclone-$host.tar.gz")" "$other" >"$work/attested-elsewhere"
    # shellcheck disable=SC2086
    run "an attestation of another build ($other)" 1 $web_env "FAKE_GH_ATTEST=$work/attested-elsewhere" -- --dir "$work/required" --repo acme/gclone --version v9.9.9
    has "the build-provenance attestation of gclone-$host.tar.gz could not be verified — nothing was installed"
    [ ! -e "$work/required/gclone" ] || fail "$current: something was installed"
done

# The attack a checksum cannot see: the archive AND its line in SHA256SUMS are replaced in the
# release. The checksum agrees with itself; no attestation exists for the new bytes.
mkdir -p "$work/swapped/dist" "$work/build"
cp "$work/v9/dist/"* "$work/swapped/dist/"
printf '#!/bin/sh\necho "gclone 9.9.9 (%s, NOT WHAT WAS BUILT)"\n' "$host" >"$work/build/gclone"
chmod 755 "$work/build/gclone"
(cd "$work/build" && tar -cf - gclone | gzip >"$work/swapped/dist/gclone-$host.tar.gz")
rm -rf "$work/build"
(
    cd "$work/swapped/dist"
    : >SHA256SUMS
    for file in gclone-*.tar.gz; do
        printf '%s  %s\n' "$(sha256_of "$file")" "$file" >>SHA256SUMS
    done
)
served="$work/swapped/dist"
start_server
web_env="GCLONE_GITHUB_API=$github GCLONE_GITHUB_WEB=$github"
d="$work/victim"
# shellcheck disable=SC2086
run "install before the swap is tried" 0 $web_env -- --base-url "$v8" --dir "$d"
# shellcheck disable=SC2086
run "a replaced archive with a matching SHA256SUMS: refused with gh" 1 $web_env "FAKE_GH_ATTEST=$attested" -- --dir "$d" --repo acme/gclone --version v9.9.9
has "the build-provenance attestation of gclone-$host.tar.gz could not be verified — nothing was installed"
has "HTTP 404"
has "it is not what that release's build produced, or the release has no attestations."
has "add --no-attestation"
lacks "checksum mismatch"
lacks "NOT WHAT WAS BUILT"
installed "$d" "gclone 8.0.0 ($host, no auth URL built in)"
no_leftovers "$d"
# shellcheck disable=SC2086
run "a replaced archive, the latest release named by gh: refused" 1 $web_env "FAKE_GH_ATTEST=$attested" FAKE_GH_LATEST=v9.9.9 -- --dir "$d" --repo acme/gclone
has "could not be verified — nothing was installed"
installed "$d" "gclone 8.0.0 ($host, no auth URL built in)"
# Without gh this is what the checksum is worth — which is why the note is there.
# shellcheck disable=SC2086
run "a replaced archive with a matching SHA256SUMS: installed without gh, with the note" 0 $web_env FAKE_GH_ATTEST=signed-out -- --dir "$work/unprotected" --repo acme/gclone --version v9.9.9
has "SHA256SUMS only (the GitHub CLI (gh) is not signed in). That shows a damaged download, not a replaced release"
has "NOT WHAT WAS BUILT"
served="$work/v9/dist"
start_server
web_env="GCLONE_GITHUB_API=$github GCLONE_GITHUB_WEB=$github"

# --- macOS: the signed build of a release ------------------------------------------------------
#
# A release may carry gclone-<target>-signed.tar.gz beside the attested archive: the same
# binary with a Developer ID signature. Tests have no Developer ID, so an ad hoc signature
# with the hardened runtime stands in for one (GCLONE_TEST_ACCEPT_ADHOC_SIGNATURE=1, which
# install.sh honours only away from the real GitHub); with it the "designated requirement"
# of a binary is its own hash, so "the same signer" means "the same signed binary" here.
# Needs macOS on Apple silicon, codesign and a C compiler (for real Mach-O binaries).

signed_cases() {
    signer="io.github.dwahdany.gclone"
    adhoc="GCLONE_TEST_ACCEPT_ADHOC_SIGNATURE=1"
    flags_of() { codesign -dv "$1" 2>&1 | sed -n 's/^CodeDirectory .* flags=\([^ ]*\) .*$/\1/p'; }
    # macho OUT TEXT: an executable that prints TEXT, as the linker leaves it (ad hoc signed).
    macho() {
        printf '#include <stdio.h>\nint main(void) { puts("%s"); return 0; }\n' "$2" >"$work/macho.c"
        cc -o "$1" "$work/macho.c"
    }
    # sign IN OUT [codesign options…]: a "Developer ID" signature, as far as a test can make one.
    sign() {
        cp "$1" "$2"
        out_bin=$2
        shift 2
        codesign -f -s - -i "$signer" "$@" "$out_bin" 2>/dev/null
    }
    # signed_release DIR UNSIGNED SIGNED: the two archives for this machine and SHA256SUMS.
    signed_release() {
        mkdir -p "$1" "$work/build"
        cp "$2" "$work/build/gclone"
        (cd "$work/build" && tar -cf - gclone | gzip >"$1/gclone-$host.tar.gz")
        cp "$3" "$work/build/gclone"
        (cd "$work/build" && tar -cf - gclone | gzip >"$1/gclone-$host-signed.tar.gz")
        rm -rf "$work/build"
        (
            cd "$1"
            : >SHA256SUMS
            for file in gclone-*.tar.gz; do
                printf '%s  %s\n' "$(sha256_of "$file")" "$file" >>SHA256SUMS
            done
        )
    }
    mkdir "$work/sig"
    text7="gclone 7.0.0 ($host, no auth URL built in)"
    macho "$work/sig/ci7" "$text7"
    sign "$work/sig/ci7" "$work/sig/signed7" --options runtime
    signed_release "$work/sig/v7" "$work/sig/ci7" "$work/sig/signed7"
    # The next release of the same signer: in a test, the same signed binary.
    text8="gclone 7.0.1 ($host, no auth URL built in)"
    macho "$work/sig/ci8" "$text8"
    sign "$work/sig/ci8" "$work/sig/signed8" --options runtime
    signed_release "$work/sig/v8" "$work/sig/ci8" "$work/sig/signed8"

    d="$work/sig/dest"
    run "signed build: first install" 0 "$adhoc" -- --base-url "$work/sig/v7" --dir "$d"
    has "Installed $text7"
    has "signed by Developer ID team not set, identifier $signer (first signed install: later updates must come from the same signer)"
    has "install.sh: note: gclone-$host-signed.tar.gz was checked against the release's SHA256SUMS, its signature (Developer ID team not set, identifier $signer) was verified and it is gclone-$host.tar.gz of the same release apart from the signature; the build provenance was NOT checked (--base-url names a directory, not a GitHub release)."
    lacks "SHA256SUMS only"
    installed "$d" "$text7"
    [ "$(flags_of "$d/gclone")" = "0x10002(adhoc,runtime)" ] || fail "$current: the unsigned build was installed" "$(flags_of "$d/gclone")"
    no_leftovers "$d"
    notes=$(printf '%s\n' "$out" | grep -c "install.sh: note:" || true)
    [ "$notes" -eq 1 ] || fail "$current: $notes notes, expected one line"

    run "signed build: the same signer again" 0 "$adhoc" -- --base-url "$work/sig/v7" --dir "$d"
    has "Reinstalled $text7"
    has "install.sh: the new binary is signed by the same signer as the installed one"
    has "     signed by Developer ID team not set, identifier $signer"
    lacks "first signed install"

    # Without the test switch an ad hoc signature is what it is: not a Developer ID.
    run "signed build: an ad hoc signature is no Developer ID" 1 -- --base-url "$work/sig/v7" --dir "$work/sig/strict"
    has "gclone-$host-signed.tar.gz is not signed with an Apple-issued Developer ID certificate — nothing was installed"
    [ ! -e "$work/sig/strict/gclone" ] || fail "$current: something was installed"

    # --unsigned: the attested build, into a place without a signed gclone.
    run "signed build: --unsigned" 0 "$adhoc" -- --base-url "$work/sig/v7" --dir "$work/sig/plain" --unsigned
    has "install.sh: --unsigned: installing gclone-$host.tar.gz although the release has gclone-$host-signed.tar.gz"
    has "SHA256SUMS only (--base-url names a directory, not a GitHub release)"
    lacks "signed by"
    case "$(flags_of "$work/sig/plain/gclone")" in
        *runtime*) fail "$current: the signed build was installed" ;;
    esac
    run "signed build: by the environment" 0 "$adhoc" GCLONE_UNSIGNED=1 -- --base-url "$work/sig/v7" --dir "$work/sig/plain"
    has "--unsigned: installing"
    # An unsigned gclone in place, then the signed build: trust on first use.
    run "signed build: over an unsigned install" 0 "$adhoc" -- --base-url "$work/sig/v7" --dir "$work/sig/plain"
    has "first signed install"
    [ "$(flags_of "$work/sig/plain/gclone")" = "0x10002(adhoc,runtime)" ] || fail "$current: not the signed build"

    # Continuity: over a signed gclone, the unsigned build of the same release stops …
    run "continuity: --unsigned over a signed install" 1 "$adhoc" -- --base-url "$work/sig/v7" --dir "$d" --unsigned
    has "the installed gclone is signed; this one is not — nothing was installed"
    has "--allow-signer-change"
    installed "$d" "$text7"
    [ "$(flags_of "$d/gclone")" = "0x10002(adhoc,runtime)" ] || fail "$current: the install was replaced"
    no_leftovers "$d"
    # … and so does a release that has no signed archive at all (omitting it is no way around).
    run "continuity: a release without a signed build over a signed install" 1 "$adhoc" "GCLONE_TARGET=$host" -- --base-url "$v9" --dir "$d"
    has "the installed gclone is signed; this one is not — nothing was installed"
    installed "$d" "$text7"
    # … and a build signed by somebody else.
    run "continuity: another signer" 1 "$adhoc" -- --base-url "$work/sig/v8" --dir "$d"
    has "the installed gclone and this one are signed by different Developer ID signers — nothing was installed"
    has "installed: $d/gclone, which requires: cdhash"
    installed "$d" "$text7"
    no_leftovers "$d"
    # Each of them goes through when the user says so.
    run "continuity: another signer, allowed" 0 "$adhoc" -- --base-url "$work/sig/v8" --dir "$d" --allow-signer-change
    has "install.sh: warning: the installed gclone and this one are signed by different Developer ID signers; installing all the same (--allow-signer-change)"
    has "to $text8"
    installed "$d" "$text8"
    run "continuity: unsigned over signed, allowed by the environment" 0 "$adhoc" GCLONE_ALLOW_SIGNER_CHANGE=1 "GCLONE_TARGET=$host" -- --base-url "$v9" --dir "$d"
    has "warning: the installed gclone is signed; this one is not; installing all the same"
    installed "$d" "gclone 9.9.9 ($host, no auth URL built in)"

    # What the signed build of a release must be. Each bad one is a release of its own.
    bad_release() {
        rm -rf "$work/sig/bad"
        signed_release "$work/sig/bad" "$1" "$2"
    }
    refused_signed() {
        run "$1" 1 "$adhoc" -- --base-url "$work/sig/bad" --dir "$work/sig/victim"
        has "$2"
        has "nothing was installed"
        [ ! -e "$work/sig/victim/gclone" ] || fail "$current: something was installed"
    }
    cat >"$work/sig/entitlements.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.cs.disable-library-validation</key><true/></dict></plist>
PLIST
    sign "$work/sig/ci7" "$work/sig/entitled" --options runtime --entitlements "$work/sig/entitlements.plist"
    bad_release "$work/sig/ci7" "$work/sig/entitled"
    refused_signed "signed build: with an entitlement" "gclone-$host-signed.tar.gz is signed with entitlements"

    sign "$work/sig/ci7" "$work/sig/library" --options runtime,library
    bad_release "$work/sig/ci7" "$work/sig/library"
    refused_signed "signed build: another flag beside the runtime" "is signed with the flags '0x12002(adhoc,library-validation,runtime)'"
    has "A release binary has the hardened runtime and nothing else: 0x10002(adhoc,runtime)."

    sign "$work/sig/ci7" "$work/sig/noruntime"
    bad_release "$work/sig/ci7" "$work/sig/noruntime"
    refused_signed "signed build: without the hardened runtime" "is not signed with an Apple-issued Developer ID certificate"

    cp "$work/sig/signed7" "$work/sig/appended"
    printf 'x' >>"$work/sig/appended"
    bad_release "$work/sig/ci7" "$work/sig/appended"
    refused_signed "signed build: bytes appended after signing" "the signature of gclone-$host-signed.tar.gz does not verify"

    # The equality proof: the signed binary of another build (here: one that prints something
    # else — a difference of a few bytes in the code) is not "the attested build, signed".
    macho "$work/sig/other" "gclone 7.0.0 ($host, no auth URL built in!)"
    sign "$work/sig/other" "$work/sig/other-signed" --options runtime
    bad_release "$work/sig/ci7" "$work/sig/other-signed"
    refused_signed "signed build: not the attested binary" "gclone-$host-signed.tar.gz is not gclone-$host.tar.gz with a signature: the two binaries differ"
    # … while a pair that is equal apart from the signature passes (signed again, the same code).
    sign "$work/sig/ci7" "$work/sig/again" --options runtime
    bad_release "$work/sig/ci7" "$work/sig/again"
    run "signed build: equal apart from the signature" 0 "$adhoc" -- --base-url "$work/sig/bad" --dir "$work/sig/equal"
    installed "$work/sig/equal" "$text7"

    # The signed archive is checked against SHA256SUMS like the other one.
    rm -rf "$work/sig/bad"
    cp -R "$work/sig/v7" "$work/sig/bad"
    printf 'x' >>"$work/sig/bad/gclone-$host-signed.tar.gz"
    refused_signed "signed build: a damaged download" "checksum mismatch for gclone-$host-signed.tar.gz"

    # With the GitHub CLI: the unsigned archive's build attestation, the equality proof, and
    # the signed archive's place in the published release.
    mkdir -p "$work/sig/v999"
    text9="gclone 9.9.9 ($host, no auth URL built in)"
    macho "$work/sig/ci9" "$text9"
    sign "$work/sig/ci9" "$work/sig/signed9" --options runtime
    signed_release "$work/sig/v999/dist" "$work/sig/ci9" "$work/sig/signed9"
    served="$work/sig/v999/dist"
    start_server
    web_env="GCLONE_GITHUB_API=$github GCLONE_GITHUB_WEB=$github"
    printf '%s acme/gclone %s refs/tags/v9.9.9\n' "$(sha256_of "$served/gclone-$host.tar.gz")" "$workflow" >"$work/sig/attested"
    printf '%s acme/gclone v9.9.9\n' "$(sha256_of "$served/gclone-$host-signed.tar.gz")" >"$work/sig/release"
    gh_env="FAKE_GH_ATTEST=$work/sig/attested FAKE_GH_RELEASE=$work/sig/release"
    : >"$work/gh.log"
    # shellcheck disable=SC2086 # web_env and gh_env are VAR=VALUE words
    run "signed build: verified with gh" 0 "$adhoc" $web_env $gh_env FAKE_GH_TOKEN=good-token -- --dir "$work/sig/gh" --repo acme/gclone
    has "install.sh: verified the build-provenance attestation of gclone-$host.tar.gz (built by $workflow on refs/tags/v9.9.9)"
    has "install.sh: verified: gclone-$host-signed.tar.gz is the build of $workflow on refs/tags/v9.9.9, signed by Developer ID team not set, identifier $signer; identical apart from the signature"
    lacks "NOT checked"
    lacks "SHA256SUMS only"
    installed "$work/sig/gh" "$text9"
    [ "$(flags_of "$work/sig/gh/gclone")" = "0x10002(adhoc,runtime)" ] || fail "$current: not the signed build"
    case "$(gh_calls)" in
        *"release verify-asset v9.9.9 "*"/gclone-$host-signed.tar.gz --repo acme/gclone"*) ;;
        *) fail "$current: gh was not asked about the signed archive" "$(gh_calls)" ;;
    esac
    # Anonymous download, the release named by gh.
    # shellcheck disable=SC2086
    run "signed build: verified with gh, the latest release" 0 "$adhoc" $web_env $gh_env FAKE_GH_LATEST=v9.9.9 -- --dir "$work/sig/gh" --repo acme/gclone
    has "identical apart from the signature"
    # The signed archive was replaced in the release, with its line in SHA256SUMS: it is a
    # valid signed copy of the attested build — by somebody — and not a file of the release
    # GitHub attested.
    : >"$work/sig/no-release"
    # shellcheck disable=SC2086
    run "signed build: not a file of the published release" 1 "$adhoc" $web_env "FAKE_GH_ATTEST=$work/sig/attested" "FAKE_GH_RELEASE=$work/sig/no-release" -- --dir "$work/sig/gh2" --repo acme/gclone --version v9.9.9
    has "gclone-$host-signed.tar.gz is not a file of the published release v9.9.9 — nothing was installed"
    [ ! -e "$work/sig/gh2/gclone" ] || fail "$current: something was installed"
    # The unsigned archive has no attestation: refused before the signature is looked at.
    : >"$work/sig/no-attest"
    # shellcheck disable=SC2086
    run "signed build: the unsigned archive is not attested" 1 "$adhoc" $web_env "FAKE_GH_ATTEST=$work/sig/no-attest" "FAKE_GH_RELEASE=$work/sig/release" -- --dir "$work/sig/gh2" --repo acme/gclone --version v9.9.9
    has "the build-provenance attestation of gclone-$host.tar.gz could not be verified — nothing was installed"
    # A gh that verifies attestations but has no `release verify-asset` yet (2.68 to 2.74):
    # the attested build is verified, the signature too, and the one thing that could not be
    # asked is named — it used to end "is not a file of the published release", for every
    # install of a signed release.
    : >"$work/gh.log"
    # shellcheck disable=SC2086
    run "signed build: a gh without release verify-asset" 0 "$adhoc" $web_env $gh_env FAKE_GH_AGE=2.74 -- --dir "$work/sig/gh274" --repo acme/gclone --version v9.9.9
    has "install.sh: verified the build-provenance attestation of gclone-$host.tar.gz"
    has "whether the signed archive itself is a file of the published release was NOT checked (this GitHub CLI (gh) is older than 2.75.0"
    lacks "is not a file of the published release"
    lacks "unknown command"
    installed "$work/sig/gh274" "$text9"
    [ "$(flags_of "$work/sig/gh274/gclone")" = "0x10002(adhoc,runtime)" ] || fail "$current: not the signed build"
    # shellcheck disable=SC2086
    run "signed build: --require-attestation, a gh without release verify-asset" 1 "$adhoc" $web_env $gh_env FAKE_GH_AGE=2.74 -- --dir "$work/sig/gh2" --repo acme/gclone --version v9.9.9 --require-attestation
    has "whether gclone-$host-signed.tar.gz is a file of the published release v9.9.9 was not verified — nothing was installed"
    has "it needs gh 2.75.0 or newer"
    [ ! -e "$work/sig/gh2/gclone" ] || fail "$current: something was installed"
    # And one from before --source-ref: the signed build with the checksum note, as without gh.
    # shellcheck disable=SC2086
    run "signed build: a gh without --source-ref" 0 "$adhoc" $web_env $gh_env FAKE_GH_AGE=2.67 -- --dir "$work/sig/gh267" --repo acme/gclone --version v9.9.9
    has "the build provenance was NOT checked (this GitHub CLI (gh) is too old to verify attestations: it needs gh 2.68.0 or newer)."
    installed "$work/sig/gh267" "$text9"

    # The entitlements of the signed build are read with codesign, and "it printed nothing"
    # means "none" only when codesign succeeded: one that cannot answer (it does not know
    # --xml, say) used to count as "no entitlements".
    mkdir "$work/sig/badcodesign"
    real_codesign=$(command -v codesign)
    cat >"$work/sig/badcodesign/codesign" <<EOF_CS
#!/bin/sh
case " \$* " in
    *" --entitlements "*) echo "codesign: unrecognized option \\\`--xml'" >&2; exit 1 ;;
esac
exec "$real_codesign" "\$@"
EOF_CS
    chmod 755 "$work/sig/badcodesign/codesign"
    run "signed build: codesign cannot report the entitlements" 1 "$adhoc" "PATH=$work/sig/badcodesign:$PATH" -- --base-url "$work/sig/v999/dist" --dir "$work/sig/badcs"
    has "cannot read the entitlements of gclone-$host-signed.tar.gz"
    has "nothing was installed"
    [ ! -e "$work/sig/badcs/gclone" ] || fail "$current: something was installed"

    # Without gh: one line that says what was and what was not checked.
    # shellcheck disable=SC2086
    run "signed build: without gh" 0 "$adhoc" $web_env FAKE_GH_ATTEST=signed-out -- --dir "$work/sig/nogh" --repo acme/gclone
    has "the build provenance was NOT checked (the GitHub CLI (gh) is not signed in)."
    lacks "SHA256SUMS only"
    installed "$work/sig/nogh" "$text9"
    # --require-attestation without gh stops, signed build or not.
    # shellcheck disable=SC2086
    run "signed build: --require-attestation without gh" 1 "$adhoc" $web_env FAKE_GH_ATTEST=signed-out -- --dir "$work/sig/gh2" --repo acme/gclone --require-attestation
    has "was not verified (the GitHub CLI (gh) is not signed in) — nothing was installed"
    # A machine without codesign takes the attested build and says so (a PATH without it).
    mkdir "$work/sig/nocodesign"
    for tool in sh "$shell" curl tar gzip awk tr mktemp cp mv rm mkdir chmod cat sed grep sha256sum shasum openssl dirname ls head cmp; do
        path=$(command -v "$tool" 2>/dev/null || true)
        case "$path" in
            /*) [ -e "$work/sig/nocodesign/$tool" ] || ln -s "$path" "$work/sig/nocodesign/$tool" ;;
        esac
    done
    cp "$work/bin/uname" "$work/bin/gh" "$work/bin/sysctl" "$work/sig/nocodesign/"
    run "signed build: no codesign on the machine" 0 "$adhoc" "PATH=$work/sig/nocodesign" -- --base-url "$work/sig/v7" --dir "$work/sig/nocs"
    has "the release has gclone-$host-signed.tar.gz, but codesign is not on this system to check a signature with; installing gclone-$host.tar.gz"
    installed "$work/sig/nocs" "$text7"

    served="$work/v9/dist"
    start_server
    web_env="GCLONE_GITHUB_API=$github GCLONE_GITHUB_WEB=$github"
}

# On Linux a release with a signed macOS archive changes nothing: the extra line in
# SHA256SUMS is ignored, also by this version of the script.
mkdir -p "$work/extra"
cp "$work/v9/dist/"* "$work/extra/"
cp "$work/extra/gclone-aarch64-apple-darwin.tar.gz" "$work/extra/gclone-aarch64-apple-darwin-signed.tar.gz"
printf '%s  %s\n' "$(sha256_of "$work/extra/gclone-aarch64-apple-darwin-signed.tar.gz")" "gclone-aarch64-apple-darwin-signed.tar.gz" >>"$work/extra/SHA256SUMS"
run "a signed macOS archive in the release, a Linux machine" 0 FAKE_UNAME_S=Linux FAKE_UNAME_M=x86_64 -- --base-url "$work/extra" --dir "$work/extra-dest"
has "Installed gclone 9.9.9 (x86_64-unknown-linux-musl, "
lacks "signed"

if [ "$host" = aarch64-apple-darwin ] && command -v codesign >/dev/null 2>&1 && command -v cc >/dev/null 2>&1; then
    signed_cases
else
    echo "skipped: the cases of the signed macOS build (they need macOS on Apple silicon, codesign and cc)"
fi

# wget in place of curl (anonymous downloads only): a PATH without curl.
if command -v wget >/dev/null 2>&1; then
    mkdir "$work/nocurl"
    for tool in sh "$shell" wget tar gzip awk tr mktemp cp mv rm mkdir chmod cat sed grep sha256sum shasum openssl dirname ls; do
        path=$(command -v "$tool" 2>/dev/null || true)
        case "$path" in
            /*) [ -e "$work/nocurl/$tool" ] || ln -s "$path" "$work/nocurl/$tool" ;;
        esac
    done
    cp "$work/bin/uname" "$work/bin/gh" "$work/bin/sysctl" "$work/nocurl/"
    # shellcheck disable=SC2086
    run "wget, public repository" 0 $web_env "PATH=$work/nocurl" -- --dir "$work/wget" --repo acme/gclone
    has "Installed gclone 9.9.9 ($host, "
    # shellcheck disable=SC2086
    run "wget, a version that does not exist" 1 $web_env "PATH=$work/nocurl" -- --dir "$work/wget" --repo acme/gclone --version 1.2.3
    has "cannot download $github/acme/gclone/releases/download/v1.2.3/"
    has "404"
    : >"$work/v9/requests.log"
    # shellcheck disable=SC2086
    run "wget, with a token, public repository" 0 $web_env "PATH=$work/nocurl" GITHUB_TOKEN=good-token -- --dir "$work/wget2" --repo acme/gclone
    has "curl is needed to use the GitHub login (GITHUB_TOKEN); trying without the login"
    has "Installed gclone 9.9.9 ($host, "
    not_requested "/repos/"
    run "wget, a local directory (file://)" 0 "PATH=$work/nocurl" -- --base-url "$v9" --dir "$work/wget3"
    has "Installed gclone 9.9.9 ($host, "
else
    echo "skipped: the wget cases (wget is not installed)"
fi

if [ "$failures" -ne 0 ]; then
    printf '%s failed checks in %s cases (shell: %s)\n' "$failures" "$count" "$shell"
    exit 1
fi
printf 'ok: %s cases (shell: %s, host target: %s)\n' "$count" "$shell" "$host"
