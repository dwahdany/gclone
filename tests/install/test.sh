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
    GCLONE_BASE_URL GCLONE_GITHUB_API GCLONE_GITHUB_WEB TERMUX_VERSION 2>/dev/null || true

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
mkdir "$work/bin"
cat >"$work/bin/gh" <<'EOF'
#!/bin/sh
if [ "$1 $2" = "auth token" ] && [ -n "${FAKE_GH_TOKEN:-}" ]; then
    echo "$FAKE_GH_TOKEN"
    exit 0
fi
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

start_server() {
    [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
    rm -f "$work/ports" "$work/v9/requests.log"
    python3 "$here/fake_github.py" "$work/v9/dist" "$work/ports" "$@" &
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
