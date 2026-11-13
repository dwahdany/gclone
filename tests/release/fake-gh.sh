#!/bin/bash
# A stand-in for the GitHub CLI over a directory, for the self-test of
# scripts/release-sign-macos.sh (tests/release/selftest.sh). It answers exactly the calls that
# script makes, the way GitHub does where it matters: a draft can be changed, a published
# release cannot; an attestation holds for certain bytes, a ref and a commit, and for nothing
# else. Nothing here talks to a network.
#
# The state directory ($FAKE_GH_STATE):
#   push, immutable              "true" or "false"
#   attested                     lines `<sha256> <ref> <commit>`: files with a build attestation
#   releases/<tag>/draft         "true" or "false"
#   releases/<tag>/body          the notes
#   releases/<tag>/assets/       the files
#   order                        the tags, newest first (`release list`)
#   log                          every call that changed something
#   hook                         if executable: run before every call, with the call's arguments;
#                                a hook that fails is the call failing (a network error)
#   cut-upload                   names, one per line: the next `release upload` of such a file is
#                                cut off the way the real `gh release upload --clobber` can be —
#                                it deletes the old asset first, then fails before the new one
#                                is there. (One-shot per line.)
#   lie-after-publish            if present: `release view` reports this file's lines as the
#                                digests of a published release (GitHub says one thing and
#                                serves another)
set -eu
state=${FAKE_GH_STATE:?FAKE_GH_STATE is not set}

[ ! -x "$state/hook" ] || "$state/hook" "$@"

sha() { shasum -a 256 "$1" | awk '{ print $1 }'; }
bad() {
    echo "fake gh: unexpected call: $*" >&2
    exit 2
}
# value_of FLAG ARGS…: the word after FLAG.
value_of() {
    flag=$1
    shift
    while [ $# -gt 0 ]; do
        if [ "$1" = "$flag" ]; then
            echo "${2:-}"
            return 0
        fi
        shift
    done
}

case "${1:-} ${2:-}" in
    "--version "*)
        echo "gh version fake-gh (self-test of release-sign-macos.sh)"
        ;;
    "auth status")
        exit 0
        ;;
    "api repos/"*)
        case "$2" in
            */immutable-releases) cat "$state/immutable" ;;
            *) cat "$state/push" ;;
        esac
        ;;
    "attestation verify")
        file=$3
        ref=$(value_of --source-ref "$@")
        commit=$(value_of --source-digest "$@")
        case " $* " in *" --deny-self-hosted-runners "*) ;; *) bad "$@" ;; esac
        [ -n "$(value_of --signer-workflow "$@")" ] || bad "$@"
        if grep -qxF "$(sha "$file") $ref $commit" "$state/attested" 2>/dev/null; then
            echo "✓ Verification succeeded!"
            exit 0
        fi
        echo "Error: HTTP 404: Not Found (no attestation for sha256:$(sha "$file"))" >&2
        exit 1
        ;;
    "release list")
        [ -f "$state/order" ] || exit 0
        while read -r tag; do
            if [ "$(cat "$state/releases/$tag/draft")" = false ]; then echo "$tag"; fi
        done <"$state/order"
        exit 0
        ;;
    "release view")
        tag=$3
        dir="$state/releases/$tag"
        [ -d "$dir" ] || {
            echo "release not found" >&2
            exit 1
        }
        case "$(value_of --jq "$@")" in
            .isDraft) cat "$dir/draft" ;;
            .body) cat "$dir/body" ;;
            ".assets[].name") ls "$dir/assets" ;;
            ".assets[] | "*)
                if [ -f "$state/lie-after-publish" ] && [ "$(cat "$dir/draft")" = false ]; then
                    cat "$state/lie-after-publish"
                else
                    for f in "$dir/assets"/*; do printf '%s  %s\n' "$(sha "$f")" "$(basename "$f")"; done
                fi
                ;;
            *) bad "$@" ;;
        esac
        ;;
    "release download")
        tag=$3
        name=$(value_of --pattern "$@")
        to=$(value_of --dir "$@")
        [ -f "$state/releases/$tag/assets/$name" ] || {
            echo "no assets match the file pattern" >&2
            exit 1
        }
        mkdir -p "$to"
        cp "$state/releases/$tag/assets/$name" "$to/$name"
        ;;
    "release upload")
        tag=$3
        dir="$state/releases/$tag"
        file=""
        for arg in "$@"; do file=$arg; done
        if [ "$(cat "$dir/draft")" = false ] && [ "$(cat "$state/immutable")" = true ]; then
            echo "HTTP 422: Cannot upload assets to an immutable release." >&2
            exit 1
        fi
        case " $* " in
            *" --clobber "*) ;;
            *) [ ! -e "$dir/assets/$(basename "$file")" ] || bad "$@" ;;
        esac
        # --clobber: the old asset is deleted, THEN the new one is uploaded.
        rm -f "$dir/assets/$(basename "$file")"
        if grep -qxF "$(basename "$file")" "$state/cut-upload" 2>/dev/null; then
            grep -vxF "$(basename "$file")" "$state/cut-upload" >"$state/cut-upload.next" || true
            mv "$state/cut-upload.next" "$state/cut-upload"
            echo "delete $tag $(basename "$file")" >>"$state/log"
            echo "Post \"https://uploads.github.com/…\": unexpected EOF" >&2
            exit 1
        fi
        cp "$file" "$dir/assets/$(basename "$file")"
        echo "upload $tag $(basename "$file")" >>"$state/log"
        ;;
    "release edit")
        tag=$3
        dir="$state/releases/$tag"
        case " $* " in *" --draft=false "*) ;; *) bad "$@" ;; esac
        notes=$(value_of --notes-file "$@")
        [ -z "$notes" ] || cp "$notes" "$dir/body"
        echo false >"$dir/draft"
        echo "publish $tag" >>"$state/log"
        ;;
    "release verify")
        tag=$3
        # A release attestation exists for a published, immutable release.
        [ "$(cat "$state/releases/$tag/draft")" = false ] && [ "$(cat "$state/immutable")" = true ]
        ;;
    "release verify-asset")
        tag=$3
        file=$4
        [ "$(cat "$state/releases/$tag/draft")" = false ] && [ "$(cat "$state/immutable")" = true ] &&
            [ -f "$state/releases/$tag/assets/$(basename "$file")" ] &&
            cmp -s "$file" "$state/releases/$tag/assets/$(basename "$file")"
        ;;
    *)
        bad "$@"
        ;;
esac
