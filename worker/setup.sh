#!/bin/sh
# One-time setup of the gclone auth Worker (README.md, "One-time setup"): deploy, the Google console checklist,
# the four secrets, a final check. Interactive; run it yourself, once. Secrets go from your keyboard (or from
# openssl) straight into `wrangler secret put` and into no file. The one file it can change is wrangler.jsonc, and
# only when you choose to serve the Worker from a host name of your own (scripts/custom-domain.mjs writes the
# `routes` entry and turns the workers.dev host off - keep that change, every later deploy needs it).
set -eu

cd "$(dirname "$0")"

say() { printf '%s\n' "$*"; }
die() { say "setup: $*" >&2; exit 1; }
pause() { printf '%s' "Press Enter to continue (Ctrl-C to stop). "; read -r _discard || die "no input"; }

ask() { # ask VAR "prompt": one non-empty line
  while :; do
    printf '%s' "$2"
    read -r answer || die "no input"
    [ -n "$answer" ] && break
  done
  eval "$1=\$answer"
}

ask_hidden() { # like ask, without echoing what is typed
  if [ -t 0 ]; then
    saved_tty=$(stty -g)
    trap 'stty "$saved_tty"' EXIT
    trap 'stty "$saved_tty"; exit 130' INT TERM
    stty -echo
    ask "$1" "$2"
    stty "$saved_tty"
    trap - EXIT INT TERM
    say
  else
    ask "$1" "$2"
  fi
}

put_secret() { # put_secret NAME VALUE — the value travels on stdin, never in argv or a file
  printf '%s' "$2" | npx wrangler secret put "$1" >/dev/null || die "wrangler secret put $1 failed"
  say "  $1 set"
}

# authorized_domain HOST: sets $domain to what Google's "Authorized domains" wants for the Worker's host, and
# $domain_note when that is a guess. Google takes a registrable domain only (a "top private domain"), never a host
# below one. <acct>.workers.dev is one (workers.dev is a public suffix). For a domain of your own it can only be
# guessed: the last two labels, which is wrong under a two-part suffix such as .co.uk - hence the note.
authorized_domain() {
  domain_note=
  case $1 in
    *.workers.dev) domain=${1#*.} ;;
    *.*.*)
      domain=${1#"${1%.*.*}".}
      domain_note="   (the registrable domain of $1, not the host itself; under a suffix like .co.uk it has three labels)"
      ;;
    *) domain=$1 ;;
  esac
}

# ./setup.sh --authorized-domain HOST prints that domain and does nothing else (scripts/setup.selftest.mjs).
if [ "${1:-}" = "--authorized-domain" ]; then
  [ -n "${2:-}" ] || die "--authorized-domain needs a host name"
  authorized_domain "$2"
  say "$domain$domain_note"
  exit 0
fi

for tool in node npm npx openssl curl; do
  command -v "$tool" >/dev/null 2>&1 || die "'$tool' is needed but was not found"
done

# Until the secrets are put the home page says "Status: not configured" - either status line proves it is the Worker.
answers() { curl -fsS "$1/" 2>/dev/null | grep -q 'Status: '; }

say "== 1/4  Deploy the Worker =="
cat <<EOF
Where will your devices reach the Worker? The URL goes into the Google client and into every device's login, so
choosing now saves doing both twice.
  1) https://gclone-auth.<acct>.workers.dev - works at once. No rate-limiting rule can be put in front of it:
     anyone can use up the free plan's daily request quota and stop your logins until midnight UTC (README.md).
  2) A host name of your own, for example auth.example.org. Its domain (example.org) must already be a zone in
     this Cloudflare account. Recommended.
EOF
custom_host=
while :; do
  ask where "1 or 2: "
  case $where in
    1) break ;;
    2)
      ask custom_host "Host name (for example auth.example.org): "
      custom_host=${custom_host#https://}
      custom_host=${custom_host%/}
      # Writes "workers_dev": false and the "routes" entry into wrangler.jsonc; refuses anything but a bare host name.
      if node scripts/custom-domain.mjs "$custom_host"; then break; fi
      custom_host=
      ;;
    *) say "  Answer 1 or 2." ;;
  esac
done

say
say "This installs the build tools, signs in to Cloudflare (a browser opens) and deploys the Worker."
pause
npm install
npx wrangler login
npx wrangler deploy

say
if [ -n "$custom_host" ]; then
  auth_url="https://$custom_host"
  say "Waiting for $auth_url/ (the DNS record and the certificate of a new host can take a few minutes) ..."
  attempt=0
  until answers "$auth_url"; do
    attempt=$((attempt + 1))
    [ "$attempt" -ge 60 ] && die "$auth_url/ does not answer like the gclone auth Worker yet. Check the domain under Workers & Pages -> gclone-auth -> Settings -> Domains & Routes, then run ./setup.sh again and give the same host name."
    sleep 5
  done
else
  say "wrangler printed the Worker's URL above: https://gclone-auth.<acct>.workers.dev"
  while :; do
    ask auth_url "Enter that URL: "
    auth_url=${auth_url%/}
    case $auth_url in
      https://?*.?*) ;;
      *) say "  '$auth_url' is not an https:// URL."; continue ;;
    esac
    if answers "$auth_url"; then break; fi
    say "  $auth_url/ does not answer like the gclone auth Worker (a new workers.dev host can take a minute)."
  done
fi
host=${auth_url#https://}
authorized_domain "$host"

say
say "Your auth URL:  $auth_url"
say
say "== 2/4  Google Cloud console (in your browser) =="
cat <<EOF
  1. Create a project:   https://console.cloud.google.com/projectcreate   (any name)
     Enable the Drive API:   https://console.cloud.google.com/apis/library/drive.googleapis.com  ->  Enable
  2. Google Auth Platform -> Get started:   https://console.cloud.google.com/auth/overview
       App name: gclone        Support and contact e-mail: yours        Audience: External
       Do NOT upload a logo (it triggers brand verification).
  3. Branding:
       Authorized domain:      $domain$domain_note
       Application home page:  $auth_url/
       Privacy policy:         $auth_url/privacy
  4. Audience -> Publish app.  The status must read "In production".
       Do NOT click "Submit for verification".
  5. Clients -> Create client -> Application type: Web application
       Authorized redirect URI:  $auth_url/callback      (exactly; no JavaScript origins)
       Copy the client ID and the client secret NOW - the secret is shown only once.

  (Workspace accounts may choose Audience "Internal" instead of External + Publish.)
EOF
say
pause

say
say "== 3/4  The Worker's four secrets =="
ask client_id "Client ID: "
ask_hidden client_secret "Client secret (not shown while you type): "
say "Which Google accounts may sign in? Usually just yours. Several addresses: comma-separated."
ask allowed_emails "Allowed e-mail address(es): "
put_secret GOOGLE_CLIENT_ID "$client_id"
put_secret GOOGLE_CLIENT_SECRET "$client_secret"
put_secret SEAL_KEY "$(openssl rand -base64 32)"
put_secret ALLOWED_EMAILS "$allowed_emails"
unset client_secret

say
say "== 4/4  Check =="
attempt=0
while :; do
  attempt=$((attempt + 1))
  if curl -fsS "$auth_url/" 2>/dev/null | grep -q 'Status: ready'; then
    say "$auth_url/ answers 'Status: ready'."
    break
  fi
  [ "$attempt" -ge 6 ] && die "$auth_url/ does not answer 'Status: ready' yet. Try 'curl $auth_url/' in a minute; see README.md, Troubleshooting."
  sleep 5
done

cat <<EOF

Done. On every device:

    gclone login $auth_url

Google console changes can take from five minutes to a few hours to apply.
EOF
if [ -n "$custom_host" ]; then
  cat <<EOF
Keep the change to wrangler.jsonc (commit it): every later deploy needs the "routes" entry.
Recommended next: the rate-limiting rule for $host (README.md, "Custom domain and rate-limiting rule", step 5).
EOF
else
  say "Recommended next: a custom domain with a rate-limiting rule (README.md)."
fi
