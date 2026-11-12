#!/usr/bin/env python3
"""A stand-in for the parts of GitHub that install.sh talks to. For tests/install/test.sh only.

    fake_github.py DIST_DIR PORT_FILE [--compact] [--private]

Serves one release (tag v9.9.9, the files of DIST_DIR as its assets) of the repository
`acme/gclone` on two loopback ports, written to PORT_FILE as "<main> <storage>":

main port, as api.github.com (needs `Authorization: Bearer good-token`):
    GET /repos/acme/gclone/releases/latest
    GET /repos/acme/gclone/releases/tags/v9.9.9
    GET /repos/acme/gclone/releases/assets/<id>   with `Accept: application/octet-stream`
        -> 302 to the storage port
main port, as github.com (anonymous; 404 with --private):
    GET /acme/gclone/releases/latest/download/<name>  -> 302 -> .../download/v9.9.9/<name>
    GET /acme/gclone/releases/download/v9.9.9/<name>
storage port, under another host name (`localhost`, the main one is `127.0.0.1`):
    GET /blob/<name>    400 if an Authorization header arrives, as the real storage host answers

Every request is appended to DIST_DIR/../requests.log as "<port-role> <path> auth=<yes|no>".
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = "acme/gclone"
TAG = "v9.9.9"
TOKEN = "good-token"

dist = os.path.abspath(sys.argv[1])
port_file = sys.argv[2]
compact = "--compact" in sys.argv
private = "--private" in sys.argv
log_path = os.path.join(os.path.dirname(dist), "requests.log")
names = sorted(os.listdir(dist))
ports = {}


def release_json():
    api = f"http://127.0.0.1:{ports['main']}"
    assets = []
    for i, name in enumerate(names):
        assets.append(
            {
                "url": f"{api}/repos/{REPO}/releases/assets/{1000 + i}",
                "id": 1000 + i,
                "node_id": "RA_x",
                "name": name,
                "label": "",
                "uploader": {"login": "someone", "id": 1, "url": f"{api}/users/someone"},
                "content_type": "application/gzip",
                "state": "uploaded",
                "size": os.path.getsize(os.path.join(dist, name)),
                "browser_download_url": f"https://github.com/{REPO}/releases/download/{TAG}/{name}",
            }
        )
    release = {
        "url": f"{api}/repos/{REPO}/releases/77",
        "assets_url": f"{api}/repos/{REPO}/releases/77/assets",
        "html_url": f"https://github.com/{REPO}/releases/tag/{TAG}",
        "id": 77,
        "author": {"login": "someone", "id": 1, "url": f"{api}/users/someone"},
        "tag_name": TAG,
        "target_commitish": "main",
        # A title and notes that look like the fields the script reads.
        "name": "gclone-x86_64-unknown-linux-musl.tar.gz",
        "draft": False,
        "prerelease": False,
        "assets": assets,
        "tarball_url": f"{api}/repos/{REPO}/tarball/{TAG}",
        "body": 'notes, with "name": "SHA256SUMS", and "tag_name": "v0.0.0" in them',
    }
    if compact:
        return json.dumps(release, separators=(",", ":")).encode()
    return json.dumps(release, indent=2).encode()


class Handler(BaseHTTPRequestHandler):
    role = "main"

    def log_message(self, *args):
        pass

    def answer(self, status, body=b"", headers=()):
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def file(self, name):
        if name not in names:
            return self.answer(404, b"no such asset\n")
        with open(os.path.join(dist, name), "rb") as f:
            self.answer(200, f.read())

    def do_GET(self):
        auth = self.headers.get("Authorization")
        with open(log_path, "a") as log:
            log.write(f"{self.role} {self.path} auth={'yes' if auth else 'no'}\n")
        path = self.path
        if self.role == "storage":
            if auth:
                return self.answer(400, b"InvalidAuthenticationInfo\n")
            if path.startswith("/blob/"):
                return self.file(path[len("/blob/"):])
            return self.answer(404)

        api = f"/repos/{REPO}/releases/"
        if path.startswith("/repos/"):
            if auth != f"Bearer {TOKEN}":
                return self.answer(401, b'{"message": "Bad credentials"}')
            if path in (api + "latest", api + "tags/" + TAG):
                return self.answer(200, release_json(), [("Content-Type", "application/json")])
            if path.startswith(api + "assets/"):
                index = int(path[len(api + "assets/"):]) - 1000
                if not 0 <= index < len(names):
                    return self.answer(404)
                if self.headers.get("Accept") != "application/octet-stream":
                    return self.answer(200, b'{"this is": "the asset\'s JSON, not its bytes"}')
                target = f"http://localhost:{ports['storage']}/blob/{names[index]}"
                return self.answer(302, headers=[("Location", target)])
            return self.answer(404, b'{"message": "Not Found"}')

        web = f"/{REPO}/releases/"
        if private:
            return self.answer(404, b"Not Found\n")
        if path.startswith(web + "latest/download/"):
            name = path[len(web + "latest/download/"):]
            return self.answer(302, headers=[("Location", f"{web}download/{TAG}/{name}")])
        if path.startswith(f"{web}download/{TAG}/"):
            return self.file(path[len(f"{web}download/{TAG}/"):])
        return self.answer(404, b"Not Found\n")


class Storage(Handler):
    role = "storage"


main = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
storage = ThreadingHTTPServer(("127.0.0.1", 0), Storage)
ports["main"] = main.server_address[1]
ports["storage"] = storage.server_address[1]
threading.Thread(target=storage.serve_forever, daemon=True).start()
with open(port_file + ".tmp", "w") as f:
    f.write(f"{ports['main']} {ports['storage']}\n")
os.replace(port_file + ".tmp", port_file)
main.serve_forever()
