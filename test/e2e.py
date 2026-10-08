"""End-to-end test: MiroPush.py (outside Rhino) -> real Worker under `wrangler dev` -> mock Miro.

    python3 -I test/e2e.py

No real Miro account or secrets: the mock plays both Miro's OAuth server and the REST API.
"""
import base64
import email.parser
import email.policy
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKER_PORT = 8799
CLIENT_ID, CLIENT_SECRET, BOARD = "test-client", "test-secret", "uXjVTEST1234="


class Mock:
    def __init__(self):
        self.codes = {}
        self.access = set()
        self.refresh = set()
        self.items = {}  # id -> {"type", "data", "parts"}
        self.n = 0
        self.log = []

    def issue(self):
        self.n += 1
        at, rt = "at%d" % self.n, "rt%d" % self.n
        self.access.add(at)
        self.refresh.add(rt)
        return {"access_token": at, "refresh_token": rt, "expires_in": 3600, "team_id": "t1", "user_id": "u1",
                "scope": "boards:read boards:write", "token_type": "bearer"}


M = Mock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, body=None, headers=None):
        raw = json.dumps(body).encode() if body is not None else b""
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def route(self):
        url = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(url.query))
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        M.log.append((self.command, url.path))

        if url.path == "/oauth/authorize":
            assert q["client_id"] == CLIENT_ID and q["response_type"] == "code"
            back = q["redirect_uri"] + "?" + urllib.parse.urlencode(
                {"error": "access_denied", "state": q["state"]} if M.__dict__.get("deny") else
                {"code": self._code(q["redirect_uri"]), "state": q["state"]})
            return self.reply(302, headers={"location": back})

        if url.path == "/v1/oauth/token" and self.command == "POST":
            if q.get("client_id") != CLIENT_ID or q.get("client_secret") != CLIENT_SECRET:
                return self.reply(401, {"error": "invalid_client"})
            if q["grant_type"] == "authorization_code":
                if M.codes.pop(q.get("code"), None) != q.get("redirect_uri"):
                    return self.reply(400, {"error": "invalid_grant"})
                return self.reply(200, M.issue())
            if q["grant_type"] == "refresh_token":
                if q.get("refresh_token") not in M.refresh:
                    return self.reply(400, {"error": "invalid_grant"})
                M.refresh.clear()  # rotation: every older token pair dies
                M.access.clear()
                return self.reply(200, M.issue())
            return self.reply(400, {"error": "unsupported_grant_type"})

        auth = self.headers.get("authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] not in M.access:
            return self.reply(401, {"message": "Unauthorized"})

        parts = url.path.strip("/").split("/")  # v2 boards <id> <kind> [<item>]
        if parts[:2] != ["v2", "boards"] or urllib.parse.unquote(parts[2]) != BOARD:
            return self.reply(404, {"message": "board not found"})
        if len(parts) == 3:
            return self.reply(200, {"id": BOARD, "name": "Test board"})
        kind = parts[3]
        item_id = parts[4] if len(parts) > 4 else None
        if kind == "images":
            fields = self._multipart(body)
            assert fields["data"][0] == "application/json", fields["data"][0]
            assert fields["resource"][0] == "image/png"
            data = json.loads(fields["data"][1])
        else:
            data = json.loads(body)
        if self.command == "POST" and item_id is None:
            M.n += 1
            new_id = "%s-%d" % (kind, M.n)
            M.items[new_id] = {"type": kind, "data": data, "bytes": len(body), "updates": 0}
            return self.reply(201, {"id": new_id, "type": kind})
        if self.command == "PATCH" and item_id:
            if item_id not in M.items:
                return self.reply(404, {"message": "item not found"})
            M.items[item_id]["updates"] += 1
            M.items[item_id]["last"] = data
            return self.reply(200, {"id": item_id})
        return self.reply(405, {"message": "nope"})

    def _code(self, redirect_uri):
        code = secrets.token_hex(8)
        M.codes[code] = redirect_uri
        return code

    def _multipart(self, body):
        msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
            b"content-type: " + self.headers["content-type"].encode() + b"\r\n\r\n" + body)
        return {p.get_param("name", header="content-disposition"): (p.get_content_type(), p.get_payload(decode=True))
                for p in msg.iter_parts()}

    do_GET = do_POST = do_PATCH = route


def start_mock():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


def start_worker(mock_port):
    token_key = base64.b64encode(secrets.token_bytes(32)).decode()
    mock = "http://127.0.0.1:%d" % mock_port
    args = ["npx", "wrangler", "dev", "--port", str(WORKER_PORT), "--ip", "127.0.0.1", "--show-interactive-dev-session=false",
            "--var", "PUBLIC_BASE_URL:http://127.0.0.1:%d" % WORKER_PORT,
            "--var", "MIRO_CLIENT_ID:" + CLIENT_ID, "--var", "MIRO_CLIENT_SECRET:" + CLIENT_SECRET,
            "--var", "TOKEN_KEY:" + token_key,
            "--var", "MIRO_AUTHORIZE_URL:%s/oauth/authorize" % mock, "--var", "MIRO_TOKEN_URL:%s/v1/oauth/token" % mock]
    proc = subprocess.Popen(args, cwd=os.path.join(ROOT, "worker"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(120):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/health" % WORKER_PORT, timeout=1) as r:
                health = json.loads(r.read())
                assert health["configured"], health
                return proc
        except OSError:
            time.sleep(0.5)
    proc.kill()
    print(proc.stdout.read().decode()[-3000:])
    raise SystemExit("wrangler dev did not start")


class MemoryStore:
    def __init__(self):
        self.tokens = None

    def load(self):
        return self.tokens

    def save(self, t):
        self.tokens = dict(t)

    def clear(self):
        self.tokens = None


def browser(url):
    """Follows the whole redirect chain like a browser would, on another thread (the loopback is served by ours)."""
    def go():
        try:
            urllib.request.urlopen(url, timeout=10).read()
        except Exception as err:  # noqa: BLE001 - surfaced through sign_in's timeout
            print("browser error:", err)
    threading.Thread(target=go, daemon=True).start()


passed = 0


def check(name, cond, detail=""):
    global passed
    if not cond:
        raise AssertionError("%s %s" % (name, detail))
    passed += 1
    print("ok  ", name)


def main():
    mock_port = start_mock()
    os.environ["MIRO_RHINO_AUTH_URL"] = "http://127.0.0.1:%d" % WORKER_PORT
    os.environ["MIRO_RHINO_API_URL"] = "http://127.0.0.1:%d" % mock_port
    proc = start_worker(mock_port)
    try:
        sys.path.insert(0, os.path.join(ROOT, "rhino"))
        import MiroPush as mp

        base = mp.AUTH_BASE

        # Worker input validation
        for qs in ["port=80&state=%s&code_challenge=%s" % ("s" * 20, "c" * 43),
                   "port=5000&state=short&code_challenge=%s" % ("c" * 43),
                   "port=5000&state=%s&code_challenge=tooshort" % ("s" * 20)]:
            status, _ = mp.http_request("GET", base + "/login?" + qs)
            check("login rejects bad input (%s)" % qs[:20], status == 400, status)
        status, body = mp.post_json(base + "/redeem", {"ticket": "x" * 60, "code_verifier": "v"})
        check("redeem rejects a forged ticket", status == 400 and body["error"] == "invalid_grant", body)
        status, _ = mp.http_request("GET", base + "/callback?state=garbage&code=x")
        check("callback rejects a forged state", status == 400)

        # Sign-in round trip
        store = mp.MiroClient  # placate linters
        store = MemoryStore()
        tokens = mp.sign_in(store, open_browser=browser, timeout=20)
        check("sign-in returns tokens", tokens["access_token"] == "at1" and tokens["refresh_token"] == "rt1", tokens)
        check("sign-in stores tokens with an absolute expiry", store.tokens["expires_at"] > time.time() * 1000)

        # A ticket can't be opened without the verifier: replay the login with our own challenge
        verifier, challenge = mp._pkce_pair()
        captured = {}

        class NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                if newurl.startswith("http://127.0.0.1:5555/"):
                    captured["url"] = newurl
                    return None
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        try:
            urllib.request.build_opener(NoFollow).open(base + "/login?" + urllib.parse.urlencode(
                {"port": 5555, "state": "s" * 24, "code_challenge": challenge}), timeout=10)
        except urllib.error.HTTPError:
            pass
        ticket = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(captured["url"]).query))["ticket"]
        check("ticket is sealed (no token in the URL)", "at" not in ticket[:3] and "rt" not in captured["url"].split("ticket=")[0])
        status, _ = mp.post_json(base + "/redeem", {"ticket": ticket, "code_verifier": mp._pkce_pair()[0]})
        check("redeem rejects the wrong verifier", status == 400)
        status, other = mp.post_json(base + "/redeem", {"ticket": ticket, "code_verifier": verifier})
        check("redeem accepts the right verifier", status == 200 and other["access_token"].startswith("at"), other)

        # Use the first session again (the replayed login minted a second one, which is fine for Miro)
        store.save(other)
        client = mp.MiroClient(store)
        check("board lookup", client.board(BOARD)["name"] == "Test board")

        # First push creates image + caption
        state = {"board_id": BOARD}
        png = b"\x89PNG\r\n\x1a\n" + secrets.token_bytes(2000)
        state, image = mp.push_view(client, state, "Perspective", png, 1920, 1080, "a.3dm · Perspective · now")
        img = M.items[image["id"]]
        check("push creates an image with position and width", img["data"]["position"]["x"] == 0 and img["data"]["geometry"]["width"] == mp.BOARD_WIDTH, img)
        cap = M.items[state["items"]["Perspective"]["caption"]]
        check("push creates a caption under the image", cap["type"] == "texts" and cap["data"]["position"]["y"] == 540 / 2 + 40, cap)

        # Second push replaces in place
        before = len(M.items)
        state, image2 = mp.push_view(client, state, "Perspective", png, 1920, 1080, "a.3dm · Perspective · later")
        check("re-push updates the same image", image2["id"] == image["id"] and M.items[image["id"]]["updates"] == 1 and len(M.items) == before)
        check("re-push keeps the image where it is (no position sent)", "position" not in M.items[image["id"]]["last"])
        check("re-push updates the caption", cap["last"]["data"]["content"].endswith("later"))

        # Another view goes next to it
        state, top = mp.push_view(client, state, "Top", png, 1000, 1000, "Top")
        check("second view is placed to the right", M.items[top["id"]]["data"]["position"]["x"] == mp.BOARD_WIDTH + 200)

        # Image deleted on the board -> recreated
        del M.items[image["id"]]
        state, image3 = mp.push_view(client, state, "Perspective", png, 1920, 1080, "again")
        check("deleted image is recreated", image3["id"] != image["id"] and state["items"]["Perspective"]["image"] == image3["id"])

        # Access token revoked server-side -> 401 -> refresh -> retry
        old_rt = store.tokens["refresh_token"]
        M.access.clear()
        client.board(BOARD)
        check("401 triggers refresh and retry", store.tokens["refresh_token"] != old_rt)
        status, _ = mp.post_json(base + "/refresh", {"refresh_token": old_rt})
        check("rotated-out refresh token is rejected as 401", status == 401)

        # Expired by clock -> proactive refresh
        rt = store.tokens["refresh_token"]
        store.tokens["expires_at"] = 0
        client.board(BOARD)
        check("expired token is refreshed before the call", store.tokens["refresh_token"] != rt)

        # Dead refresh token -> signed out
        M.access.clear()
        M.refresh.clear()
        try:
            client.board(BOARD)
            check("dead session raises NotSignedIn", False)
        except mp.NotSignedIn:
            check("dead session raises NotSignedIn and clears the keychain", store.tokens is None)

        # User clicks Deny on Miro's consent screen
        M.deny = True
        try:
            mp.sign_in(MemoryStore(), open_browser=browser, timeout=20)
            check("denied consent raises", False)
        except mp.MiroError as err:
            check("denied consent raises a clear error", "access_denied" in str(err), err)
        M.deny = False

        # Cancel while waiting
        try:
            mp.sign_in(MemoryStore(), open_browser=lambda url: None, pump=lambda: True, timeout=20)
        except mp.MiroError as err:
            check("Esc cancels sign-in", "cancelled" in str(err))

        # Board URL parsing
        for text, want in [("https://miro.com/app/board/uXjVTEST1234=/", BOARD),
                           ("https://miro.com/app/board/uXjVTEST1234%3D/?moveToWidget=1&cot=14", BOARD),
                           ("uXjVTEST1234=", BOARD), ("https://example.com/nope", None), ("", None)]:
            check("parse_board_id(%r)" % text[:40], mp.parse_board_id(text) == want, mp.parse_board_id(text))

        print("\n%d checks passed" % passed)
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
