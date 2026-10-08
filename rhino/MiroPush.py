#! python3
# r: keyring, certifi
"""MiroPush: send the active Rhino viewport to a Miro board as an image.

Run it from Rhino 8 (ScriptEditor, or an alias, see README). First run signs you in to
Miro in the browser and asks for a board URL. Pushing the same view again replaces the
image already on the board, so it keeps its position, size and any comments.

Sign-in goes through the rhino-miro auth Worker, which holds the Miro app's client secret.
Tokens are kept in the OS keychain (macOS Keychain / Windows Credential Manager), never in
the .3dm file or on disk.
"""
import base64
import datetime
import hashlib
import http.server
import json
import os
import re
import secrets
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser

AUTH_BASE = os.environ.get("MIRO_RHINO_AUTH_URL", "https://rhino-miro.seanwinters.app").rstrip("/")
API_BASE = os.environ.get("MIRO_RHINO_API_URL", "https://api.miro.com").rstrip("/")
KEYRING_SERVICE = "rhino-miro"
KEYRING_ENTRY = "tokens"
DOC_SECTION = "MiroPush"
CAPTURE_WIDTH_PX = 1920
BOARD_WIDTH = 960  # board units for a newly created image
SIGN_IN_TIMEOUT_S = 300
# Cloudflare's browser check rejects the default "Python-urllib" agent (403, error 1010).
USER_AGENT = "MiroPush/0.1 (Rhino 8)"


class MiroError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class NotSignedIn(MiroError):
    pass


# ---------------------------------------------------------------- HTTP

def _ssl_context():
    # Rhino's bundled CPython may not see the system CA store; certifi is listed in `# r:`.
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


_SSL = None


def http_request(method, url, headers=None, body=None, timeout=60):
    """Returns (status, parsed JSON or None). Never raises for HTTP error statuses."""
    global _SSL
    if _SSL is None:
        _SSL = _ssl_context()
    req = urllib.request.Request(url, data=body, method=method, headers=dict(headers or {}, **{"user-agent": USER_AGENT}))
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL if url.startswith("https") else None) as res:
            status, raw = res.status, res.read()
    except urllib.error.HTTPError as err:
        status, raw = err.code, err.read()
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, {"message": raw[:300].decode("utf-8", "replace")}


def post_json(url, payload):
    return http_request("POST", url, {"content-type": "application/json", "accept": "application/json"},
                        json.dumps(payload).encode("utf-8"))


def multipart(fields):
    """fields: list of (name, filename, content_type, bytes). Returns (content_type, body)."""
    boundary = "----rhino-miro-" + uuid.uuid4().hex
    out = bytearray()
    for name, filename, ctype, data in fields:
        out += ("--%s\r\n" % boundary).encode()
        disp = 'form-data; name="%s"' % name
        if filename:
            disp += '; filename="%s"' % filename
        out += ("Content-Disposition: %s\r\nContent-Type: %s\r\n\r\n" % (disp, ctype)).encode()
        out += data + b"\r\n"
    out += ("--%s--\r\n" % boundary).encode()
    return "multipart/form-data; boundary=" + boundary, bytes(out)


# ---------------------------------------------------------------- tokens

class KeyringStore:
    """Token pair as one JSON blob in the OS keychain."""

    def load(self):
        import keyring
        raw = keyring.get_password(KEYRING_SERVICE, KEYRING_ENTRY)
        return json.loads(raw) if raw else None

    def save(self, tokens):
        import keyring
        keyring.set_password(KEYRING_SERVICE, KEYRING_ENTRY, json.dumps(tokens))

    def clear(self):
        import keyring
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_ENTRY)
        except keyring.errors.PasswordDeleteError:
            pass


def _pkce_pair():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


_DONE_PAGE = ("<!doctype html><meta charset='utf-8'><title>%s</title>"
              "<body style='font:16px system-ui;max-width:32em;margin:15vh auto;text-align:center'>"
              "<h1 style='font-size:22px'>%s</h1><p>%s</p></body>")


def sign_in(store, open_browser=webbrowser.open, pump=None, timeout=SIGN_IN_TIMEOUT_S):
    """Browser sign-in via the auth Worker. `pump()` is called while waiting; return True to cancel."""
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)
    result = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            q = dict(urllib.parse.parse_qsl(url.query))
            if url.path != "/callback" or q.get("state") != state:
                self.send_response(404)
                self.end_headers()
                return
            result.update(q)
            ok = "ticket" in q
            title = "Signed in to Miro" if ok else "Sign-in failed"
            msg = "You can close this tab and go back to Rhino." if ok else "Error: %s. Go back to Rhino and try again." % q.get("error", "unknown")
            body = (_DONE_PAGE % (title, title, msg)).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 0.25
    try:
        port = server.server_address[1]
        open_browser("%s/login?%s" % (AUTH_BASE, urllib.parse.urlencode(
            {"port": port, "state": state, "code_challenge": challenge})))
        deadline = time.time() + timeout
        while not result:
            server.handle_request()
            if pump and pump():
                raise MiroError("Sign-in cancelled.")
            if time.time() > deadline:
                raise MiroError("Sign-in timed out after %d s." % timeout)
    finally:
        server.server_close()

    if "ticket" not in result:
        raise MiroError("Miro sign-in failed: %s" % result.get("error", "unknown error"))
    status, tokens = post_json(AUTH_BASE + "/redeem", {"ticket": result["ticket"], "code_verifier": verifier})
    if status != 200 or not tokens or not tokens.get("access_token"):
        raise MiroError("Could not complete sign-in: %s" % (tokens or {}).get("error_description", status), status)
    store.save(tokens)
    return tokens


# ---------------------------------------------------------------- Miro REST

class MiroClient:
    def __init__(self, store):
        self.store = store

    def _tokens(self):
        tokens = self.store.load()
        if not tokens or not tokens.get("access_token"):
            raise NotSignedIn("Not signed in to Miro.")
        expires_at = tokens.get("expires_at")
        if expires_at is not None and time.time() * 1000 > expires_at - 60_000:
            tokens = self._refresh(tokens)
        return tokens

    def _refresh(self, tokens):
        if not tokens.get("refresh_token"):
            self.store.clear()
            raise NotSignedIn("Miro session expired, sign in again.")
        status, fresh = post_json(AUTH_BASE + "/refresh", {"refresh_token": tokens["refresh_token"]})
        if status == 401:
            self.store.clear()
            raise NotSignedIn("Miro session expired, sign in again.")
        if status != 200 or not fresh or not fresh.get("access_token"):
            raise MiroError("Token refresh failed (%s)." % status, status)
        # Miro rotates both tokens on refresh; the old refresh token is dead from here on.
        self.store.save(fresh)
        return fresh

    def request(self, method, path, payload=None, files=None):
        tokens = self._tokens()
        for attempt in (1, 2):
            headers = {"authorization": "Bearer " + tokens["access_token"], "accept": "application/json"}
            body = None
            if files is not None:
                headers["content-type"], body = multipart(files)
            elif payload is not None:
                headers["content-type"] = "application/json"
                body = json.dumps(payload).encode("utf-8")
            status, data = http_request(method, API_BASE + path, headers, body)
            if status == 401 and attempt == 1:
                tokens = self._refresh(tokens)
                continue
            if status >= 400:
                raise MiroError("Miro %s %s failed (%s): %s" % (method, path, status, _error_text(data)), status)
            return data

    def board(self, board_id):
        return self.request("GET", "/v2/boards/%s" % _q(board_id))

    def _image_files(self, png, data):
        # `data` must be typed application/json (else position is ignored) and must NOT have a
        # filename (else Miro reads it as a file and fails with a 500 "Failed to convert 'data'").
        return [("data", None, "application/json", json.dumps(data).encode("utf-8")),
                ("resource", "view.png", "image/png", png)]

    def create_image(self, board_id, png, data):
        return self.request("POST", "/v2/boards/%s/images" % _q(board_id), files=self._image_files(png, data))

    def get_image(self, board_id, item_id):
        return self.request("GET", "/v2/boards/%s/images/%s" % (_q(board_id), _q(item_id)))

    def update_image(self, board_id, item_id, png, data):
        return self.request("PATCH", "/v2/boards/%s/images/%s" % (_q(board_id), _q(item_id)), files=self._image_files(png, data))

    def create_text(self, board_id, content, x, y, width):
        return self.request("POST", "/v2/boards/%s/texts" % _q(board_id), payload={
            "data": {"content": content},
            "style": {"fontSize": "14", "color": "#555555"},
            "position": {"x": x, "y": y, "origin": "center"},
            "geometry": {"width": width},
        })

    def update_text(self, board_id, item_id, content):
        return self.request("PATCH", "/v2/boards/%s/texts/%s" % (_q(board_id), _q(item_id)),
                            payload={"data": {"content": content}})


def _error_text(data):
    data = data or {}
    return data.get("message") or data.get("detail") or data.get("title") or ""


def _q(s):
    return urllib.parse.quote(s, safe="")


def parse_board_id(text):
    """Accepts a board URL (https://miro.com/app/board/uXjV...=/) or a bare board ID."""
    text = (text or "").strip()
    m = re.search(r"/app/board/([^/?#]+)", text)
    board_id = urllib.parse.unquote(m.group(1) if m else text)
    return board_id if re.fullmatch(r"[A-Za-z0-9_=+\-]{6,}", board_id) else None


def push_view(client, state, view_name, png, width_px, height_px, caption):
    """Create or replace the image (and its caption) for one view. Mutates and returns `state`."""
    board_id = state["board_id"]
    items = state.setdefault("items", {})
    entry = items.get(view_name) or {}
    data = {"title": caption}

    image = None
    if entry.get("image"):
        try:
            # Replacing the file resets the image to its pixel size, so keep the width it has now.
            width = (client.get_image(board_id, entry["image"]).get("geometry") or {}).get("width")
            image = client.update_image(board_id, entry["image"], png, dict(data, geometry={"width": width}) if width else data)
        except MiroError as err:
            if err.status != 404:  # deleted on the board: fall through and create a new one
                raise
            entry = {}
    if image is None:
        x = state.get("next_x", 0)
        height = BOARD_WIDTH * height_px / float(width_px)
        image = client.create_image(board_id, png, dict(data, position={"x": x, "y": 0, "origin": "center"},
                                                        geometry={"width": BOARD_WIDTH}))
        entry = {"image": image["id"]}
        state["next_x"] = x + BOARD_WIDTH + 200
        text = client.create_text(board_id, caption, x, height / 2 + 40, BOARD_WIDTH)
        entry["caption"] = text["id"]
    elif entry.get("caption"):
        try:
            client.update_text(board_id, entry["caption"], caption)
        except MiroError as err:
            if err.status != 404:
                raise
            entry.pop("caption")
    items[view_name] = entry
    return state, image


def item_link(board_id, item_id):
    return "https://miro.com/app/board/%s/?moveToWidget=%s" % (_q(board_id), item_id)


# ---------------------------------------------------------------- Rhino

def _doc_state(doc):
    raw = doc.Strings.GetValue(DOC_SECTION, "state")
    return json.loads(raw) if raw else {}


def _save_doc_state(doc, state):
    doc.Strings.SetString(DOC_SECTION, "state", json.dumps(state))


def _capture_png(view, width_px):
    import Rhino
    size = view.ActiveViewport.Size
    height_px = max(1, int(round(width_px * size.Height / float(max(1, size.Width)))))
    path = os.path.join(tempfile.gettempdir(), "miropush-%s.png" % uuid.uuid4().hex)
    try:
        try:
            import System
            vc = Rhino.Display.ViewCapture()
            vc.Width, vc.Height = width_px, height_px
            vc.ScaleScreenItems = False
            vc.DrawAxes = False
            vc.DrawGrid = False
            vc.DrawGridAxes = False
            vc.TransparentBackground = False
            bitmap = vc.CaptureToBitmap(view)
            if bitmap is None:
                raise RuntimeError("CaptureToBitmap returned nothing")
            bitmap.Save(path, System.Drawing.Imaging.ImageFormat.Png)
        except Exception as err:
            # System.Drawing is unreliable on macOS: fall back to the built-in command.
            Rhino.RhinoApp.WriteLine("MiroPush: ViewCapture failed (%s), using ViewCaptureToFile." % err)
            Rhino.RhinoApp.RunScript('_-ViewCaptureToFile _Width=%d _Height=%d _DrawGrid=_No _DrawWorldAxes=_No '
                                     '_DrawCPlaneAxes=_No _TransparentBackground=_No "%s" _Enter'
                                     % (width_px, height_px, path), False)
        if not os.path.exists(path):
            raise MiroError("Could not capture the viewport.")
        with open(path, "rb") as f:
            return f.read(), width_px, height_px
    finally:
        if os.path.exists(path):
            os.remove(path)


def _ask_board(default=""):
    import Rhino
    gs = Rhino.Input.Custom.GetString()
    gs.SetCommandPrompt("Miro board URL or ID")
    if default:
        gs.SetDefaultString(default)
    if gs.Get() != Rhino.Input.GetResult.String:
        return None
    board_id = parse_board_id(gs.StringResult())
    if not board_id:
        Rhino.RhinoApp.WriteLine("MiroPush: that doesn't look like a Miro board URL.")
    return board_id


def _ask_action():
    import Rhino
    go = Rhino.Input.Custom.GetOption()
    go.SetCommandPrompt("Press Enter to push the active view to Miro")
    go.AcceptNothing(True)
    names = ["Board", "SignIn", "SignOut"]  # Board = pick another board, then push
    indices = {go.AddOption(n): n for n in names}
    res = go.Get()
    if res == Rhino.Input.GetResult.Nothing:
        return "Push"
    if res == Rhino.Input.GetResult.Option:
        return indices.get(go.OptionIndex())
    return None


def main():
    import Rhino
    import scriptcontext as sc

    def say(msg):
        Rhino.RhinoApp.WriteLine("MiroPush: " + msg)

    def pump():
        Rhino.RhinoApp.Wait()
        return sc.escape_test(False)

    doc = sc.doc
    store = KeyringStore()
    client = MiroClient(store)

    action = _ask_action()
    if action is None:
        return
    if action == "SignOut":
        store.clear()
        say("signed out (tokens removed from the keychain).")
        return
    try:
        if action == "SignIn" or not store.load():
            say("opening the browser to sign in to Miro (Esc to cancel)...")
            sign_in(store, pump=pump)
            say("signed in.")
            if action == "SignIn":
                return

        state = _doc_state(doc)
        if action == "Board" or not state.get("board_id"):
            board_id = _ask_board(state.get("board_id", ""))
            if not board_id:
                return
            board = client.board(board_id)
            if board_id != state.get("board_id"):
                state = {"board_id": board_id}  # item IDs belong to the old board
            say("board: '%s'." % board.get("name", board_id))
            _save_doc_state(doc, state)

        view = doc.Views.ActiveView
        view_name = view.ActiveViewport.Name
        png, w, h = _capture_png(view, CAPTURE_WIDTH_PX)
        file_name = doc.Name or "Untitled"
        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        caption = "%s · %s · %s" % (file_name, view_name, stamp)
        say("uploading %s (%d×%d)..." % (view_name, w, h))
        state, image = push_view(client, state, view_name, png, w, h, caption)
        _save_doc_state(doc, state)
        say("done: %s" % item_link(state["board_id"], image["id"]))
    except NotSignedIn as err:
        say("%s Run MiroPush and choose SignIn." % err)
    except MiroError as err:
        say(str(err))


if __name__ == "__main__":
    main()
