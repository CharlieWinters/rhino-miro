# Rhino → Miro (MiroPush)

A Rhino 8 command that sends the active viewport to a Miro board as an image. Pushing the
same view again replaces that image in place, so it keeps its position, size and comments.
A small caption under each image shows file · view · time.

```
Rhino (rhino/MiroPush.py) ──REST──▶ api.miro.com            (images, texts)
        │
        └─ sign-in / refresh ─▶ rhino-miro.seanwinters.app  (worker/, Cloudflare)
                                   holds the Miro client secret, stores nothing
```

## Sign-in

Miro's token endpoint needs the client secret, and that can't ship inside a script. So the
Worker acts as a broker:

1. Rhino opens a listener on a random `127.0.0.1` port and opens the browser at
   `/login?port=…&state=…&code_challenge=…` (a PKCE challenge).
2. The Worker sends the browser to Miro's consent screen. Miro redirects back to `/callback`,
   where the Worker exchanges the code for tokens.
3. The Worker seals the tokens and the challenge into a 2-minute ticket (AES-GCM, `TOKEN_KEY`)
   and redirects the browser to Rhino's listener with that ticket.
4. Rhino posts the ticket and its PKCE verifier to `/redeem` and gets the tokens back. Only the
   process holding the verifier can open a ticket.
5. Tokens go in the OS keychain (`keyring`: macOS Keychain, Windows Credential Manager). When
   they expire (1 hour), Rhino calls `/refresh`. Miro rotates the pair each time and the new pair
   replaces the old one.

## One-time setup

1. **Miro app.** In Miro, open Profile → Settings → Your apps → Create new app, on a dev team.
   - Leave **Expire user authorization token** on. You can't change this after the app is created.
   - Redirect URI: `https://rhino-miro.seanwinters.app/callback`
   - Scopes: `boards:read`, `boards:write`
   - People on other teams can only sign in after you turn on **Distribute app** in the app
     settings. This is not a Marketplace listing.
2. **Worker config.** Put the app's client ID in `worker/wrangler.jsonc` → `MIRO_CLIENT_ID`. Then
   run this in your own terminal and paste the client secret at the prompt, not into chat:
   ```sh
   cd worker
   npx wrangler secret put MIRO_CLIENT_SECRET
   npm run deploy
   curl -s https://rhino-miro.seanwinters.app/health   # → {"ok":true,"configured":true}
   ```
   `TOKEN_KEY` is already set. If you rotate it, only sign-ins in progress at that moment fail.
3. **Rhino 8.**
   - Open `rhino/MiroPush.py` in the ScriptEditor and Run it once. The `# r: keyring, certifi`
     line installs those two packages.
   - Optionally add an alias in Options → Aliases: `MiroPush` → `_-ScriptEditor _Run "<path>/MiroPush.py"`

## Use

`MiroPush`, then:

- **Enter**: push the active view. The first time, it asks you to sign in and for a board URL.
- **Board**: switch to a different board, then push. Image IDs are kept per document, per view.
- **SignIn** / **SignOut**: SignOut removes the tokens from the keychain.

The board and item IDs are saved in the `.3dm` file (document strings, section `MiroPush`), so
re-opening the file and pushing again updates the same images.

## Tests

```sh
python3 -I test/e2e.py
```

This runs the real Worker under `wrangler dev` against a mock Miro (OAuth and REST) and covers:

- sign-in, ticket sealing and the PKCE check
- create, update in place, and re-create after the item is deleted
- refresh on 401 and on expiry, with token rotation
- denied consent and cancel
- board URL parsing

It needs no real accounts.

**Verified in Rhino 8 on macOS (2026-10-08)**, by driving the running Rhino with
`/Applications/Rhino 8.app/Contents/Resources/bin/rhinocode script <file>.py`:

- sign-in, and `keyring`/`certifi` inside Rhino's CPython
- `ViewCapture` + `System.Drawing` capture (the `-ViewCaptureToFile` fallback has never been needed)
- create, then re-push in place

**Miro API quirks found on the live API:**

- The multipart `data` part must have no filename, or Miro returns a 500 with "Failed to convert 'data'".
- Replacing an image's file resets it to its pixel size unless a `geometry.width` is sent with it.
- A JSON `PATCH` on an image silently ignores `geometry`.
- Cloudflare blocks Python's default `Python-urllib` user agent (403, error 1010), so the script sends its own.

## Before colleagues use it

Have #security_stream look at the Worker. It holds the Miro client secret as a Cloudflare
secret and relays refresh tokens.
