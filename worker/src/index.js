/**
 * rhino-miro auth broker: holds the Miro app's client secret so the Rhino script doesn't have to.
 *
 *   Rhino --opens browser--> /login --302--> Miro consent --302--> /callback
 *         (Worker swaps the code for tokens, seals them into a ticket bound to Rhino's PKCE challenge)
 *   /callback --302--> http://127.0.0.1:<port>/callback?ticket=...   (Rhino's loopback listener)
 *   Rhino --POST /redeem {ticket, code_verifier}--> tokens
 *   Rhino --POST /refresh {refresh_token}--> rotated token pair
 *
 * Stateless: the login flow and the ticket are sealed values (seal.js); nothing is stored.
 * Tokens only cross the browser encrypted, and only the process holding the PKCE verifier
 * can open them.
 */
import { seal, unseal, sha256B64url, safeEqual } from "./seal.js";

const FLOW_TTL_MS = 10 * 60 * 1000; // time allowed on Miro's consent screen
const TICKET_TTL_MS = 2 * 60 * 1000; // time for Rhino to redeem the ticket

function config(env, url) {
  return {
    baseUrl: (env.PUBLIC_BASE_URL || url.origin).replace(/\/$/, ""),
    clientId: env.MIRO_CLIENT_ID,
    clientSecret: env.MIRO_CLIENT_SECRET,
    tokenKey: env.TOKEN_KEY,
    authorizeUrl: env.MIRO_AUTHORIZE_URL || "https://miro.com/oauth/authorize",
    tokenUrl: env.MIRO_TOKEN_URL || "https://api.miro.com/v1/oauth/token",
  };
}

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

const page = (title, message, status = 200) =>
  new Response(
    `<!doctype html><meta charset="utf-8"><title>${title}</title>` +
      `<body style="font:16px system-ui;max-width:32em;margin:15vh auto;text-align:center">` +
      `<h1 style="font-size:22px">${title}</h1><p>${message}</p></body>`,
    { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } }
  );

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

/** POST to Miro's token endpoint. Miro documents these as query parameters. */
async function miroToken(cfg, params) {
  const qs = new URLSearchParams({ client_id: cfg.clientId, client_secret: cfg.clientSecret, ...params });
  const res = await fetch(`${cfg.tokenUrl}?${qs}`, { method: "POST", headers: { accept: "application/json" } });
  const body = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body };
}

/** Only the fields Rhino needs, plus an absolute expiry so the client doesn't have to track clocks. */
function tokenPair(body) {
  return {
    access_token: body.access_token,
    refresh_token: body.refresh_token ?? null,
    expires_at: body.expires_in ? Date.now() + body.expires_in * 1000 : null,
    team_id: body.team_id ?? null,
    user_id: body.user_id ?? null,
    scope: body.scope ?? null,
  };
}

const B64URL = /^[A-Za-z0-9_-]+$/;

async function login(url, cfg) {
  const port = parseInt(url.searchParams.get("port") || "", 10);
  const state = url.searchParams.get("state") || "";
  const challenge = url.searchParams.get("code_challenge") || "";
  if (!(port >= 1024 && port <= 65535)) return page("Bad request", "Missing or invalid loopback port.", 400);
  if (state.length < 16 || state.length > 128 || !B64URL.test(state)) return page("Bad request", "Missing or invalid state.", 400);
  if (challenge.length !== 43 || !B64URL.test(challenge)) return page("Bad request", "Missing or invalid PKCE code_challenge (S256).", 400);

  const flow = await seal(cfg.tokenKey, "flow", { port, state, challenge, exp: Date.now() + FLOW_TTL_MS });
  const authorize = new URL(cfg.authorizeUrl);
  authorize.search = new URLSearchParams({
    response_type: "code",
    client_id: cfg.clientId,
    redirect_uri: `${cfg.baseUrl}/callback`,
    state: flow,
  });
  return Response.redirect(authorize.toString(), 302);
}

async function callback(url, cfg) {
  const flow = await unseal(cfg.tokenKey, "flow", url.searchParams.get("state"));
  if (!flow) return page("Sign-in expired", "Start again from Rhino: run <b>MiroPush</b> and choose <b>SignIn</b>.", 400);

  const back = new URL(`http://127.0.0.1:${flow.port}/callback`);
  back.searchParams.set("state", flow.state);

  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  if (error || !code) {
    back.searchParams.set("error", error || "missing_code");
    return Response.redirect(back.toString(), 302);
  }

  const res = await miroToken(cfg, {
    grant_type: "authorization_code",
    code,
    redirect_uri: `${cfg.baseUrl}/callback`,
  });
  if (!res.ok || !res.body.access_token) {
    console.log(JSON.stringify({ event: "code_exchange_failed", status: res.status, error: res.body.error ?? res.body.message }));
    back.searchParams.set("error", "token_exchange_failed");
    return Response.redirect(back.toString(), 302);
  }

  const ticket = await seal(cfg.tokenKey, "ticket", {
    tokens: tokenPair(res.body),
    challenge: flow.challenge,
    exp: Date.now() + TICKET_TTL_MS,
  });
  back.searchParams.set("ticket", ticket);
  return Response.redirect(back.toString(), 302);
}

async function redeem(request, cfg) {
  const body = await readJson(request);
  if (!body || typeof body.ticket !== "string" || typeof body.code_verifier !== "string") {
    return json({ error: "invalid_request", error_description: "ticket and code_verifier are required" }, 400);
  }
  const ticket = await unseal(cfg.tokenKey, "ticket", body.ticket);
  if (!ticket) return json({ error: "invalid_grant", error_description: "ticket is invalid or expired" }, 400);
  if (!safeEqual(await sha256B64url(body.code_verifier), ticket.challenge)) {
    return json({ error: "invalid_grant", error_description: "code_verifier does not match" }, 400);
  }
  return json(ticket.tokens);
}

async function refresh(request, cfg) {
  const body = await readJson(request);
  if (!body || typeof body.refresh_token !== "string" || !body.refresh_token) {
    return json({ error: "invalid_request", error_description: "refresh_token is required" }, 400);
  }
  const res = await miroToken(cfg, { grant_type: "refresh_token", refresh_token: body.refresh_token });
  if (!res.ok || !res.body.access_token) {
    // 4xx from Miro means the refresh token is dead: Rhino should sign in again.
    const status = res.status >= 400 && res.status < 500 ? 401 : 502;
    return json({ error: "refresh_failed", miro_status: res.status, miro_error: res.body.error ?? res.body.message ?? null }, status);
  }
  return json(tokenPair(res.body));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cfg = config(env, url);
    const route = `${request.method} ${url.pathname}`;
    try {
      if (route === "GET /health") return json({ ok: true, configured: Boolean(cfg.clientId && cfg.clientSecret && cfg.tokenKey) });
      if (!cfg.clientId || !cfg.clientSecret || !cfg.tokenKey) return json({ error: "server_not_configured" }, 503);
      switch (route) {
        case "GET /":
          return page("Rhino → Miro", "Sign-in broker for the MiroPush command in Rhino. Nothing to do here.");
        case "GET /login":
          return await login(url, cfg);
        case "GET /callback":
          return await callback(url, cfg);
        case "POST /redeem":
          return await redeem(request, cfg);
        case "POST /refresh":
          return await refresh(request, cfg);
        default:
          return json({ error: "not_found" }, 404);
      }
    } catch (err) {
      console.log(JSON.stringify({ event: "unhandled", route, message: String(err?.message ?? err) }));
      return json({ error: "server_error" }, 500);
    }
  },
};
