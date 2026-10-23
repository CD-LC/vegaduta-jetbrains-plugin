// The local-platform probe decides whether the "Connect" affordance even
// exists, so the two failure modes that matter are covered: reporting a server
// that is not VegaDuta (a stray app on the port) and crashing a caller because
// nothing is running. No port is ever opened by this file.

import { describe, expect, it, vi } from "vitest";
import {
  LOCAL_PLATFORM_DEFAULTS,
  discoverLocalPlatform,
  localAuthLogin,
  localAuthRefresh,
  probeLocalPlatform,
} from "../src/api/localPlatform";

const API = "http://127.0.0.1:8080";
const AUTH = "http://127.0.0.1:8180";

function liveUpResponse(): Response {
  return new Response(JSON.stringify({ status: "UP" }), { status: 200 });
}

function realmResponse(): Response {
  return new Response(JSON.stringify({ realm: "agentic-ai" }), { status: 200 });
}

/** Fake fetch driven by exact-path handlers; an unlisted URL rejects like a
 * closed port, exactly as undici does. */
function fakeFetch(handlers: Record<string, () => Response | Promise<Response>>) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const handler = handlers[String(input)];
    if (!handler) throw new TypeError("fetch failed: ECONNREFUSED");
    return handler();
  }) as unknown as typeof fetch;
}

/** A full local install answering: liveness + the /api/agents fingerprint +
 * the agentic-ai realm. */
function fullInstall(agentsStatus = 401) {
  return fakeFetch({
    [`${API}/api/system/status/live`]: liveUpResponse,
    [`${API}/api/agents`]: () => new Response("unauthorized", { status: agentsStatus }),
    [`${AUTH}/realms/agentic-ai`]: realmResponse,
  });
}

describe("probeLocalPlatform", () => {
  it("reports api and auth base for a full local install", async () => {
    const found = await probeLocalPlatform(API, AUTH, { fetchImpl: fullInstall() });
    expect(found).toEqual({ apiBase: API, authBase: AUTH, authMode: "keycloak" });
  });

  it("reports authMode local for a personal install - no Keycloak by design", async () => {
    // personal.yml runs core alone with app.auth.mode=local: accounts live
    // in core, /api/auth/local/config answers mode:"local", and there is no
    // Keycloak to wait for. The caller's sign-in is identifier + password.
    const fetchImpl = fakeFetch({
      [`${API}/api/system/status/live`]: liveUpResponse,
      [`${API}/api/agents`]: () => new Response("unauthorized", { status: 401 }),
      [`${API}/api/auth/local/config`]: () =>
        new Response(JSON.stringify({ mode: "local", setupRequired: false, credentialTypes: ["password"] }), { status: 200 }),
    });

    await expect(probeLocalPlatform(API, AUTH, { fetchImpl })).resolves.toEqual({
      apiBase: API,
      authBase: null,
      authMode: "local",
    });
  });

  it("reports authBase+authMode null when neither auth path answers", async () => {
    // A lite install still booting its Keycloak: still a found server, just
    // one where the only guaranteed sign-in is a vmcp_ API key.
    const fetchImpl = fakeFetch({
      [`${API}/api/system/status/live`]: liveUpResponse,
      [`${API}/api/agents`]: () => new Response("unauthorized", { status: 401 }),
    });

    await expect(probeLocalPlatform(API, AUTH, { fetchImpl })).resolves.toEqual({
      apiBase: API,
      authBase: null,
      authMode: null,
    });
  });

  it("accepts the 200 fingerprint too, for a dev profile without the security filter", async () => {
    const found = await probeLocalPlatform(API, AUTH, { fetchImpl: fullInstall(200) });
    expect(found).toEqual({ apiBase: API, authBase: AUTH, authMode: "keycloak" });
  });

  it("refuses a stray app that returns {\"status\":\"UP\"} but 404s /api/agents", async () => {
    const fetchImpl = fakeFetch({
      [`${API}/api/system/status/live`]: liveUpResponse,
      [`${API}/api/agents`]: () => new Response("not found", { status: 404 }),
    });

    await expect(probeLocalPlatform(API, AUTH, { fetchImpl })).resolves.toBeNull();
  });

  it("refuses when liveness does not say UP, even if /api/agents would answer", async () => {
    const fetchImpl = fakeFetch({
      [`${API}/api/system/status/live`]: () => new Response(JSON.stringify({ status: "DOWN" }), { status: 503 }),
      [`${API}/api/agents`]: () => new Response("unauthorized", { status: 401 }),
    });

    await expect(probeLocalPlatform(API, AUTH, { fetchImpl })).resolves.toBeNull();
  });

  it("returns null when nothing is running, and never lets a thrown fetch escape", async () => {
    const fetchImpl = fakeFetch({});
    await expect(probeLocalPlatform(API, AUTH, { fetchImpl })).resolves.toBeNull();
    await expect(probeLocalPlatform("", AUTH, { fetchImpl })).resolves.toBeNull();
  });

  it("tolerates a trailing slash on both bases", async () => {
    const found = await probeLocalPlatform(`${API}/`, `${AUTH}/`, { fetchImpl: fullInstall() });
    expect(found).toEqual({ apiBase: API, authBase: AUTH, authMode: "keycloak" });
  });

  it("does not count a realm-shaped reply from a different realm as sign-in ready", async () => {
    const fetchImpl = fakeFetch({
      [`${API}/api/system/status/live`]: liveUpResponse,
      [`${API}/api/agents`]: () => new Response("unauthorized", { status: 401 }),
      [`${AUTH}/realms/agentic-ai`]: () =>
        new Response(JSON.stringify({ realm: "master" }), { status: 200 }),
    });

    await expect(probeLocalPlatform(API, AUTH, { fetchImpl })).resolves.toEqual({
      apiBase: API,
      authBase: null,
      authMode: null,
    });
  });
});

describe("local accounts (personal install)", () => {
  const sessionBody = {
    accessToken: "acc-token",
    tokenType: "Bearer",
    expiresIn: 3600,
    refreshToken: "ref-token",
    refreshExpiresIn: 2592000,
    passwordChangeRequired: false,
    user: { id: "u1", email: "me@local", firstName: "Me", lastName: "", tenantId: "t", roles: [] },
  };

  it("logs in with identifier + password and parses the session", async () => {
    const seen: string[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      seen.push(`${init?.method} ${input} ${init?.body}`);
      return new Response(JSON.stringify(sessionBody), { status: 200 });
    }) as unknown as typeof fetch;

    const result = await localAuthLogin(API, "me@local", "s3cret", { fetchImpl });

    expect(result).toEqual({
      ok: true,
      session: {
        accessToken: "acc-token",
        refreshToken: "ref-token",
        expiresIn: 3600,
        refreshExpiresIn: 2592000,
        passwordChangeRequired: false,
        username: "Me",
      },
    });
    expect(seen[0]).toContain(`POST ${API}/api/auth/local/login`);
    expect(seen[0]).toContain('"identifier":"me@local"');
  });

  it("surfaces the server's own refusal message, never a throw", async () => {
    const fetchImpl = fakeFetch({
      [`${API}/api/auth/local/login`]: () =>
        new Response(JSON.stringify({ error: "bad_credentials", message: "Wrong email or password." }), { status: 401 }),
    });

    await expect(localAuthLogin(API, "me@local", "wrong", { fetchImpl })).resolves.toEqual({
      ok: false,
      message: "Wrong email or password.",
      status: 401,
    });
  });

  it("answers with a plain failure when the server is unreachable or the body is odd", async () => {
    await expect(localAuthLogin(API, "a", "b", { fetchImpl: fakeFetch({}) })).resolves.toMatchObject({
      ok: false,
    });
    const weird = fakeFetch({
      [`${API}/api/auth/local/login`]: () => new Response("<html>", { status: 200 }),
    });
    await expect(localAuthLogin(API, "a", "b", { fetchImpl: weird })).resolves.toMatchObject({ ok: false });
  });

  it("refreshes a session and tolerates a missing refresh token", async () => {
    const fetchImpl = fakeFetch({
      [`${API}/api/auth/local/refresh`]: () =>
        new Response(JSON.stringify({ ...sessionBody, refreshToken: undefined }), { status: 200 }),
    });

    const result = await localAuthRefresh(API, "ref-token", { fetchImpl });
    expect(result).toMatchObject({ ok: true });
    if (result.ok) {
      expect(result.session.accessToken).toBe("acc-token");
      expect(result.session.refreshToken).toBeNull();
    }
  });

  it("falls back to the email for the display name", async () => {
    const fetchImpl = fakeFetch({
      [`${API}/api/auth/local/login`]: () =>
        new Response(JSON.stringify({ ...sessionBody, user: { ...sessionBody.user, firstName: " " } }), { status: 200 }),
    });
    const result = await localAuthLogin(API, "me@local", "s3cret", { fetchImpl });
    if (result.ok) expect(result.session.username).toBe("me@local");
  });
});

describe("discoverLocalPlatform", () => {
  it("prefers the earlier candidate when several answer", async () => {
    const second = "http://127.0.0.1:18080";
    const secondAuth = "http://127.0.0.1:18180";
    const fetchImpl = fakeFetch({
      [`${API}/api/system/status/live`]: liveUpResponse,
      [`${API}/api/agents`]: () => new Response("unauthorized", { status: 401 }),
      [`${AUTH}/realms/agentic-ai`]: realmResponse,
      [`${second}/api/system/status/live`]: liveUpResponse,
      [`${second}/api/agents`]: () => new Response("unauthorized", { status: 401 }),
      [`${secondAuth}/realms/agentic-ai`]: realmResponse,
    });

    const found = await discoverLocalPlatform([API, second], (api) =>
      api === second ? secondAuth : AUTH,
      { fetchImpl }
    );
    expect(found).toEqual({ apiBase: API, authBase: AUTH, authMode: "keycloak" });
  });

  it("returns null when no candidate answers", async () => {
    await expect(
      discoverLocalPlatform([API], () => AUTH, { fetchImpl: fakeFetch({}) })
    ).resolves.toBeNull();
  });
});

describe("LOCAL_PLATFORM_DEFAULTS", () => {
  it("are the compose defaults, not a cloud deployment", () => {
    expect(LOCAL_PLATFORM_DEFAULTS.apiBase).toBe("http://127.0.0.1:8080");
    expect(LOCAL_PLATFORM_DEFAULTS.authBase).toBe("http://127.0.0.1:8180");
  });
});
