// Local platform detection: find a VegaDuta server the user is running on
// their own machine (deploy/compose lite.yml, a dev `mvn spring-boot:run`,
// or the installed stack) instead of asking them to type api/auth URLs they
// may not know.
//
// RULE 0 NOTE (same carve-out as agent/discovery.ts, edge/ollamaEngine.ts and
// the local inference server setting in every host): the 127.0.0.1 defaults
// below are the USER'S OWN install on their own machine, not a cloud
// browser-facing platform URL or a cloud token issuer. A local install's
// Keycloak only ever issues tokens to that same machine's owner. The probe
// still never DEFAULTS the platform URL - it only ever confirms a server is
// there and offers the user a "Connect" they can ignore; the configured
// environment stays the authority until the user picks local.
//
// Fingerprint, not a guess: an HTTP 200 on /api/system/status/live alone is
// not enough (any Spring app could answer that shape), so detection also
// requires /api/agents to answer the way a VegaDuta core does to an
// unauthenticated caller - 401/403 (secured) or 200 (a dev profile without
// the security filter). A random server that happens to return {"status":
// "UP"} for one path but 404s /api/agents is not reported.
//
// Typed-failure contract, as everywhere else in this folder: nothing here
// throws. A failed probe is an absent result, not an exception.

/** Same budget as agent/discovery.ts: loopback refuses instantly, so the
 * timeout only matters for something that accepts the connection and stalls. */
const PROBE_TIMEOUT_MS = 1_200;

/** A login or refresh is a real request the user is waiting on, not a
 * background probe - it gets a real timeout, not the probe budget. */
const AUTH_TIMEOUT_MS = 10_000;

/** The compose default ports (deploy/compose: CORE_HOST_PORT and
 * KEYCLOAK_HOST_PORT on BIND_ADDR 127.0.0.1). Hosts expose these as settings
 * so a non-default install stays reachable. */
export const LOCAL_PLATFORM_DEFAULTS = {
  apiBase: "http://127.0.0.1:8080",
  authBase: "http://127.0.0.1:8180",
} as const;

/** The realm every VegaDuta Keycloak ships (deploy/keycloak/agentic-ai-realm.json). */
const KEYCLOAK_REALM = "agentic-ai";

/** The permitAll local-accounts surface a personal install exposes
 * (LocalAuthSecurityConfig.BASE_PATH / LocalAuthController). */
const LOCAL_AUTH_PATH = "/api/auth/local";

/** How a locally running install authenticates, decided by the probe:
 *  - "keycloak": the agentic-ai realm answers on authBase (a lite/full local
 *    install) - interactive sign-in is the device flow.
 *  - "local": /api/auth/local/config answered mode:"local" (a personal
 *    install, app.auth.mode=local - accounts live in core, no Keycloak
 *    exists by design) - sign-in is identifier + password on /api/auth/local.
 *  - null: neither answered (still booting, or an unusual install) - the
 *    vmcp_ API-key path is the honest fallback. */
export type LocalAuthMode = "keycloak" | "local";

/** What a probe established about a locally running platform. */
export interface LocalServerInfo {
  /** Origin of the answering VegaDuta core, no trailing slash. */
  apiBase: string;
  /** Origin of its Keycloak, or null when the realm did not answer - the
   * device flow cannot start then. */
  authBase: string | null;
  /** Which sign-in this install accepts. Null = only the vmcp_ API-key path
   * is guaranteed to work. */
  authMode: LocalAuthMode | null;
}

interface ProbeOptions {
  fetchImpl?: typeof fetch;
  signal?: AbortSignal;
  timeoutMs?: number;
}

/** One bounded GET that resolves to the Response or null on any failure.
 * Never rejects. */
async function get(url: string, options: ProbeOptions): Promise<Response | null> {
  const doFetch = options.fetchImpl ?? globalThis.fetch;
  if (typeof doFetch !== "function") return null;
  if (options.signal?.aborted) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? PROBE_TIMEOUT_MS);
  const onAbort = (): void => controller.abort();
  options.signal?.addEventListener("abort", onAbort);
  try {
    return await doFetch(url, { signal: controller.signal });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", onAbort);
  }
}

/** {status:"UP"} from GET /api/system/status/live - core's permitAll liveness
 * probe (SystemStatusController.live(), written so logged-out callers do not
 * have to 401 just to learn "the process is up"). */
async function liveUp(apiBase: string, options: ProbeOptions): Promise<boolean> {
  const response = await get(`${apiBase}/api/system/status/live`, options);
  if (!response || !response.ok) return false;
  try {
    const body = (await response.json()) as { status?: unknown };
    return body?.status === "UP";
  } catch {
    return false;
  }
}

/** The second half of the fingerprint: /api/agents answers like a VegaDuta
 * core, not like an unrelated app that happened to return {"status":"UP"}.
 * Secured cores answer 401/403; a dev profile without the security filter
 * answers 200 with the agent list. Both count - anything else does not. */
async function agentsEndpointExists(apiBase: string, options: ProbeOptions): Promise<boolean> {
  const response = await get(`${apiBase}/api/agents`, options);
  if (!response) return false;
  return response.status === 200 || response.status === 401 || response.status === 403;
}

/** The Keycloak realm every install ships is public metadata
 * (GET /realms/agentic-ai returns the realm JSON). Answering with
 * realm === "agentic-ai" means interactive device-flow sign-in can run. */
async function realmAnswers(authBase: string, options: ProbeOptions): Promise<boolean> {
  const response = await get(`${authBase}/realms/${KEYCLOAK_REALM}`, options);
  if (!response || !response.ok) return false;
  try {
    const body = (await response.json()) as { realm?: unknown };
    return body?.realm === KEYCLOAK_REALM;
  } catch {
    return false;
  }
}

/** GET /api/auth/local/config is permitAll and reports {mode:"local"} on a
 * personal install (app.auth.mode=local): accounts and sessions are held by
 * core itself, so identifier + password sign-in on /api/auth/local/login is
 * the path - and there IS no Keycloak to wait for. A keycloak-mode install
 * answers anything else (404, a different mode). */
async function localAuthAnswers(apiBase: string, options: ProbeOptions): Promise<boolean> {
  const response = await get(`${apiBase}${LOCAL_AUTH_PATH}/config`, options);
  if (!response || !response.ok) return false;
  try {
    const body = (await response.json()) as { mode?: unknown };
    return body?.mode === "local";
  } catch {
    return false;
  }
}

/**
 * Probes one candidate api base (and the auth base that belongs to it) and
 * reports what was found, or null when nothing VegaDuta-shaped answers.
 * Never throws; ~2 probe budgets worst case on loopback.
 *
 * `authBase` is still probed when given: a local core without a reachable
 * Keycloak is reported with authBase: null so the caller can offer the API-key
 * path rather than a sign-in that cannot start.
 */
export async function probeLocalPlatform(
  apiBase: string,
  authBase: string,
  options: ProbeOptions = {}
): Promise<LocalServerInfo | null> {
  // A caller whose settings predate the local base settings passes undefined
  // here; that is "nothing configured", not a crash.
  const origin = (apiBase ?? "").trim().replace(/\/+$/, "");
  if (origin === "") return null;
  if (!(await liveUp(origin, options))) return null;
  if (!(await agentsEndpointExists(origin, options))) return null;
  const auth = (authBase ?? "").trim().replace(/\/+$/, "");
  const realmUp = auth !== "" && (await realmAnswers(auth, options));
  if (realmUp) {
    return { apiBase: origin, authBase: auth, authMode: "keycloak" };
  }
  // No Keycloak: a personal install (accounts in core) or nothing to sign
  // in with at all - the probe's authMode says which.
  const local = await localAuthAnswers(origin, options);
  return { apiBase: origin, authBase: null, authMode: local ? "local" : null };
}

/**
 * Probes candidate api bases in order and returns the first that answers,
 * or null. Deterministic like discoverLocalEndpoint: list order, not race
 * order. `authBase` is resolved per candidate by `authBaseFor` (or taken as
 * the same value for every candidate when a single string is passed).
 */
export async function discoverLocalPlatform(
  candidates: readonly string[],
  authBaseFor: (apiBase: string) => string,
  options: ProbeOptions = {}
): Promise<LocalServerInfo | null> {
  for (const candidate of candidates) {
    const found = await probeLocalPlatform(candidate, authBaseFor(candidate), options);
    if (found) return found;
  }
  return null;
}

// --- local-accounts sessions (personal installs) -----------------------------

/** One /api/auth/local session, as LocalAuthController.SessionResponse/view()
 * returns it. Camel-case field names, NOT the OIDC snake_case. */
export interface LocalAuthSession {
  accessToken: string;
  /** null when the response carried none (a refresh keeps the old one). */
  refreshToken: string | null;
  /** Seconds until the access token expires, as the server reported. */
  expiresIn: number;
  refreshExpiresIn: number | null;
  passwordChangeRequired: boolean;
  /** firstName when set, else the account's email - display only. */
  username: string | null;
}

/** Typed outcome, never a throw: the refusals are LocalAuthException's
 * {error, message} shape and anything else is a transport/parse problem.
 * `status` is the HTTP status when one arrived - a refused REFRESH means the
 * session is gone (drop it), while an unreachable server or a timeout is
 * transient (keep it, retry later). */
export type LocalAuthResult =
  | { ok: true; session: LocalAuthSession }
  | { ok: false; message: string; status?: number };

function parseSession(body: unknown): LocalAuthSession | null {
  if (typeof body !== "object" || body === null) return null;
  const o = body as Record<string, unknown>;
  const accessToken = typeof o.accessToken === "string" ? o.accessToken : null;
  if (!accessToken) return null;
  const user = (o.user ?? {}) as Record<string, unknown>;
  const firstName = typeof user.firstName === "string" && user.firstName.trim() !== "" ? user.firstName : null;
  const email = typeof user.email === "string" && user.email.trim() !== "" ? user.email : null;
  return {
    accessToken,
    refreshToken: typeof o.refreshToken === "string" ? o.refreshToken : null,
    expiresIn: typeof o.expiresIn === "number" ? o.expiresIn : 60,
    refreshExpiresIn: typeof o.refreshExpiresIn === "number" ? o.refreshExpiresIn : null,
    passwordChangeRequired: o.passwordChangeRequired === true,
    username: firstName ?? email,
  };
}

/** The server's own refusal message when it has one ({error, message}),
 * else a plain fallback. Never throws. */
function refusalMessage(body: unknown, fallback: string): string {
  const message = (body as Record<string, unknown> | null)?.message;
  return typeof message === "string" && message !== "" ? message : fallback;
}

async function postLocalAuth(
  apiBase: string,
  path: string,
  payload: Record<string, string>,
  options: ProbeOptions
): Promise<LocalAuthResult> {
  const doFetch = options.fetchImpl ?? globalThis.fetch;
  if (typeof doFetch !== "function") return { ok: false, message: "No fetch available." };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? AUTH_TIMEOUT_MS);
  const onAbort = (): void => controller.abort();
  options.signal?.addEventListener("abort", onAbort);
  let response: Response;
  try {
    response = await doFetch(`${apiBase}${LOCAL_AUTH_PATH}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
  } catch {
    return { ok: false, message: `Could not reach ${apiBase}.` };
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", onAbort);
  }
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    /* a refusal with no body falls back below */
  }
  if (!response.ok) {
    return { ok: false, message: refusalMessage(body, `Sign-in refused (${response.status}).`), status: response.status };
  }
  const session = parseSession(body);
  return session ? { ok: true, session } : { ok: false, message: "The server answered, but not with a session." };
}

/** POST /api/auth/local/login - identifier + password on a personal install.
 * Same login the console's own sign-in page posts. */
export async function localAuthLogin(
  apiBase: string,
  identifier: string,
  password: string,
  options: ProbeOptions = {}
): Promise<LocalAuthResult> {
  return postLocalAuth(apiBase, "/login", { identifier, password }, options);
}

/** POST /api/auth/local/refresh - mint a new access token from the stored
 * refresh token. A failed refresh means the session is gone, exactly like a
 * revoked OIDC refresh token. */
export async function localAuthRefresh(
  apiBase: string,
  refreshToken: string,
  options: ProbeOptions = {}
): Promise<LocalAuthResult> {
  return postLocalAuth(apiBase, "/refresh", { refreshToken }, options);
}
