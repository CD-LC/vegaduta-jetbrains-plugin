// Host-side probe for a VegaDuta platform the user is running on their own
// machine (compose lite, or a dev build) - the Kotlin twin of
// clients/shared/src/api/localPlatform.ts, same fingerprint and same
// never-throws contract.
//
// RULE 0 note: this is the one case where a loopback platform URL is
// legitimate - the user's own install, explicitly opted into (the "local"
// environment or the panel's Connect button). Nothing here ever becomes a
// default apiBase; it only confirms that a server is there so the UI can
// offer to connect.
//
// Fingerprint, not a guess: 200 + {"status":"UP"} on /api/system/status/live
// (core's permitAll liveness probe, SystemStatusController.live()) AND
// /api/agents answering the way a VegaDuta core answers an unauthenticated
// caller - 401/403 (secured) or 200 (a dev profile without the security
// filter). A stray app that happens to return the liveness shape but 404s
// /api/agents is not reported.

package ai.vegaduta.ide.api

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

object LocalPlatformProbe {

    /** How a locally running install authenticates:
     *  "keycloak" - the agentic-ai realm answers on authBase (lite/full local
     *    install): interactive sign-in is the device flow.
     *  "local"    - /api/auth/local/config answered mode:"local" (a personal
     *    install, app.auth.mode=local - accounts live in core, no Keycloak
     *    exists by design): sign-in is identifier + password on
     *    /api/auth/local/login.
     *  null       - neither answered (still booting, or an unusual install):
     *    the vmcp_ API-key path is the honest fallback. */
    enum class AuthMode { KEYCLOAK, LOCAL }

    /** What a probe established about a locally running platform. */
    data class Result(
        /** Origin of the answering VegaDuta core, no trailing slash. */
        val apiBase: String,
        /** Origin of its Keycloak, or null when the agentic-ai realm did not
         * answer - the device flow cannot start then. */
        val authBase: String?,
        /** Which sign-in this install accepts. Null = only the vmcp_
         * API-key path is guaranteed to work. */
        val authMode: AuthMode?,
    )

    /** Same budget as shared's PROBE_TIMEOUT_MS: loopback refuses instantly,
     * so this only bounds something that accepts the socket and stalls. */
    private const val PROBE_TIMEOUT_MS = 1200L

    private val http: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofMillis(PROBE_TIMEOUT_MS))
        .build()

    private fun get(url: String): HttpResponse<String>? =
        runCatching {
            http.send(
                HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofMillis(PROBE_TIMEOUT_MS))
                    .GET()
                    .build(),
                HttpResponse.BodyHandlers.ofString(),
            )
        }.getOrNull()

    private fun liveUp(apiBase: String): Boolean {
        val response = get("$apiBase/api/system/status/live") ?: return false
        if (response.statusCode() !in 200..299) return false
        return runCatching {
            WireJson.parseToJsonElement(response.body()).jsonObject["status"]
                ?.jsonPrimitive?.contentOrNull == "UP"
        }.getOrDefault(false)
    }

    private fun agentsEndpointExists(apiBase: String): Boolean {
        val status = get("$apiBase/api/agents")?.statusCode() ?: return false
        return status == 200 || status == 401 || status == 403
    }

    private fun realmAnswers(authBase: String): Boolean {
        val response = get("$authBase/realms/$KEYCLOAK_REALM") ?: return false
        if (response.statusCode() !in 200..299) return false
        return runCatching {
            WireJson.parseToJsonElement(response.body()).jsonObject["realm"]
                ?.jsonPrimitive?.contentOrNull == KEYCLOAK_REALM
        }.getOrDefault(false)
    }

    /** GET /api/auth/local/config is permitAll and reports {mode:"local"} on
     * a personal install (app.auth.mode=local): accounts and sessions are
     * held by core itself, so identifier + password sign-in on
     * /api/auth/local/login is the path - and there IS no Keycloak to wait
     * for. A keycloak-mode install answers anything else. */
    private fun localAuthAnswers(apiBase: String): Boolean {
        val response = get("$apiBase/api/auth/local/config") ?: return false
        if (response.statusCode() !in 200..299) return false
        return runCatching {
            WireJson.parseToJsonElement(response.body()).jsonObject["mode"]
                ?.jsonPrimitive?.contentOrNull == "local"
        }.getOrDefault(false)
    }

    /** Probes one candidate pair. Returns null when nothing VegaDuta-shaped
     * answers at [apiBase]; never throws. */
    fun probe(apiBase: String, authBase: String): Result? {
        val api = apiBase.trim().trimEnd('/')
        if (api.isEmpty() || !liveUp(api) || !agentsEndpointExists(api)) return null
        val auth = authBase.trim().trimEnd('/')
        if (auth.isNotEmpty() && realmAnswers(auth)) {
            return Result(apiBase = api, authBase = auth, authMode = AuthMode.KEYCLOAK)
        }
        // No Keycloak: a personal install (accounts in core) or nothing to
        // sign in with at all - the probe's authMode says which.
        val local = localAuthAnswers(api)
        return Result(apiBase = api, authBase = null, authMode = if (local) AuthMode.LOCAL else null)
    }

    // --- local-accounts sessions (personal installs) -------------------------

    private const val AUTH_TIMEOUT_MS = 10_000L

    /** One /api/auth/local session, as LocalAuthController.SessionResponse
     * returns it - camel-case fields, NOT the OIDC snake_case. */
    data class Session(
        val accessToken: String,
        /** null when the response carried none (a refresh keeps the old one). */
        val refreshToken: String?,
        /** Server-reported access-token lifetime, seconds. */
        val expiresIn: Long,
        /** firstName when set, else the account's email - display only. */
        val username: String?,
        val passwordChangeRequired: Boolean,
    )

    /** Typed outcome, never a throw: the refusals are LocalAuthException's
     * {error, message} shape and anything else is a transport/parse problem.
     * [status] is the HTTP status when one arrived - a refused refresh means
     * the session is gone (drop it); an unreachable server is transient. */
    sealed interface AuthResult {
        data class Ok(val session: Session) : AuthResult
        data class Failed(val message: String, val status: Int?) : AuthResult
    }

    /** Parses a SessionResponse body. Internal (not private) so unit tests in
     * the same module cover the wire shape without a live install. */
    internal fun parseSession(body: String): Session? = runCatching {
        val obj = WireJson.parseToJsonElement(body).jsonObject
        val access = obj["accessToken"]?.jsonPrimitive?.contentOrNull ?: return null
        val user = obj["user"]?.jsonObject
        val firstName = user?.get("firstName")?.jsonPrimitive?.contentOrNull?.trim()?.takeIf { it.isNotEmpty() }
        val email = user?.get("email")?.jsonPrimitive?.contentOrNull?.trim()?.takeIf { it.isNotEmpty() }
        Session(
            accessToken = access,
            refreshToken = obj["refreshToken"]?.jsonPrimitive?.contentOrNull,
            expiresIn = obj["expiresIn"]?.jsonPrimitive?.longOrNull ?: 60,
            username = firstName ?: email,
            passwordChangeRequired = obj["passwordChangeRequired"]?.jsonPrimitive?.contentOrNull == "true",
        )
    }.getOrNull()

    private fun post(apiBase: String, path: String, jsonBody: String): AuthResult {
        val response = try {
            http.send(
                HttpRequest.newBuilder(URI.create("$apiBase/api/auth/local$path"))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofMillis(AUTH_TIMEOUT_MS))
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build(),
                HttpResponse.BodyHandlers.ofString(),
            )
        } catch (e: Exception) {
            return AuthResult.Failed("Could not reach $apiBase.", null)
        }
        val obj = runCatching { WireJson.parseToJsonElement(response.body()).jsonObject }.getOrNull()
        if (response.statusCode() !in 200..299) {
            val message = obj?.get("message")?.jsonPrimitive?.contentOrNull
                ?: "Sign-in refused (${response.statusCode()})."
            return AuthResult.Failed(message, response.statusCode())
        }
        val session = obj?.let { parseSession(response.body()) }
        return session?.let { AuthResult.Ok(it) }
            ?: AuthResult.Failed("The server answered, but not with a session.", response.statusCode())
    }

    /** POST /api/auth/local/login - identifier + password on a personal
     * install. Same login the console's own sign-in page posts. */
    fun login(apiBase: String, identifier: String, password: String): AuthResult =
        post(
            apiBase,
            "/login",
            buildJsonObject {
                put("identifier", identifier)
                put("password", password)
            }.toString(),
        )

    /** POST /api/auth/local/refresh - mint a new access token from the stored
     * refresh token. A refused refresh means the session is gone, exactly
     * like a revoked OIDC refresh token. */
    fun refresh(apiBase: String, refreshToken: String): AuthResult =
        post(
            apiBase,
            "/refresh",
            buildJsonObject { put("refreshToken", refreshToken) }.toString(),
        )
}
