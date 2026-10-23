// Persisted plugin settings. RULE 0 (CLAUDE.md): never localhost defaults -
// the two real deployments are staging (.xyz) and production (.ai); `custom`
// exists for self-hosted installs and is entered explicitly by the user.
// Mirrors ENVIRONMENTS in clients/shared/src/api/types.ts.
//
// Two addresses here MAY be loopback URLs, both the user's own machine rather
// than a cloud endpoint: the local inference server (Ollama / LM Studio /
// llama.cpp, clients/shared/src/edge/ollamaEngine.ts documents the carve-out)
// and the "local" environment - a VegaDuta install the user runs themselves
// (compose lite or a dev build), explicitly selected, never defaulted.
// The local inference server still has no default: blank means it is off.

package ai.vegaduta.ide.settings

import ai.vegaduta.ide.agent.DEFAULT_MAX_STEPS
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.components.service

@Service(Service.Level.APP)
@State(name = "VegadutaSettings", storages = [Storage("vegaduta-ide.xml")])
class VegadutaSettingsState : PersistentStateComponent<VegadutaSettingsState.State> {

    class State {
        var environment: String = ENV_PRODUCTION
        var customApiBase: String = ""
        var customAuthBase: String = ""
        // The "local" environment - a VegaDuta install on this machine.
        // Blank = the compose defaults (core :8080, Keycloak :8180); a
        // non-default install types its own. Explicitly opted into by picking
        // "local" in the environment combo or the panel's Connect button.
        var localApiBase: String = ""
        var localAuthBase: String = ""
        // Local inference (the user's own OpenAI-compatible server: Ollama,
        // LM Studio, llama.cpp). Blank base URL = the whole local path is off,
        // which is the default: nothing is probed until the user types a URL.
        // Mirrors VS Code's vegaduta.ollama.baseUrl / vegaduta.ollama.model.
        var localServerBaseUrl: String = ""
        var localServerModel: String = ""
        var localCompletionsEnabled: Boolean = false
        // Coding agent. Mirrors the vegaduta.agent.* settings in
        // clients/vscode/package.json, defaults included. Blank base URL means
        // "probe the well-known local ports" (LOCAL_ENDPOINTS), not "call the
        // platform" - an agent run never touches VegaDuta.
        //
        // The provider API KEY is deliberately absent from this class: settings
        // sync between machines and show up in screen shares. It lives in
        // PasswordSafe (TokenStore.agentApiKey()).
        var agentBaseUrl: String = ""
        var agentModel: String = ""
        var agentMaxSteps: Int = DEFAULT_MAX_STEPS
        var agentAutoApproveEdits: Boolean = false
        var agentAutoApproveCommands: Boolean = false
        // Private Mode (ai.vegaduta.ide.privacy). Persisted so it survives an
        // IDE restart: a user who turned it on must not find it silently off.
        var privateMode: Boolean = false
        // Bundled on-device runtime (ai.vegaduta.ide.runtime). The model the
        // person last started - blank = do not start anything when the IDE
        // opens - and the loopback address the runtime last wrote into
        // localServerBaseUrl, so it can tell its own address from one the user
        // typed and never overwrite theirs.
        var bundledRuntimeModel: String = ""
        var bundledRuntimeBaseUrl: String = ""
    }

    // Not persisted: who wants to hear when Private Mode flips (every open
    // chat tool window, in every project).
    private val privacyListeners = java.util.concurrent.CopyOnWriteArrayList<Runnable>()

    private var state = State()

    override fun getState(): State = state

    override fun loadState(state: State) {
        this.state = state
    }

    var environment: String
        get() = state.environment
        set(value) {
            state.environment = value
        }

    var customApiBase: String
        get() = state.customApiBase
        set(value) {
            state.customApiBase = value
        }

    var customAuthBase: String
        get() = state.customAuthBase
        set(value) {
            state.customAuthBase = value
        }

    var localApiBase: String
        get() = state.localApiBase
        set(value) {
            state.localApiBase = value
        }

    var localAuthBase: String
        get() = state.localAuthBase
        set(value) {
            state.localAuthBase = value
        }

    var localServerBaseUrl: String
        get() = state.localServerBaseUrl
        set(value) {
            state.localServerBaseUrl = value
        }

    var localServerModel: String
        get() = state.localServerModel
        set(value) {
            state.localServerModel = value
        }

    var localCompletionsEnabled: Boolean
        get() = state.localCompletionsEnabled
        set(value) {
            state.localCompletionsEnabled = value
        }

    var agentBaseUrl: String
        get() = state.agentBaseUrl
        set(value) {
            state.agentBaseUrl = value
        }

    var agentModel: String
        get() = state.agentModel
        set(value) {
            state.agentModel = value
        }

    var agentMaxSteps: Int
        get() = state.agentMaxSteps
        set(value) {
            state.agentMaxSteps = value
        }

    var agentAutoApproveEdits: Boolean
        get() = state.agentAutoApproveEdits
        set(value) {
            state.agentAutoApproveEdits = value
        }

    var agentAutoApproveCommands: Boolean
        get() = state.agentAutoApproveCommands
        set(value) {
            state.agentAutoApproveCommands = value
        }

    var bundledRuntimeModel: String
        get() = state.bundledRuntimeModel
        set(value) {
            state.bundledRuntimeModel = value
        }

    var bundledRuntimeBaseUrl: String
        get() = state.bundledRuntimeBaseUrl
        set(value) {
            state.bundledRuntimeBaseUrl = value
        }

    /** Setting it (from the chat panel or Settings) notifies every
     * privacy listener, whether or not the value changed - a listener that
     * re-posts privacy.state is idempotent. */
    var privateMode: Boolean
        get() = state.privateMode
        set(value) {
            state.privateMode = value
            for (listener in privacyListeners) {
                runCatching { listener.run() }
            }
        }

    fun addPrivacyListener(listener: Runnable) {
        privacyListeners.add(listener)
    }

    fun removePrivacyListener(listener: Runnable) {
        privacyListeners.remove(listener)
    }

    /** The coding agent's endpoint, or null to let discovery pick one. Same
     * RULE 0 carve-out as the local inference server above: this is the user's
     * own server, or a provider origin they typed. */
    fun agentBaseUrlOrNull(): String? = state.agentBaseUrl.trim().trimEnd('/').ifBlank { null }

    /** The model id to ask for, or null to take the first one the server lists. */
    fun agentModelOrNull(): String? = state.agentModel.trim().ifBlank { null }

    /** The step ceiling, clamped to the same range the VS Code setting declares.
     * A persisted state file is editable by hand, so the bound is re-applied on
     * read rather than trusted from disk - it is a safety property, and an
     * unbounded loop with write and shell tools is the thing it bounds. */
    fun agentMaxStepsBounded(): Int = state.agentMaxSteps.coerceIn(AGENT_MIN_STEPS, AGENT_MAX_STEPS)

    /** The local inference server origin, trimmed of trailing slashes, or null
     * when the user has not set one. RULE 0 does not apply to it (see the
     * header): it is the user's own machine, not a platform URL, and there is
     * deliberately no default - null means "no local inference here". */
    fun localServerBaseUrlOrNull(): String? =
        state.localServerBaseUrl.trim().trimEnd('/').ifBlank { null }

    /** The model id to ask for, or null to take the first one the server
     * lists (ollamaEngine.ts's pickModel() rule). */
    fun localServerModelOrNull(): String? = state.localServerModel.trim().ifBlank { null }

    /** Completions need BOTH the opt-in and a server to talk to. */
    fun localCompletionsActive(): Boolean =
        state.localCompletionsEnabled && localServerBaseUrlOrNull() != null

    /** The local install's api base, or the compose default when unset. */
    fun localApiBaseOrDefault(): String =
        state.localApiBase.trim().trimEnd('/').ifBlank { LOCAL_API_DEFAULT }

    /** Its Keycloak, same defaulting. */
    fun localAuthBaseOrDefault(): String =
        state.localAuthBase.trim().trimEnd('/').ifBlank { LOCAL_AUTH_DEFAULT }

    fun apiBase(): String = when (state.environment) {
        ENV_PRODUCTION -> "https://api.vegaduta.ai"
        ENV_LOCAL -> localApiBaseOrDefault()
        ENV_CUSTOM -> state.customApiBase.trim().ifBlank { "https://api.vegaduta.xyz" }
        else -> "https://api.vegaduta.xyz"
    }

    fun authBase(): String = when (state.environment) {
        ENV_PRODUCTION -> "https://auth.vegaduta.ai"
        ENV_LOCAL -> localAuthBaseOrDefault()
        ENV_CUSTOM -> state.customAuthBase.trim().ifBlank { "https://auth.vegaduta.xyz" }
        else -> "https://auth.vegaduta.xyz"
    }

    companion object {
        const val ENV_STAGING = "staging"
        const val ENV_PRODUCTION = "production"
        const val ENV_CUSTOM = "custom"
        const val ENV_LOCAL = "local"

        /** deploy/compose defaults (CORE_HOST_PORT / KEYCLOAK_HOST_PORT on
         * BIND_ADDR 127.0.0.1) - the one pair of loopback URLs this plugin
         * may hold, because they name the user's own install. */
        const val LOCAL_API_DEFAULT = "http://127.0.0.1:8080"
        const val LOCAL_AUTH_DEFAULT = "http://127.0.0.1:8180"

        /** vegaduta.agent.maxSteps' declared minimum/maximum in
         * clients/vscode/package.json. */
        const val AGENT_MIN_STEPS = 1
        const val AGENT_MAX_STEPS = 300

        fun getInstance(): VegadutaSettingsState = service()
    }
}
