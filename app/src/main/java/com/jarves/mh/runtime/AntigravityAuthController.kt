package com.jarves.mh.runtime

import android.content.Context
import com.jarves.mh.R
import com.jarves.mh.ui.AppStrings
import java.io.File
import java.io.RandomAccessFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

/** Drives only agy's official interactive OAuth flow; it never reads the resulting credentials. */
class AntigravityAuthController(
    private val context: Context,
    initiallySignedIn: Boolean,
    initialAccountEmail: String,
    private val onSignedInChanged: (Boolean, String?) -> Unit,
) {
    private val installer = RuntimeInstaller(context)
    private val mutableState = MutableStateFlow(
        AntigravityAuthState(
            status = if (initiallySignedIn) AntigravityAuthStatus.SIGNED_IN else AntigravityAuthStatus.SIGNED_OUT,
            message = initialAccountEmail.takeIf(String::isNotBlank)?.let { AppStrings.get(context, R.string.rt_agy_connected_as, it) },
            accountEmail = initialAccountEmail.takeIf(String::isNotBlank),
        ),
    )
    val state: StateFlow<AntigravityAuthState> = mutableState.asStateFlow()
    private fun str(@androidx.annotation.StringRes id: Int, vararg args: Any): String = AppStrings.get(context, id, *args)
    private val authOutput = File(context.cacheDir, "antigravity-auth-output.log")
    private val logoutOutput = File(context.cacheDir, "antigravity-logout-output.log")
    @Volatile private var process: Process? = null
    @Volatile private var codeSubmitted = false

    init {
        // Remove output left by an app/process crash before starting a new OAuth flow.
        authOutput.delete()
        logoutOutput.delete()
        if (hasOfficialCredential() && !initiallySignedIn) {
            mutableState.value = AntigravityAuthState(
                status = AntigravityAuthStatus.SIGNED_IN,
                message = initialAccountEmail.takeIf(String::isNotBlank)?.let { AppStrings.get(context, R.string.rt_agy_connected_as, it) }
                    ?: AppStrings.get(context, R.string.rt_agy_google_connected),
                accountEmail = initialAccountEmail.takeIf(String::isNotBlank),
            )
            onSignedInChanged(true, initialAccountEmail.takeIf(String::isNotBlank))
        }
    }

    private fun officialCredentialFile() = File(
        context.filesDir,
        "runtime/ubuntu/root/.gemini/antigravity-cli/antigravity-oauth-token",
    )

    fun hasOfficialCredential(): Boolean = officialCredentialFile().let { it.isFile && it.length() > 0L }

    suspend fun beginLogin() = withContext(Dispatchers.IO) {
        process?.takeIf { it.isAlive }?.let {
            runCatching { it.destroy() }
            process = null
            delay(100)
        }
        if (!installer.isAgentInstalled(com.jarves.mh.model.AgentKind.ANTIGRAVITY)) {
            mutableState.value = AntigravityAuthState(
                AntigravityAuthStatus.ERROR,
                message = str(R.string.rt_agy_install_first),
            )
            return@withContext
        }
        mutableState.value = AntigravityAuthState(AntigravityAuthStatus.STARTING, message = str(R.string.rt_agy_starting))
        codeSubmitted = false
        authOutput.delete()
        val runtime = installer.installedRuntime()
        val workspace = java.io.File(context.filesDir, "workspaces/antigravity-auth").apply { mkdirs() }
        val running = installer.process(
            runtime.proot,
            runtime.rootfs,
            workspace,
            // SSH selects agy's official manual browser URL + one-time code flow.
            // NativeSpawn supplies a real PTY; PocketDev remains only the terminal.
            mapOf(
                "SSH_CONNECTION" to "127.0.0.1 1 127.0.0.1 1",
                "TERM" to "xterm-256color",
                "NO_COLOR" to "1",
            ),
            listOf(RuntimeInstaller.AGY_GUEST_PATH),
            guestWorkspacePath = "/workspace/antigravity-auth",
            emulateHardLinks = false,
            outputFile = authOutput,
            pseudoTerminal = true,
            ptyRows = 40,
            ptyColumns = 120,
        )
        process = running
        val native = running as? NativeSpawnProcess ?: error("Unsupported Antigravity authentication process")
        var offset = 0L
        val output = StringBuilder()
        var handshakeReplies = 0
        var lastHandshakeReplyTime = 0L
        var lastMenuAdvanceTime = 0L
        var menuAdvanceCount = 0
        var lastInteractionTime = System.currentTimeMillis()
        var colorScreenCompleted = false
        var renderingScreenCompleted = false
        var privacyScreenCompleted = false
        var workspaceTrustCompleted = false
        val startTime = System.currentTimeMillis()

        try {
            while (running.isAlive || native.outputFile.length() > offset) {
                val available = native.outputFile.length() - offset
                val now = System.currentTimeMillis()

                if (available <= 0) {
                    // Check for timeout if waiting in STARTING status (allow up to 120s for 200MB CLI cold start & network)
                    if (mutableState.value.status == AntigravityAuthStatus.STARTING && now - startTime > 120_000L) {
                        error(str(R.string.rt_agy_sign_in_failed) + " (Timed out waiting for login link)")
                    }
                    delay(80)
                    continue
                }
                val bytes = ByteArray(minOf(available, 16L * 1024).toInt())
                val count = RandomAccessFile(native.outputFile, "r").use { file ->
                    file.seek(offset)
                    file.read(bytes)
                }
                if (count <= 0) continue
                offset += count
                output.append(bytes.decodeToString(0, count))
                val fullRaw = output.toString()
                val clean = sanitizeTerminalOutput(fullRaw).takeLast(40_000)

                // Respond to terminal capability and cursor position queries without arbitrary length thresholds
                if (handshakeReplies < 10 &&
                    now - lastHandshakeReplyTime > 500L &&
                    (fullRaw.contains("\u001B[?u") || fullRaw.contains("\u001B[c") || fullRaw.contains("\u001B[6n"))
                ) {
                    running.outputStream.write(TERMINAL_HANDSHAKE_REPLY.toByteArray(Charsets.UTF_8))
                    running.outputStream.flush()
                    handshakeReplies++
                    lastHandshakeReplyTime = now
                }

                // Check for OAuth URL continuously, checking raw OSC 8 hyperlink first
                val url = extractOsc8GoogleOAuthUrl(fullRaw)
                    ?: extractGoogleOAuthUrl(clean)
                    ?: extractGoogleOAuthUrl(fullRaw)
                if (url != null && mutableState.value.authorizationUrl == null) {
                    android.util.Log.i("AntigravityAuthController", "Detected Google OAuth URL: ${url.take(60)}...")
                    mutableState.value = AntigravityAuthState(
                        AntigravityAuthStatus.AWAITING_CODE,
                        authorizationUrl = url,
                        message = str(R.string.rt_agy_finish_sign_in),
                    )
                }

                // Advance login menu reliably: re-send selection if still at login menu after 1.2s,
                // but do not spam while agy is actively contacting Google ("Signing in...")
                val isSigningIn = clean.contains("Signing in", true) || clean.contains("Signing you in", true)
                if (isSigningIn && mutableState.value.status == AntigravityAuthStatus.STARTING) {
                    mutableState.value = mutableState.value.copy(
                        message = str(R.string.rt_agy_oauth_selected),
                    )
                }

                val isAtLoginMenu = (clean.contains("Select login method", true) ||
                    clean.contains("Google OAuth", true) ||
                    clean.contains("Other sign-in options", true)) &&
                    url == null &&
                    !isSigningIn &&
                    !clean.contains("authorization code", true)

                if (isAtLoginMenu && now - lastMenuAdvanceTime > 1200L) {
                    lastMenuAdvanceTime = now
                    menuAdvanceCount++
                    // In raw terminal mode, Enter is '\r' (0x0D).
                    android.util.Log.i("AntigravityAuthController", "Advancing login menu (attempt $menuAdvanceCount)")
                    running.outputStream.write("\r".toByteArray(Charsets.UTF_8))
                    running.outputStream.flush()
                    if (mutableState.value.status == AntigravityAuthStatus.STARTING) {
                        mutableState.value = mutableState.value.copy(
                            message = str(R.string.rt_agy_oauth_selected),
                        )
                    }
                }

                if (clean.contains("authentication failed", true) || clean.contains("failed to exchange", true)) {
                    error(str(R.string.rt_agy_auth_failed))
                }

                val hasNewOfficialCredential = codeSubmitted &&
                    officialCredentialFile().exists() &&
                    officialCredentialFile().lastModified() >= startTime &&
                    !clean.contains("authorization code", true)

                if (isSignedInScreen(clean) || hasNewOfficialCredential) {
                    val email = extractSignedInEmail(clean)
                    onSignedInChanged(true, email)
                    mutableState.value = AntigravityAuthState(
                        AntigravityAuthStatus.SIGNED_IN,
                        message = email?.let { str(R.string.rt_agy_connected_as, it) } ?: str(R.string.rt_agy_google_connected),
                        accountEmail = email,
                    )
                    // Leave the official CLI cleanly so it flushes credential/session state
                    runCatching {
                        running.outputStream.write("/quit\r\n".toByteArray(Charsets.UTF_8))
                        running.outputStream.flush()
                    }
                    repeat(20) {
                        if (!running.isAlive) return@repeat
                        delay(50)
                    }
                    if (running.isAlive) running.destroy()
                    break
                }
                if (!colorScreenCompleted && clean.contains("Choose your color scheme", true) && now - lastInteractionTime > 1000L) {
                    running.outputStream.write("\r\n".toByteArray(Charsets.UTF_8))
                    running.outputStream.flush()
                    lastInteractionTime = now
                    colorScreenCompleted = true
                }
                if (!renderingScreenCompleted &&
                    (clean.contains("no flickering", true) || clean.contains("Native Terminal experience", true)) &&
                    now - lastInteractionTime > 1000L
                ) {
                    running.outputStream.write("\u001B[B\r\n".toByteArray(Charsets.UTF_8))
                    running.outputStream.flush()
                    lastInteractionTime = now
                    renderingScreenCompleted = true
                }
                if (!privacyScreenCompleted &&
                    (clean.contains("Terms of Service", true) || clean.contains("Data Use", true)) &&
                    now - lastInteractionTime > 1000L
                ) {
                    val optOutAndFinish = if (clean.contains("[x] Yes", true)) " \t\t\r\n" else "\t\t\r\n"
                    running.outputStream.write(optOutAndFinish.toByteArray(Charsets.UTF_8))
                    running.outputStream.flush()
                    lastInteractionTime = now
                    privacyScreenCompleted = true
                    mutableState.value = mutableState.value.copy(
                        message = str(R.string.rt_agy_finishing_setup),
                    )
                }
                if (!workspaceTrustCompleted &&
                    (clean.contains("trust", true) && (clean.contains("folder", true) || clean.contains("project", true))) &&
                    now - lastInteractionTime > 1000L
                ) {
                    running.outputStream.write("\r\n".toByteArray(Charsets.UTF_8))
                    running.outputStream.flush()
                    lastInteractionTime = now
                    workspaceTrustCompleted = true
                }
            }
            if (!codeSubmitted && mutableState.value.status == AntigravityAuthStatus.STARTING) {
                val exit = running.waitFor()
                error(str(R.string.rt_agy_closed_early, exit))
            }
        } catch (error: Throwable) {
            if (mutableState.value.status != AntigravityAuthStatus.SIGNED_IN) {
                mutableState.value = AntigravityAuthState(
                    AntigravityAuthStatus.ERROR,
                    message = error.message?.take(240) ?: str(R.string.rt_agy_sign_in_failed),
                )
            }
        } finally {
            if (running.isAlive) running.destroy()
            runCatching { running.outputStream.close() }
            native.outputFile.delete() // OAuth terminal output is intentionally ephemeral.
            process = null
            codeSubmitted = false
        }
    }

    fun submitCode(code: String) {
        val value = code.trim()
        require(value.isNotBlank()) { str(R.string.rt_agy_paste_code) }
        val running = process ?: error(str(R.string.rt_agy_start_again))
        check(running.isAlive) { str(R.string.rt_agy_session_expired) }
        // agy's interactive editor runs the PTY in raw mode and treats CR+LF as
        // the Enter key. LF alone inserts/repaints a line without submitting it.
        running.outputStream.write((value + "\r\n").toByteArray(Charsets.UTF_8))
        running.outputStream.flush()
        codeSubmitted = true
        mutableState.value = mutableState.value.copy(
            status = AntigravityAuthStatus.COMPLETING,
            message = str(R.string.rt_agy_completing),
        )
    }

    suspend fun logout() = withContext(Dispatchers.IO) {
        process?.destroy()
        val previousEmail = mutableState.value.accountEmail
        mutableState.value = AntigravityAuthState(
            status = AntigravityAuthStatus.STARTING,
            message = str(R.string.rt_agy_signing_out),
            accountEmail = previousEmail,
        )
        try {
            // Under Android PRoot agy deliberately uses this file instead of a
            // Linux Secret Service keyring. Deleting this exact app-private file
            // is the deterministic equivalent of agy's /logout; its contents are
            // never read, copied, or logged by PocketDev.
            val credential = officialCredentialFile()
            if (credential.exists()) {
                check(credential.delete()) {
                    str(R.string.rt_agy_remove_credential_failed)
                }
            }
            check(!hasOfficialCredential()) { str(R.string.rt_agy_logout_incomplete) }
            onSignedInChanged(false, null)
            mutableState.value = AntigravityAuthState(AntigravityAuthStatus.SIGNED_OUT, message = str(R.string.rt_agy_signed_out))
        } catch (error: Throwable) {
            mutableState.value = AntigravityAuthState(
                status = AntigravityAuthStatus.SIGNED_IN,
                message = error.message?.take(240) ?: str(R.string.rt_agy_logout_failed),
                accountEmail = previousEmail,
            )
            throw error
        } finally {
            process = null
            logoutOutput.delete()
        }
    }

    fun cancel() {
        process?.destroy()
        mutableState.value = AntigravityAuthState(AntigravityAuthStatus.SIGNED_OUT)
    }

    fun invalidateSession(message: String) {
        onSignedInChanged(false, null)
        mutableState.value = AntigravityAuthState(AntigravityAuthStatus.ERROR, message = message)
    }
}

internal fun extractOsc8GoogleOAuthUrl(output: String): String? {
    val match = OSC8_OAUTH_URL.find(output) ?: return null
    val candidate = match.groupValues[1].trimEnd { it !in URL_CHARACTERS }
    return candidate.takeIf {
        it.contains("client_id=", ignoreCase = true) &&
            (it.contains("redirect_uri=", ignoreCase = true) || it.contains("response_type=", ignoreCase = true))
    }
}

internal fun extractGoogleOAuthUrl(output: String): String? {
    // Check OSC 8 escape sequence first if called directly with raw terminal output
    extractOsc8GoogleOAuthUrl(output)?.let { return it }

    val compact = output.replace(Regex("[\\r\\n\\t ]+"), "")

    // 1. Primary match: Google OAuth authorization URL up to terminal formatting / box chars
    val oauthPattern = Regex("https://accounts\\.google\\.com/o/oauth2/[^\\s\"'<>│─→]+")
    val match = oauthPattern.find(compact)
    if (match != null) {
        val candidate = match.value.trimEnd { char -> char !in URL_CHARACTERS }
        if (candidate.contains("client_id=", ignoreCase = true) &&
            (candidate.contains("redirect_uri=", ignoreCase = true) ||
                candidate.contains("response_type=", ignoreCase = true) ||
                candidate.contains("code_challenge=", ignoreCase = true))
        ) {
            return candidate
        }
    }

    // 2. PKCE match targeting state parameter
    GOOGLE_OAUTH_URL.find(compact)?.value
        ?.takeIf { "client_id=" in it && ("code_challenge=" in it || "redirect_uri=" in it) }
        ?.let { return it }

    // 3. Fallback for any Google Accounts URL with auth or code
    val candidates = Regex("https://accounts\\.google\\.com/[^\\s\"'<>│─→]{20,}")
        .findAll(compact)
        .map { it.value.trimEnd { char -> char !in URL_CHARACTERS } }
        .filter {
            (it.contains("oauth", ignoreCase = true) || it.contains("auth", ignoreCase = true)) &&
                it.contains("client_id=", ignoreCase = true) &&
                (it.contains("redirect_uri=", ignoreCase = true) || it.contains("response_type=", ignoreCase = true))
        }
        .toList()
    if (candidates.isNotEmpty()) {
        return candidates.first()
    }

    // 4. Fallback for post-menu screens or generic browser prompts
    if (output.contains("browser", true) || output.contains("visit", true) ||
        output.contains("open", true) || output.contains("code", true) ||
        output.contains("paste", true) || output.contains("authenticate", true)
    ) {
        val generic = Regex("https://[^\\s\"'<>│─→]{20,}")
            .findAll(compact)
            .map { it.value.trimEnd { char -> char !in URL_CHARACTERS } }
            .filter { it.length >= 30 && "." in it && "google" in it && "client_id=" in it }
            .firstOrNull()
        if (generic != null) return generic
    }
    return null
}

private fun isSignedInScreen(output: String): Boolean =
    output.contains("for shortcuts", true) ||
        (output.contains("Antigravity CLI", true) && output.contains("Google AI", true)) ||
        output.contains("logged in as", true) ||
        output.contains("signed in as", true) ||
        output.contains("authenticated as", true) ||
        output.contains("welcome to antigravity", true) ||
        output.contains("authentication successful", true)

private fun extractSignedInEmail(output: String): String? =
    Regex("[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}", RegexOption.IGNORE_CASE)
        .findAll(output)
        .map { it.value }
        .firstOrNull { !it.endsWith(".apps.googleusercontent.com", ignoreCase = true) }

private val URL_CHARACTERS = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
    "-._~:/?#[]@!$&'()*+,;=%").toSet()

private val GOOGLE_OAUTH_URL = Regex(
    "https://accounts\\.google\\.com/[^\\s\\\"'<>]*?[?&]state=[A-Za-z0-9._~-]+",
)

private val OSC8_OAUTH_URL = Regex(
    """\u001B\]8;[^;]*;(https://accounts\.google\.com/o/oauth2/[^\u0007\u001B]+)(?:\u0007|\u001B\\)""",
)

private const val TERMINAL_HANDSHAKE_REPLY = "\u001B[?2026;1\$y\u001B[?2027;1\$y\u001B[?1u"

private val AUTH_ANSI = Regex("\\u001B(?:\\][^\\u0007]*(?:\\u0007|\\u001B\\\\)|\\[[0-?]*[ -/]*[@-~]|[()][A-Z0-9])")
private fun sanitizeTerminalOutput(text: String): String = text
    .replace(AUTH_ANSI, "")
    .filter { it == '\n' || it == '\r' || it == '\t' || it.code >= 0x20 }
