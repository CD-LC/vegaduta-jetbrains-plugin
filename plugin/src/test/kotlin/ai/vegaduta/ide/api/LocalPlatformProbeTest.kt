// Wire-shape coverage for LocalPlatformProbe's /api/auth/local parsing - the
// camelCase SessionResponse (NOT the OIDC snake_case) and the refusal shape.
// No network: parseSession takes the response body directly.

package ai.vegaduta.ide.api

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LocalPlatformProbeTest {

    private val sessionBody = """
        {
          "accessToken": "acc-token",
          "tokenType": "Bearer",
          "expiresIn": 3600,
          "refreshToken": "ref-token",
          "refreshExpiresIn": 2592000,
          "passwordChangeRequired": false,
          "user": {
            "id": "u1", "email": "me@local", "firstName": "Me",
            "lastName": "", "tenantId": "t", "roles": []
          }
        }
    """.trimIndent()

    @Test
    fun `parses a session response`() {
        val s = LocalPlatformProbe.parseSession(sessionBody)
        requireNotNull(s)
        assertEquals("acc-token", s.accessToken)
        assertEquals("ref-token", s.refreshToken)
        assertEquals(3600, s.expiresIn)
        assertEquals("Me", s.username)
        assertTrue(!s.passwordChangeRequired)
    }

    @Test
    fun `falls back to email for the display name`() {
        val body = sessionBody.replace("\"firstName\": \"Me\"", "\"firstName\": \" \"")
        assertEquals("me@local", LocalPlatformProbe.parseSession(body)?.username)
    }

    @Test
    fun `tolerates a missing refresh token`() {
        val body = sessionBody.replace("\"refreshToken\": \"ref-token\",", "")
        val s = LocalPlatformProbe.parseSession(body)
        requireNotNull(s)
        assertNull(s.refreshToken)
    }

    @Test
    fun `rejects a body with no access token`() {
        assertNull(LocalPlatformProbe.parseSession("{}"))
        assertNull(LocalPlatformProbe.parseSession("<html>"))
        assertNull(LocalPlatformProbe.parseSession("""{"error":"bad_credentials","message":"Wrong."}"""))
    }
}
