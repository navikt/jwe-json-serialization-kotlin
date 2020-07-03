package no.nav.security.jwe

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import net.minidev.json.JSONObject
import no.nav.security.jwe.testsupport.makeJwkRSA
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.BufferedReader
import java.io.InputStreamReader
import java.lang.RuntimeException

class PyJWCryptoInteropEncryptTest {

    /**
     * NB: This test requires python3 in path, with jwcrypto installed (pip3 install jwcrypto)
     */

    @Test
    fun `Encrypt without AdditionalAuthenticatedData, then decrypt with Python JWCrypto`() {
        val payload = "This Is The PlainText { 1 2 3 }"
        val plaintext = payload.toByteArray(Charsets.UTF_8)
        val jwkPair1 = makeJwkRSA()
        val jwkPair2 = makeJwkRSA()
        val jwkPair3 = makeJwkRSA()
        val recipientsPublic = JWKSet(listOf(jwkPair1.public, jwkPair2.public))
        val jwe = encryptAsJsonSerializedJWE(plaintext = plaintext, recipientKeys = recipientsPublic)

        assertEquals(payload, decryptWithPythonJWCrypto(jwe, jwkPair1.private))

        assertEquals(payload, decryptWithPythonJWCrypto(jwe, jwkPair2.private))

        assertThrows<ProcessExitedWithError> {
            decryptWithPythonJWCrypto(jwe, jwkPair3.private)
        }
    }

    @Test
    fun `Compress and Encrypt without AdditionalAuthenticatedData, then decrypt with Python JWCrypto`() {
        val payload = "This Is The PlainText TO be Compressed { 1 2 3 }"
        val plaintext = payload.toByteArray(Charsets.UTF_8)
        val jwkPair1 = makeJwkRSA()
        val jwkPair2 = makeJwkRSA()
        val jwkPair3 = makeJwkRSA()
        val recipientsPublic = JWKSet(listOf(jwkPair1.public, jwkPair2.public))
        val jwe = encryptAsJsonSerializedJWE(
            plaintext = plaintext,
            recipientKeys = recipientsPublic,
            useCompression = true
        )

        assertEquals(payload, decryptWithPythonJWCrypto(jwe, jwkPair1.private))

        assertEquals(payload, decryptWithPythonJWCrypto(jwe, jwkPair2.private))

        assertThrows<ProcessExitedWithError> {
            decryptWithPythonJWCrypto(jwe, jwkPair3.private)
        }
    }

    @Test
    fun `Compress and Encrypt _with_ AdditionalAuthenticatedData, then decrypt with Python JWCrypto`() {
        val payload = "This Is The PlainText TO be Compressed { 1 2 3 }"
        val plaintext = payload.toByteArray(Charsets.UTF_8)
        val jwkPair1 = makeJwkRSA()
        val jwkPair2 = makeJwkRSA()
        val jwkPair3 = makeJwkRSA()
        val recipientsPublic = JWKSet(listOf(jwkPair1.public, jwkPair2.public))
        val jwe = encryptAsJsonSerializedJWE(
            plaintext = plaintext,
            recipientKeys = recipientsPublic,
            useCompression = true,
            additionalAuthenticatedData = "aDdItIoNaL auth DATA".toByteArray()
        )

        assertEquals(payload, decryptWithPythonJWCrypto(jwe, jwkPair1.private))

        assertEquals(payload, decryptWithPythonJWCrypto(jwe, jwkPair2.private))

        assertThrows<ProcessExitedWithError> {
            decryptWithPythonJWCrypto(jwe, jwkPair3.private)
        }
    }

}

private fun decryptWithPythonJWCrypto(jwe: JSONObject, jwk: JWK): String {
    val process = ProcessBuilder()
        .command(
            "python3",
            System.getProperty("user.dir") + "/src/test/python/jw_decrypt.py",
            jwk.toJSONString(),
            jwe.toJSONString()
        )
        .start()
    process.waitFor()
    if (process.exitValue() != 0) {
        throw ProcessExitedWithError()
    }
    val reader = BufferedReader(InputStreamReader(process.inputStream))
    return reader.readText().trim()
}

class ProcessExitedWithError : RuntimeException()
