package no.nav.security.jwe

import com.nimbusds.jose.jwk.JWKSet
import no.nav.security.jwe.testsupport.makeJwkRSA
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class EncryptDecryptTest {

    @Test
    fun `Encrypt without AdditionalAuthenticatedData, then decrypt`() {
        val payload = "This Is The PlainText { æ ø å }"
        val plaintext = payload.toByteArray(Charsets.UTF_8)
        val jwkPair1 = makeJwkRSA()
        val jwkPair2 = makeJwkRSA()
        val jwkPair3 = makeJwkRSA()
        val recipientsPublic = JWKSet(listOf(jwkPair1.public, jwkPair2.public))
        val jwe = encryptAsJsonSerializedJWE(
            plaintext = plaintext,
            recipientKeys = recipientsPublic,
            useCompression = false)

        val oneJwkSet = JWKSet(jwkPair1.private)
        assertEquals(payload, decryptJsonSerializedJWEtoString(jwe, oneJwkSet))
        val anotherJwkSet = JWKSet(jwkPair2.private)
        assertEquals(payload, decryptJsonSerializedJWEtoString(jwe, anotherJwkSet))
        val nonMatchingJwkSet = JWKSet(jwkPair3.private)
        assertThrows<NoMatchingKeyException> {
            decryptJsonSerializedJWEtoString(jwe, nonMatchingJwkSet)
        }
    }

    @Test
    fun `Compress and Encrypt without AdditionalAuthenticatedData, then decrypt`() {
        val payload = "This Is The PlainText { æ ø å }"
        val plaintext = payload.toByteArray(Charsets.UTF_8)
        val jwkPair1 = makeJwkRSA()
        val jwkPair2 = makeJwkRSA()
        val jwkPair3 = makeJwkRSA()
        val recipientsPublic = JWKSet(listOf(jwkPair1.public, jwkPair2.public))
        val jwe = encryptAsJsonSerializedJWE(
            plaintext = plaintext,
            recipientKeys = recipientsPublic,
            useCompression = true)

        val oneJwkSet = JWKSet(jwkPair1.private)
        assertEquals(payload, decryptJsonSerializedJWEtoString(jwe, oneJwkSet))
        val anotherJwkSet = JWKSet(jwkPair2.private)
        assertEquals(payload, decryptJsonSerializedJWEtoString(jwe, anotherJwkSet))
        val nonMatchingJwkSet = JWKSet(jwkPair3.private)
        assertThrows<NoMatchingKeyException> {
            decryptJsonSerializedJWEtoString(jwe, nonMatchingJwkSet)
        }
    }

    @Test
    fun `make sure compressed JWE is actually compressed`() {
        val plaintext = ByteArray(10000) { 0 }
        val jwkPair1 = makeJwkRSA()
        val recipientsPublic = JWKSet(listOf(jwkPair1.public))

        val unCompressedJWE = encryptAsJsonSerializedJWE(
            plaintext = plaintext,
            recipientKeys = recipientsPublic,
            useCompression = false)
        val compressedJWE = encryptAsJsonSerializedJWE(
            plaintext = plaintext,
            recipientKeys = recipientsPublic,
            useCompression = true)

        assertTrue(unCompressedJWE.toString().length > 10000)
        assertTrue(compressedJWE.toString().length < 1500)

        assertArrayEquals(plaintext, decryptJsonSerializedJWE(unCompressedJWE, JWKSet(listOf(jwkPair1.private))))
        assertArrayEquals(plaintext, decryptJsonSerializedJWE(compressedJWE, JWKSet(listOf(jwkPair1.private))))
    }

}