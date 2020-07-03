package no.nav.security.jwe

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.util.Base64URL
import no.nav.security.jwe.testsupport.makeJwkRSA
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class NegativeTest {

    @Test
    fun `Decryption fails when keyId matches, but key is wrong`() {
        val payload = "This Is The PlainText { æ ø å }"
        val plaintext = payload.toByteArray(Charsets.UTF_8)
        val jwkPair1 = makeJwkRSA()
        val wrongKeyWithMatchingKeyId = makeJwkRSA(keyId = jwkPair1.private.keyID)
        val recipientsPublic = JWKSet(listOf(jwkPair1.public))
        val jwe = encryptAsJsonSerializedJWE(
            plaintext = plaintext,
            recipientKeys = recipientsPublic,
            useCompression = false
        )
        val oneJwkSet = JWKSet(jwkPair1.private)
        assertEquals(payload, decryptJsonSerializedJWEtoString(jwe, oneJwkSet))

        val anotherJwkSet = JWKSet(wrongKeyWithMatchingKeyId.private)
        assertThrows<JOSEException> {
            decryptJsonSerializedJWEtoString(jwe, anotherJwkSet)
        }
    }

    @Test
    fun `Unpack fails if AAD is wrong`() {
        val payload = "This Is The PlainText { æ ø å }"
        val plaintext = payload.toByteArray(Charsets.UTF_8)
        val jwkPair1 = makeJwkRSA()
        val recipientsPublic = JWKSet(listOf(jwkPair1.public))
        val jwe = encryptAsJsonSerializedJWE(
            plaintext = plaintext,
            recipientKeys = recipientsPublic,
            useCompression = false,
            additionalAuthenticatedData = "12345".toByteArray()
        )
        val oneJwkSet = JWKSet(jwkPair1.private)

        jwe["aad"] = Base64URL.encode("wrong stufff").toString()
        assertThrows<JOSEException> {
            decryptJsonSerializedJWEtoString(jwe, oneJwkSet)
        }
        jwe["aad"] = null
        assertThrows<JOSEException> {
            decryptJsonSerializedJWEtoString(jwe, oneJwkSet)
        }
        jwe["aad"] = Base64URL.encode("12345").toString()
        assertEquals(payload, decryptJsonSerializedJWEtoString(jwe, oneJwkSet))
    }

    @Test
    fun `Unpack fails if TAG is wrong`() {
        val payload = "This Is The PlainText { æ ø å }"
        val plaintext = payload.toByteArray(Charsets.UTF_8)
        val jwkPair1 = makeJwkRSA()
        val recipientsPublic = JWKSet(listOf(jwkPair1.public))
        val jwe = encryptAsJsonSerializedJWE(
            plaintext = plaintext,
            recipientKeys = recipientsPublic,
            useCompression = false
        )
        val oneJwkSet = JWKSet(jwkPair1.private)

        jwe["tag"] = Base64URL.encode("wrong stufff").toString()
        assertThrows<JOSEException> {
            decryptJsonSerializedJWEtoString(jwe, oneJwkSet)
        }
        jwe["tag"] = null
        assertThrows<IllegalArgumentException> {
            decryptJsonSerializedJWEtoString(jwe, oneJwkSet)
        }
    }

}