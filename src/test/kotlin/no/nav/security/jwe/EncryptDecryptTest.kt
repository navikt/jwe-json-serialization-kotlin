package no.nav.security.jwe

import com.nimbusds.jose.jwk.JWKSet
import no.nav.security.jwe.testsupport.makeJwkRSA
import org.junit.jupiter.api.Assertions
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
        val jwe = encryptAsJsonSerializedJWE(plaintext = plaintext, recipientKeys = recipientsPublic)

        println(jwe)

        val oneJwkSet = JWKSet(jwkPair1.private)
        Assertions.assertEquals(payload, decryptJsonSerializedJWE(jwe, oneJwkSet))
        val anotherJwkSet = JWKSet(jwkPair2.private)
        Assertions.assertEquals(payload, decryptJsonSerializedJWE(jwe, anotherJwkSet))
        val nonMatchingJwkSet = JWKSet(jwkPair3.private)
        assertThrows<NoMatchingKeyException> {
            decryptJsonSerializedJWE(jwe, nonMatchingJwkSet)
        }
    }

}