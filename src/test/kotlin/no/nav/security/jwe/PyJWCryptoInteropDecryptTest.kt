package no.nav.security.jwe

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import net.minidev.json.JSONObject
import net.minidev.json.parser.JSONParser
import no.nav.security.jwe.testsupport.makeJwkRSA
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class PyJWCryptoInteropDecryptTest {

    @Test
    fun `Decrypt JWE from Python JWCrypto without AdditionalAuthenticatedData`() {
        val exampleWithAAD: String = PyJWCryptoInteropDecryptTest::class.java.getResource("/pyjwcrypto_ex1.json")
            .readText().trim()
        val data: JSONObject =
            JSONParser(JSONParser.MODE_STRICTEST).parse(exampleWithAAD.toByteArray(Charsets.UTF_8)) as JSONObject
        val privateJWK = JWK.parse(data["private"] as JSONObject)
        val otherPrivateJWK = JWK.parse(data["other_private"] as JSONObject)
        val nonMatchingPrivateJWK = makeJwkRSA().private
        val jwe = data["jwe"] as JSONObject
        val payload = data.getAsString("payload")

        val oneJwkSet = JWKSet(privateJWK)
        Assertions.assertEquals(payload, decryptJsonSerializedJWEtoString(jwe, oneJwkSet))
        val anotherJwkSet = JWKSet(otherPrivateJWK)
        Assertions.assertEquals(payload, decryptJsonSerializedJWEtoString(jwe, anotherJwkSet))
        val nonMatchingJwkSet = JWKSet(nonMatchingPrivateJWK)
        assertThrows<NoMatchingKeyException> {
            decryptJsonSerializedJWEtoString(jwe, nonMatchingJwkSet)
        }
    }

    @Test
    fun `Decrypt JWE from Python JWCrypto with AdditionalAuthenticatedData`() {
        val exampleWithAAD: String = PyJWCryptoInteropDecryptTest::class.java.getResource("/pyjwcrypto_ex2_aad.json")
            .readText().trim()
        val data: JSONObject =
            JSONParser(JSONParser.MODE_STRICTEST).parse(exampleWithAAD.toByteArray(Charsets.UTF_8)) as JSONObject
        val privateJWK = JWK.parse(data["private"] as JSONObject)
        val otherPrivateJWK = JWK.parse(data["other_private"] as JSONObject)
        val nonMatchingPrivateJWK = makeJwkRSA().private
        val jwe = data["jwe"] as JSONObject
        val payload = data.getAsString("payload")


        val oneJwkSet = JWKSet(privateJWK)
        Assertions.assertEquals(payload, decryptJsonSerializedJWEtoString(jwe, oneJwkSet))
        val anotherJwkSet = JWKSet(otherPrivateJWK)
        Assertions.assertEquals(payload, decryptJsonSerializedJWEtoString(jwe, anotherJwkSet))
        val nonMatchingJwkSet = JWKSet(nonMatchingPrivateJWK)
        assertThrows<NoMatchingKeyException> {
            decryptJsonSerializedJWEtoString(jwe, nonMatchingJwkSet)
        }
    }

    @Test
    fun `Decrypt commpressed JWE from Python JWCrypto with AdditionalAuthenticatedData`() {
        val exampleWithAAD: String = PyJWCryptoInteropDecryptTest::class.java.getResource("/pyjwcrypto_aad_compressed.json")
            .readText().trim()
        val data: JSONObject =
            JSONParser(JSONParser.MODE_STRICTEST).parse(exampleWithAAD.toByteArray(Charsets.UTF_8)) as JSONObject
        val privateJWK = JWK.parse(data["private"] as JSONObject)
        val otherPrivateJWK = JWK.parse(data["other_private"] as JSONObject)
        val nonMatchingPrivateJWK = makeJwkRSA().private
        val jwe = data["jwe"] as JSONObject
        val payload = data.getAsString("payload")


        val oneJwkSet = JWKSet(privateJWK)
        Assertions.assertEquals(payload, decryptJsonSerializedJWEtoString(jwe, oneJwkSet))
        val anotherJwkSet = JWKSet(otherPrivateJWK)
        Assertions.assertEquals(payload, decryptJsonSerializedJWEtoString(jwe, anotherJwkSet))
        val nonMatchingJwkSet = JWKSet(nonMatchingPrivateJWK)
        assertThrows<NoMatchingKeyException> {
            decryptJsonSerializedJWEtoString(jwe, nonMatchingJwkSet)
        }
    }

}