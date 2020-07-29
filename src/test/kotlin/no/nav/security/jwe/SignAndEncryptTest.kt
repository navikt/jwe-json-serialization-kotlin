package no.nav.security.jwe

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm.RS256
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jwk.JWKSet
import net.minidev.json.JSONObject
import net.minidev.json.parser.JSONParser
import no.nav.security.jwe.testsupport.makeJwkRSA
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * Test/Demo of signed (compact) JWS wrapped in JSON Serialized JWE.
 * (Compact JWS is sufficient when there is only one signature/signer)
 * Order should be JWE(JWS(payload)), not the other way around.
 * Ref: https://tools.ietf.org/html/rfc7519#section-11.2 ("Signing and Encryption Order")
 */
class SignAndEncryptTest {

    private fun String.asJSONObject(): JSONObject =
        JSONParser(JSONParser.MODE_STRICTEST).parse(this.toByteArray(Charsets.UTF_8)) as JSONObject

    val someJsonPayload = """
        {
            "personId" : "123",
            "verified" : true
        }
    """.trimIndent().asJSONObject()

    @Test
    fun `standard compact JWS wrapped in JSON serialized JWE`() {
        val signingKey = makeJwkRSA()
        val signingAlgorithm = RS256
        val recipientEncryptionKey = makeJwkRSA()
        val anotherRecipientEncryptionKey = makeJwkRSA()

        val payloadToSign = Payload(someJsonPayload)
        val jws = JWSObject(
            JWSHeader.Builder(signingAlgorithm)
                .keyID(signingKey.private.keyID)
                .build(), payloadToSign
        )
        val signer = DefaultJWSSignerFactory().createJWSSigner(signingKey.private, signingAlgorithm)
        jws.sign(signer)
        assertTrue(jws.state == JWSObject.State.SIGNED)
        val signedJWSAsString = jws.serialize()

        println(signedJWSAsString)

        val jwe: String = encryptAsJsonSerializedJWE(
            plaintext = signedJWSAsString.toByteArray(Charsets.US_ASCII),
            recipientKeys = JWKSet(listOf(recipientEncryptionKey.public, anotherRecipientEncryptionKey.public))
        ).toJSONString()

        decryptAndVerify(
            encryptedJWS = jwe,
            decryptionKeys = JWKSet(recipientEncryptionKey.private),
            trustedSigners = JWKSet(signingKey.public)
        ).apply {
            assertEquals(signingKey.public.keyID, this.verifiedSignedByKeyId)
            assertEquals(someJsonPayload, this.payload.asJSONObject())
        }

        decryptAndVerify(
            encryptedJWS = jwe,
            decryptionKeys = JWKSet(anotherRecipientEncryptionKey.private),
            trustedSigners = JWKSet(signingKey.public)
        ).apply {
            assertEquals(signingKey.public.keyID, this.verifiedSignedByKeyId)
            assertEquals(someJsonPayload, this.payload.asJSONObject())
        }

        assertThrows<JOSEException> {
            decryptAndVerify(
                encryptedJWS = jwe,
                // matching keyId, but wrong decryption-key:
                decryptionKeys = JWKSet(makeJwkRSA(keyId = recipientEncryptionKey.private.keyID).private),
                trustedSigners = JWKSet(signingKey.public)
            )
        }

        assertThrows<SignatureVerificationException> {
            decryptAndVerify(
                encryptedJWS = jwe,
                decryptionKeys = JWKSet(recipientEncryptionKey.private),
                // matching keyId, but wrong verification-key:
                trustedSigners = JWKSet(makeJwkRSA(keyId = signingKey.public.keyID).public)
            )
        }
    }

    private data class DecryptAndVerifyResult(
        val payload: String,
        val verifiedSignedByKeyId: String
    )

    private class SignatureVerificationException : RuntimeException("Signature verification failed!")

    private fun decryptAndVerify(
        encryptedJWS: String,
        decryptionKeys: JWKSet,
        trustedSigners: JWKSet
    ): DecryptAndVerifyResult {
        val decryptedJWEPayload = decryptJsonSerializedJWEtoString(encryptedJWS.asJSONObject(), decryptionKeys)
        val jws = JWSObject.parse(decryptedJWEPayload)
        if (trustedSigners.getKeyByKeyId(jws.header.keyID) == null) throw RuntimeException("Unrecognized signers keyId")
        val verifier = DefaultJWSVerifierFactory().createJWSVerifier(
            jws.header,
            trustedSigners.getKeyByKeyId(jws.header.keyID).toPublicJWK().toRSAKey().toRSAPublicKey()
        )
        val ok = jws.verify(verifier)
        if (!ok) throw SignatureVerificationException()
        return DecryptAndVerifyResult(
            payload = jws.payload.toString(),
            verifiedSignedByKeyId = jws.header.keyID
        )
    }

}