package no.nav.security.jwe

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.crypto.impl.AESGCM
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider
import com.nimbusds.jose.crypto.impl.RSAKeyUtils
import com.nimbusds.jose.crypto.impl.RSA_OAEP_256
import com.nimbusds.jose.jca.JWEJCAContext
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.Container
import net.minidev.json.JSONArray
import net.minidev.json.JSONObject
import net.minidev.json.parser.JSONParser
import java.security.Provider
import javax.crypto.SecretKey

class NoMatchingKeyException : RuntimeException("Found no mathing key")

fun encryptAsJsonSerializedJWE(
    plaintext: ByteArray,
    recipientKeys: JWKSet,
    additionalAuthenticatedData: ByteArray? = null
): JSONObject {
    val jwe = JSONObject()
    val protectedHeader = JSONObject().apply {
        this["alg"] = "RSA-OAEP-256"
        this["enc"] = "A256GCM"
    }
    jwe["protected"] = Base64URL.encode(protectedHeader.toJSONString().toByteArray(Charsets.UTF_8)).toString()
    if (additionalAuthenticatedData != null) {
        jwe["aad"] = Base64URL.encode(additionalAuthenticatedData).toString()
    }

    val jcaContext = JWEJCAContext()

    val cek: SecretKey = ContentCryptoProvider.generateCEK(EncryptionMethod.A256GCM, jcaContext.getSecureRandom())
    val ivContainer = Container(AESGCM.generateIV(jcaContext.getSecureRandom()))
    val authCipherText = AESGCM.encrypt(cek, ivContainer, plaintext, jwe.getAdditionalAuthenticatedData(), jcaContext.provider)
    jwe["iv"] = Base64URL.encode(ivContainer.get()).toString()
    jwe["ciphertext"] = Base64URL.encode(authCipherText.cipherText).toString()
    jwe["tag"] = Base64URL.encode(authCipherText.authenticationTag).toString()

    val recipientsList = recipientKeys.keys.map { recipientJWK ->
        require(recipientJWK is RSAKey) { "Only RSA supported yet" }
        val encryptedKey:String = Base64URL.encode(
            RSA_OAEP_256.encryptCEK(
                recipientJWK.toRSAPublicKey(),
                cek,
                jcaContext.getKeyEncryptionProvider()
            )
        ).toString()
        val kid:String = recipientJWK.keyID
        JSONObject().apply {
            this["encrypted_key"] = encryptedKey
            this["header"] = JSONObject().apply {
                this["kid"] = kid
            }
        }
    }
    jwe["recipients"] = JSONArray().apply { recipientsList.forEach { this.appendElement(it) } }
    return jwe
}

fun decryptJsonSerializedJWE(jwe: JSONObject, jwkSet: JWKSet): String {
    val cipherText = Base64URL(jwe.getAsString("ciphertext"))
    val iv = Base64URL(jwe.getAsString("iv"))
    val protectedHeaderBase64String: String = jwe.getAsString("protected")
    val protectedHeaderBytes: ByteArray = Base64URL(protectedHeaderBase64String).decode()
    val protectedHeader: JSONObject = JSONParser(JSONParser.MODE_STRICTEST).parse(protectedHeaderBytes) as JSONObject
    val authTag = Base64URL(jwe.getAsString("tag"))
    (jwe["recipients"] as JSONArray).forEach { recipientUntyped ->
        val recipient = recipientUntyped as JSONObject
        val recipientUnprotectedHeader = recipient["header"] as JSONObject
        val recipientHeader = JSONObject(protectedHeader).apply {
            // Make copy of protected header and merge recipient header into it.
            // (If field exists in both, then protected header wins).
            merge(recipientUnprotectedHeader)
        }
        val kid = recipientHeader.getAsString("kid")
        val key: JWK? = jwkSet.getKeyByKeyId(kid)
        if (key != null) {
            val alg = recipientHeader.getAsString("alg")
            val enc = recipientHeader.getAsString("enc")
            val encryptedKey = Base64URL(recipient.getAsString("encrypted_key"))
            require(alg == "RSA-OAEP-256") { "Only RSA-OAEP-256 supported yet" }
            /* NB: If introducing RSA1_5 (though there should be no need) remember protection against MMA attack.
                    Ref: /nimbus-jose-jwt-8.19-sources.jar!/com/nimbusds/jose/crypto/RSADecrypter.java:251
             */
            require(enc == "A256GCM") { "Only A256GCM supported yet" }
            val rsaPrivateKey = RSAKeyUtils.toRSAPrivateKey(key as RSAKey)
            val securityProvider: Provider? = null
            val cek = RSA_OAEP_256.decryptCEK(rsaPrivateKey, encryptedKey.decode(), securityProvider)
            val plainText = AESGCM.decrypt(
                cek,
                iv.decode(),
                cipherText.decode(),
                jwe.getAdditionalAuthenticatedData(),
                authTag.decode(),
                securityProvider
            )
            return String(plainText, Charsets.UTF_8)
        }
    }
    throw NoMatchingKeyException()
}

private fun JSONObject.getAdditionalAuthenticatedData(): ByteArray {
    val protectedHeaderBase64String: String = this.getAsString("protected")
    val aadBase64String: String? = this.getAsString("aad")
    return if (aadBase64String == null) {
        /*  Ref: https://tools.ietf.org/html/rfc7516
            A.1.5.  Additional Authenticated Data
            Let the Additional Authenticated Data encryption parameter be ASCII(BASE64URL(UTF8(JWE Protected Header))).
         */
        protectedHeaderBase64String.toByteArray(Charsets.US_ASCII)
    } else {
        /*  Ref: https://tools.ietf.org/html/rfc7516
            14.  Let the Additional Authenticated Data encryption parameter be
                ASCII(Encoded Protected Header).  However, if a JWE AAD value is
                present (which can only be the case when using the JWE JSON
                Serialization), instead let the Additional Authenticated Data
                encryption parameter be ASCII(Encoded Protected Header || '.' ||
                BASE64URL(JWE AAD)).
         */
        ("$protectedHeaderBase64String.$aadBase64String").toByteArray(Charsets.US_ASCII)
    }
}
