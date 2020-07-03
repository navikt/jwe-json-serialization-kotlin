package no.nav.security.jwe.testsupport

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import javax.crypto.KeyGenerator

fun makeJwkAES(keyId: String = UUID.randomUUID().toString()): JWK {
    val keygen = KeyGenerator.getInstance("AES")
    keygen.init(256)
    val key = keygen.generateKey()
    val keyBase64 = Base64URL.encode(key.encoded).toString()
    val jwkString = """
         {"kty":"oct",
          "kid":"$keyId",
          "alg":"A256KW",
          "k":"$keyBase64"}
      """.trimIndent()

    return JWK.parse(jwkString)
}

data class JWKPair(
    val public: RSAKey,
    val private: RSAKey
)

fun makeJwkRSA(keyId: String = UUID.randomUUID().toString()): JWKPair {
    val keygen = KeyPairGenerator.getInstance("RSA")
    keygen.initialize(2048)
    val keypair = keygen.generateKeyPair()
    val priv = keypair.private as RSAPrivateKey
    val pub = keypair.public as RSAPublicKey
    val pubBuilder = RSAKey.Builder(pub)
    pubBuilder.keyID(keyId)
    val jwkPub = pubBuilder.build()
    val privBuilder = RSAKey.Builder(pub)
    privBuilder.keyID(keyId)
    privBuilder.privateKey(priv)
    val jwkPriv = privBuilder.build()

    return JWKPair(public = jwkPub.toPublicJWK(), private = jwkPriv)
}
