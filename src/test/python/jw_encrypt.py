from jwcrypto import jwk, jwe
from jwcrypto.common import json_encode, json_decode

print("{")


public_key = jwk.JWK()
private_key = jwk.JWK.generate(kty='RSA', size=2048, kid="key001")
public_key.import_key(**json_decode(private_key.export_public()))

print('"public":')
print(public_key.export_public())
print(',"private":')
print(private_key.export_private())

other_public_key = jwk.JWK()
other_private_key = jwk.JWK.generate(kty='RSA', size=2048, kid="key002")
other_public_key.import_key(**json_decode(other_private_key.export_public()))

print(',"other_public":')
print(other_public_key.export_public())
print(',"other_private":')
print(other_private_key.export_private())

payload = "My Encrypted message"
print(',"payload":"' + payload + '"')
protected_header = {
    #"alg": "RSA-OAEP-256",
    #"enc": "A256CBC-HS512",
    "typ": "JWE",
    "zip": "DEF"
    #"kid": public_key.key_id,
}

aad = "some additional authenticated data"
print(',"aad":"' + aad + '"')


jwetoken = jwe.JWE(payload.encode('utf-8'),
                   aad=aad.encode('utf-8'),
                       #recipient=public_key,
                       protected=protected_header)

jwetoken.add_recipient(public_key, {
    "alg": "RSA-OAEP-256",
    #"enc": "A256CBC-HS512",
    "enc": "A256GCM",
    "kid": public_key.key_id
})

jwetoken.add_recipient(other_public_key, {
    "alg": "RSA-OAEP-256",
    #"enc": "A256CBC-HS512",
    "enc": "A256GCM",
    "kid": other_public_key.key_id
})


enc = jwetoken.serialize()
print(',"jwe":')
print(enc)
print("}")