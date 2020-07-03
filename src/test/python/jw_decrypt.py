from jwcrypto import jwk, jwe
from jwcrypto.common import json_encode, json_decode
import sys

jwkString = sys.argv[1]
jweString = sys.argv[2]

private_key = jwk.JWK.from_json(jwkString)
jwetoken = jwe.JWE()
jwetoken.deserialize(jweString, key = private_key)
print(jwetoken.payload.decode("utf-8"))
