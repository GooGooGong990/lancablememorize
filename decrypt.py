##### PERSONAL KEY TO DECRYPTION KEY WITH RSA PRIVATE KEY #####

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

KEY = b"""-----BEGIN RSA PRIVATE KEY-----
PRIVATE KEY
-----END RSA PRIVATE KEY-----"""

personalKey = ""

privateKey = RSA.import_key(KEY)
cipher = PKCS1_OAEP.new(privateKey)

decodedKey = base64.b64decode(personalKey)
decriptionKey = cipher.decrypt(decodedKey)

print("DECRIPTION KEY: ", decriptionKey.decode())
