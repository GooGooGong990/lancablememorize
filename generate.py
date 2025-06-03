##### GENERATE RSA KEY PAIR ####

from Crypto.PublicKey import RSA

key = RSA.generate(2048)

private = key.export_key()
with open("private.pem", "wb") as f:
    f.write(private)

public = key.publickey().export_key()
with open("public.pem", "wb") as f:
    f.write(public)
