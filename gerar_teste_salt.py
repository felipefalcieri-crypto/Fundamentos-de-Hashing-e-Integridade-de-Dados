import hashlib
import os

salt1 = os.urandom(16).hex()
salt2 = os.urandom(16).hex()

h1 = hashlib.sha256(bytes.fromhex(salt1) + b"senha123").hexdigest()
h2 = hashlib.sha256(bytes.fromhex(salt1) + b"qwerty").hexdigest()
h3 = hashlib.sha256(bytes.fromhex(salt2) + b"naoexiste").hexdigest()

with open("hashes_com_salt.txt", "w") as f:
    f.write(salt1 + ":" + h1 + "\n")
    f.write(salt1 + ":" + h2 + "\n")
    f.write(salt2 + ":" + h3 + "\n")

print("Arquivo hashes_com_salt.txt gerado.")
