# Import required libraries
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import os

# What Bob Sends to Alice
msg = []

### Bobs Plaintext Message ###
f = open("BobsPlaintextMessage.txt","r")
message = f.read()
f.close()

#### KEY GENERATION ####


# Generate AES key for Bob
bob_aes_key = os.urandom(32)
iv = b'0000000000000000'

#### KEY EXCHANGE ####

# Get Alice's public key
with open("AlicePublicKey.txt", 'rb') as pem_in:
    pemlines = pem_in.read()

alice_public_key = load_pem_public_key(pemlines,default_backend())

# Encrypt Bob's Message with AES
cipher = Cipher(algorithms.AES(bob_aes_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(bytes(message, 'ascii')*16) + encryptor.finalize()
msg.append(ciphertext)

# Encrypt AES key with Alice's public key
ciphertext2 = alice_public_key.encrypt(bob_aes_key,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
msg.append(ciphertext2)

# Create MAC
h = hmac.HMAC(b"test key",hashes.SHA256(), backend=default_backend())
h.update(ciphertext)
signtaure = h.finalize()
msg.append(signtaure)

# Send Message to Alice

f = open("Transmitted_Data.txt","wb")
for i in msg:
    f.write(i)
f.close()