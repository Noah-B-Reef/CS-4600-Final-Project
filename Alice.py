from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import math 

# Alice reads her private key
with open("AlicePrivateKey.txt", 'rb') as pem_in:
    alice_private_key = load_pem_private_key(pem_in.read(),password=None,backend=default_backend())

# Alice reads Bobs Message
with open("Transmitted_Data.txt", 'rb') as pem_in:
    ciphertext = pem_in.read()

length_ciphertext = len(ciphertext[0:len(ciphertext)-32-256])

# Alice verifies the MAC
h = hmac.HMAC(b"test key", hashes.SHA256(), backend=default_backend())
h.update(ciphertext[0:length_ciphertext])
h.verify(ciphertext[length_ciphertext + 256::])
print("MAC Verified")

# Alice decrypts the AES key
bob_aes_key = alice_private_key.decrypt(ciphertext[length_ciphertext:length_ciphertext + 256],padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

# Alice decrypts the message
iv = b'0000000000000000'
cipher = Cipher(algorithms.AES(bob_aes_key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext[0:length_ciphertext]) + decryptor.finalize()
length = math.floor(len(plaintext)/16) 
print("Plaintext: " + str(plaintext[0:length]))


