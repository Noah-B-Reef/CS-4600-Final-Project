from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Generate a private key for Alice and Bob
alice_private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
pem_private_key_alice = alice_private_key.private_bytes(encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

bob_private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
pem_private_key_bob = bob_private_key.private_bytes(encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

# Generate public keys for Alice and Bob
alice_public_key = alice_private_key.public_key()
pem_public_key_alice = alice_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

bob_public_key = bob_private_key.public_key()
pem_public_key_bob = bob_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    

# Alice sends her public key to Bob
with open("AlicePublicKey.txt", 'wb') as pem_out:
        pem_out.write(pem_public_key_alice)
        pem_out.close()

# Saves Alice's private key to a file
with open("AlicePrivateKey.txt", 'wb') as pem_out:
        pem_out.write(pem_private_key_alice)
        pem_out.close()

# Bob sends his public key to Alice
with open("BobPublicKey.txt", 'wb') as pem_out:
        pem_out.write(pem_public_key_bob)
        pem_out.close()

# Bob saves his private key to a file
with open("BobPrivateKey.txt", 'wb') as pem_out:
        pem_out.write(pem_private_key_bob)
        pem_out.close()


