from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


# Generate a private key for Bob
bob_private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)

# Generate public keys for Bob
bob_public_key = bob_private_key.public_key()

# Get Alice's public key
f = open("AlicesKey.txt","r")
alice_public_key = f.read()



# Bob encrypts a message for Alice
message = b"Hello Alice!"
ciphertext = alice_public_key.encrypt(message, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
print(ciphertext)

# Alice decrypts the message
plaintext = alice_private_key.decrypt(ciphertext,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
print(plaintext)