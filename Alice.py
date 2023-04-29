from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


# Generate a private key for Alice and Bob
alice_private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)

# Generate public keys for Alice
alice_public_key = alice_private_key.public_key()


# Alice sends her public key to Bob
f = open("AlicesKey.txt","w")
f.write(str(alice_public_key))
f.close()


# Alice encrypts a message for Bob
message = b"Hello Bob!"
ciphertext = bob_public_key.encrypt(message,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
print(ciphertext)

# Bob decrypts the message
plaintext = bob_private_key.decrypt(ciphertext,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
print(plaintext)

# Bob encrypts a message for Alice
message = b"Hello Alice!"
ciphertext = alice_public_key.encrypt(message,padding.OAEP(
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
