from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

message = input("Enter a string to be encrypted: ")

bytestr = message.encode()#Convert string to byte string 

key,ct,iv = encrypt(byte_string)#Encrypt the message

print(f"encrypted message: {ct}")

decrypted_message = decrypt(key,ct,iv)#Decrypt the message

print(f"The decrypted message: {decrypted_message}")

    
        
def encrypt(message):#encrypt message
    
    backend = default_backend()
    key = os.urandom(32)#generate key
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)#generating chiper
    encryptor = cipher.encryptor() 
    ct = encryptor.update(message) + encryptor.finalize()#encrypting message
    return key,ct,iv

def decrypt(key,ct,iv):#decrypting encrypted text
    
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)#generating chiper
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ct) + decryptor.finalize()#decypting encrypted text
    return decrypted_message.decode()
