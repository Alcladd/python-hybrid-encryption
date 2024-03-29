#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from base64 import b64decode
from Crypto.Util.Padding import unpad
import glob

# sk = receiver private key
# Ck = encrypted symmetric key
# k = symmetric key

# use secret/private key to decrypt ck to get symmetric key k
file_in = open("Ck.bin", "rb")
sk = RSA.import_key(open("private.pem").read())
#sk = RSA.import_key(open("private2.pem").read())
Ck = file_in.read(sk.size_in_bytes())
cipher_rsa = PKCS1_OAEP.new(sk)
k = cipher_rsa.decrypt(Ck)
file_in.close()
print()

# CM = ciphertext, M = message
for file in glob.glob("*.txt"):
	try:
		textfile = open(file, "rb")
		CM = b64decode(textfile.read())
		iv = b'\x85\xf2\xf5\x84\xa0y!#t\xdf\xeb\xa2u\x9b\xabp'
		cipher = AES.new(k, AES.MODE_CBC, iv)
		M = unpad(cipher.decrypt(CM), AES.block_size)
		textfile.close()
		textfile = open(file, "w")
		textfile.write(M.decode('utf-8'))
		textfile.close()
	except ValueError:
		print("Decryption is unsuccessful")
		print()
	else:
		print("Decryption is successful")
		print()
		
print("Decryption process has ended")
