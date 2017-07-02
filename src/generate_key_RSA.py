import csv
import sys
private_file=open('private','wb')
public_file=open('public','wb')
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_RSA(bits=2048):
	'''
	Generate an RSA keypair with an exponent of 65537 in PEM format
	param: bits The key length in bits
	Return private key and public key
	'''
	
	new_key = RSA.generate(bits)
	public_key = new_key.publickey().exportKey("PEM")
	private_key = new_key.exportKey("PEM")
	#private_file.write(private_key)
	#public_file.write(public_key)
	return public_key,private_key

def encrypt_RSA(public_key, message):

    '''
    param: public_key_loc Path to public key
    param: message String to be encrypted
    return base64 encoded encrypted string
    '''
    
    rsakey = RSA.importKey(public_key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted = rsakey.encrypt(message)
    return encrypted.encode('base64')
    

def decrypt_RSA(private_key, package):
    '''
    param: public_key_loc Path to your private key
    param: package String to be decrypted
    return decrypted string
    '''
    from Crypto.PublicKey import RSA 
    from Crypto.Cipher import PKCS1_OAEP 
    from base64 import b64decode 
    #key = open(private_key_loc, "rb").read() 
    rsakey = RSA.importKey(private_key) 
    rsakey = PKCS1_OAEP.new(rsakey) 
    decrypted = rsakey.decrypt(b64decode(package)) 
    return decrypted

a,b=generate_RSA()
print a
print b

pk=encrypt_RSA(a,"FUCK YOU")
print(decrypt_RSA(b,pk))
pk=encrypt_RSA(b,"FUCK YOU")
print(decrypt_RSA(a,pk))

