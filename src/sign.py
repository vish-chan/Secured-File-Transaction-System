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

def sign_data(private_key, data):
    '''
    param: private_key_loc Path to your private key
    param: package Data to be signed
    return: base64 encoded signature
    '''
    from Crypto.PublicKey import RSA 
    from Crypto.Signature import PKCS1_v1_5 
    from Crypto.Hash import SHA256 
    from base64 import b64encode, b64decode 
    key = private_key
    rsakey = RSA.importKey(key) 
    signer = PKCS1_v1_5.new(rsakey) 
    digest = SHA256.new() 
    # It's being assumed the data is base64 encoded, so it's decoded before updating the digest 
    digest.update(b64decode(data)) 
    sign = signer.sign(digest) 
    return b64encode(sign)

def verify_sign(public_key, signature, data):
    '''
    Verifies with a public key from whom the data came that it was indeed 
    signed by their private key
    param: public_key_loc Path to public key
    param: signature String signature to be verified
    return: Boolean. True if the signature is valid; False otherwise. 
    '''
    from Crypto.PublicKey import RSA 
    from Crypto.Signature import PKCS1_v1_5 
    from Crypto.Hash import SHA256 
    from base64 import b64decode 
    pub_key = public_key 
    rsakey = RSA.importKey(pub_key) 
    signer = PKCS1_v1_5.new(rsakey) 
    digest = SHA256.new() 
    # Assumes the data is base64 encoded to begin with
    digest.update(b64decode(data)) 
    if signer.verify(digest, b64decode(signature)):
        return True
    else :
	return False
from base64 import b64encode
a,b=generate_RSA()
print a
print b
pk=sign_data(b,b64encode("tushar"))
print pk
print verify_sign(a,pk,b64encode("Tushar"))
