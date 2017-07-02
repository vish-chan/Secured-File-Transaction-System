#!/usr/bin/python           # This is client.py file
import string
import socket  
import csv
import sys
from uuid import getnode as get_mac
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode
import commands
from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random

def getmac(iface='eth0'):
    return "c8:0a:a9:bc:76:c7"
    mac = commands.getoutput("ifconfig " + iface + "| grep HWaddr | awk '{ print $5 }'")
    print "Using mac for authentication: " + mac
    if len(mac)==17:
        return mac

def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = ''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def decrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = in_file.read(bs)[len('Salted__'):]
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = ord(chunk[-1])
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(chunk)

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
    return False

s = socket.socket()         # Create a socket object
host = socket.gethostname() # Get local machine name

def client():
	
	port = 9999            # Reserve a port for your service.
	public_key,private_key=generate_RSA()
	#print private_key
	s.connect(("localhost", port))
	s.send(public_key)
	server_public=s.recv(102400)
	mac = getmac()[0:]
	sign_mac=sign_data(private_key,b64encode(mac))
	nonce="ggjf"
	id1="tushar"
	data_send=id1+','+nonce+','+mac
	pk=encrypt_RSA(server_public,data_send)
	s.send(pk)
	s.send(sign_mac)	
	n=s.recv(1024)
	x=int(n)
	if (x==0):
		print "Nice Try :)"
		s.close()
		exit(0)
	print("You can securely download the followin files: \n")
	print(s.recv(1024))
		
	print('Choose the file to download.Press 0 to exit.\n')
	while (1):
		data_send = raw_input(' \n')
		if data_send=='0':
			s.send('0')
			break
		sign_filename=sign_data(private_key,b64encode(data_send))
		encrypted_filename=encrypt_RSA(server_public,data_send)
		s.send(encrypted_filename)
		s.send(sign_filename)
		encrypted_file=s.recv(1000*1024*8)
		encrypted_out= open(data_send+".encrypted",'wb')
		encrypted_out.write(encrypted_file)
		fd=open('client_file.csv','ab')
		fdwrite=csv.writer(fd,delimiter=',')
		fdwrite.writerow([data_send+".encrypted",nonce])
		#read_encrypted_out=open(data_send+".encrypted",'rb')
		#decrypted_out=open(data_send+".decrypted",'wb')
		#decrypt(read_encrypted_out,decrypted_out,getmac()[0:]+nonce)
		print ("Downloading complete \n Next File : ")	
	
	s.close()

client()


