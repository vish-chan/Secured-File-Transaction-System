from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random
import socket
import sys
import csv
from base64 import b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

levelFile=open('level.csv','rwb')
userFile=open('user.csv','rwb')
writeuserFile=csv.writer(userFile,delimiter=',')
readuserFile=csv.reader(userFile,delimiter=',')
writelevelFile=csv.writer(levelFile,delimiter=',')
readlevelFile=csv.reader(levelFile,delimiter=',')



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

    
def display_directory(level):
	levelFile.seek(0)
	l=[]
	n=0;
	for row in readlevelFile :
		if int(row[1])<=level:
			l.append(row[0])
	print l
	return l
	
def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = ''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = Random.new().read(bs - len('Salted__'))
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write('Salted__' + salt)
    finished = False
    while not finished:
        chunk = in_file.read(1024 * bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += padding_length * chr(padding_length)
            finished = True
        out_file.write(cipher.encrypt(chunk))

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
    else:
	return False

def server():
	public_key,private_key=generate_RSA()
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("localhost",9999))
	s.listen(10) 
	sc, address = s.accept()#connection accepted
	#id,encrypted(MAC,nonce)
	client_public=sc.recv(204800)
	sc.send(public_key)
	handshake=sc.recv(1024000)
	sign_mac=sc.recv(1024000)
	ins=decrypt_RSA(private_key,handshake)
	id1=ins.split(',')[0]
	nonce=ins.split(',')[1]
	recv_mac=ins.split(',')[2]
	MAC=""
	level=1
	for row in readuserFile :
		if row[0]==id1:
			c_public_key=row[3]
			MAC=row[1]
			level=int(row[2])
			break
	userFile.seek(0)
	l=[]
	print verify_sign(client_public,sign_mac,b64encode(MAC))
	if verify_sign(client_public,sign_mac,b64encode(MAC)) :
		l= display_directory(level)
		sc.send(str(len(l)))
		for i in l:
			sc.send(i+'\n')

	else:
		sc.send('0')
	flag=1
	while (flag):
		encrypted_filename=sc.recv(102400)
		if encrypted_filename == '0':
			break
		sign_filename=sc.recv(124000)
		filename=decrypt_RSA(private_key,encrypted_filename)
		if filename=='0':
			break
		if (verify_sign(client_public,sign_filename,b64encode(filename))):
			if filename in l:
				input_file= open("../file-list/"+filename,'rb')
				temp_file= open("../file-list/"+filename+".temp",'wb')
				encrypt(input_file,temp_file,MAC+nonce)
				_file= open("../file-list/"+filename+".temp",'rb')			
				sc.send(str(_file.read()))
					
	
'''
outFile=open('ep','wb')
inFile=open('abc.png','rb')
tempFile=open('temp','wb')


encrypt(inFile,outFile,"abcde")
outFile2=open('ep','rb')
decrypt(outFile2,tempFile,"abcde")
'''
server()

