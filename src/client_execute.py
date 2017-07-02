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
 
total = len(sys.argv)
 
# Get the arguments list 
cmdargs = str(sys.argv)

def getmac(iface='eth0'):
    mac = commands.getoutput("ifconfig " + iface + "| grep HWaddr | awk '{ print $5 }'")
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

 
fd=open('client_file.csv','rb')
readFile=csv.reader(fd,delimiter=',')
for row in readFile:
	if row[0]== str(sys.argv[1]):
		data_send = row[0]
		nonce = row[1]
		read_encrypted_out=open(data_send,'rb')
		decrypted_out=open(data_send+".decrypted",'wb')
		decrypt(read_encrypted_out,decrypted_out,getmac()[0:]+nonce)
