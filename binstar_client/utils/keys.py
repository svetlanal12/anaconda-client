'''
Created on Jan 27, 2014

@author: sean
'''

# from binstar.core import database as db
import Crypto.Hash.MD5 as MD5
from Crypto.PublicKey import RSA
import Crypto.Util.number as CUN
import os
import base64

def unpack_bigint(b):
    b = bytearray(b)  # in case you're passing in a bytes/str
    return sum((1 << (bi * 8)) * bb for (bi, bb) in enumerate(b))

def pack_bigint(i):
    b = bytearray()                                         
    while i:                                                   
        b.append(i & 0xFF)
        i >>= 8
    return bytes(b)

def md5_hash(plaintext):
    return MD5.new(plaintext).digest()

def verify(public_key, plaintext, sig):
    md5 = md5_hash(plaintext)
    return verify_hash(public_key, md5, sig)
 
def verify_hash(public_key, md5, sig):
    bsig = base64.b64decode(sig)
    pub = RSA.importKey(public_key)
    signature = (unpack_bigint(bsig),)
    return pub.verify(md5, signature) 

def sign(private_key, plaintext, passphrase):
    md5 = md5_hash(plaintext)
    return sign_hash(private_key, md5, passphrase)

def sign_hash(private_key, md5, passphrase):
    key = RSA.importKey(private_key, passphrase=passphrase)
    K = CUN.getRandomNumber(128, os.urandom)
    signature, = key.sign(md5, K)
    
    return base64.b64encode(pack_bigint(signature))

def generate_private_key(passphrase):
    key = RSA.generate(1024 * 2)
    return key.exportKey(passphrase=passphrase)

def generate_keypair(passphrase):
    key = RSA.generate(1024 * 2)
    return key.exportKey(passphrase=passphrase), key.publickey().exportKey()

# def veryify_user(user, user_to_trust, signature):
#     public_key = db.trust.get_public_key(user)
#     value = db.trust.get_public_key(user_to_trust)
#     return verify(public_key, value, signature)


def create_public_key(private_key, passphrase):
    key = RSA.importKey(private_key, passphrase=passphrase)
    return key.publickey().exportKey()


