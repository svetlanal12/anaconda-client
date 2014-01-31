'''
Created on Jan 27, 2014

@author: sean
'''

# from binstar.core import database as db
from Crypto.PublicKey import RSA
from binstar_client.utils import appdirs, bool_input, get_config
from os.path import join, isfile
import Crypto.Hash.MD5 as MD5
import Crypto.Util.number as CUN
import base64
import getpass
import os
import sys
import urllib

import logging
logger = logging.getLogger('binstar.keys')


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



def create_public_key(private_key, passphrase):
    key = RSA.importKey(private_key, passphrase=passphrase)
    return key.publickey().exportKey()

def get_public_key(bs):
    
    
    config = get_config()
    url = config.get('url', 'https://api.binstar.org')
    user = bs.user()
    data_dir = appdirs.user_data_dir('binstar', 'ContinuumIO')
    public_keyfile = join(data_dir, '%s-%s-public.pem' % (urllib.quote_plus(url), user['login']))
    logger.debug("public_keyfile: %s", public_keyfile)
    
    public_key = bs.get_public_key()
    if not isfile(public_keyfile):
        with open(public_keyfile, 'w') as fd:
            fd.write(public_key)
            return public_key
    
    with open(public_keyfile) as fd:
        public_key = fd.read()
        return public_key

def get_public_keyfile(user):
    data_dir = appdirs.user_data_dir('binstar', 'ContinuumIO')
    config = get_config()
    url = config.get('url', 'https://api.binstar.org')
    return join(data_dir, '%s-%s-public.pem' % (urllib.quote_plus(url), user['login']))

def get_private_keyfile(user):
    data_dir = appdirs.user_data_dir('binstar', 'ContinuumIO')
    config = get_config()
    url = config.get('url', 'https://api.binstar.org')
    return join(data_dir, '%s-%s-private.pem' % (urllib.quote_plus(url), user['login']))

def remove_keypair(bs):
    user = bs.user()
    private_keyfile = get_private_keyfile(user)
    public_keyfile = get_public_keyfile(user)
    if isfile(private_keyfile):
        os.unlink(private_keyfile)
    if isfile(public_keyfile):
        os.unlink(public_keyfile)

def get_keypair(bs):

    user = bs.user()
    private_keyfile = get_private_keyfile(user)
    public_keyfile = get_public_keyfile(user)
    
    if not isfile(private_keyfile):
        generate = bool_input('You do not have a private keyfile would you like to generate one now?')
        if not generate:
            raise SystemExit('goodby')
        
        passphrase = ''
        while not passphrase:
            passphrase = getpass.getpass('Please enter a passphrase for your private key: ', stream=sys.stderr)
            if not passphrase:
                print('passphrase may not be empty')
        
        passphrase_confirm = getpass.getpass('Please confirm your passphrase: ', stream=sys.stderr)
        if passphrase_confirm != passphrase:
            raise SystemExit('passphrase does not match')
        
        private_key, public_key = generate_keypair(passphrase)
        open(private_keyfile, 'w').write(private_key)
        open(public_keyfile, 'w').write(public_key)
    else:
        private_key = open(private_keyfile).read()
        public_key = open(public_keyfile).read()
    
#     your_public_key_in_binstar = bs.get_public_key()
#     if not your_public_key_in_binstar:
    bs.set_public_key(public_key)
    
    return open(private_keyfile).read(), open(public_keyfile).read()




def test_passphrase(private_key, passphrase):
    try:
        RSA.importKey(private_key, passphrase=passphrase)
        return True
    except ValueError:
        return False
    
    
        


