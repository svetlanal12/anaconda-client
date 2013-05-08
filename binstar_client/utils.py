'''
Created on Apr 29, 2013

@author: sean
'''

from hashlib import md5
from keyring import get_keyring
from os.path import exists, join, dirname, expanduser
import appdirs
import base64
import getpass
import os
import urlparse
import yaml

class UserError(Exception):
    pass

class PackageSpec(object):
    def __init__(self, user, package, version, basename, attrs):
        self._user = user
        self._package = package
        self._version = version
        self._basename = basename
        self.attrs = attrs
    
    @property
    def user(self):
        if self._user is None:
            raise UserError('user not given')
        return self._user

    @property
    def package(self):
        if self._package is None:
            raise UserError('package not given in spec')
        return self._package

    @property
    def version(self):
        if self._version is None:
            raise UserError('version not given in spec')
        return self._version

    @property
    def basename(self):
        if self._basename is None:
            raise UserError('basename not given in spec')
        return self._basename
        
def parse_specs(spec):
    user = spec
    package = version = basename = None
    attrs = {}
    if '/' in user:
        user, package = user.split('/',1)
    if package and '/' in package:
        package, version = package.split('/', 1)
        
    if version and '/' in version:
        version, basename = version.split('/', 1)
    
    if basename and '?' in basename:
        basename, qsl = basename.rsplit('?', 1)
        attrs = dict(urlparse.parse_qsl(qsl))
    
    return PackageSpec(user, package, version, basename, attrs)

def get_binstar():
    from binstar_client import Binstar
    
    kr = get_keyring()
    token = kr.get_password('binstar-token', getpass.getuser())
    url = get_config().get('url', 'https://api.binstar.org')
    
    return Binstar(token, domain=url,)

def load_config(config_file):
    if exists(config_file):
        with open(config_file) as fd:
            data = yaml.load(fd)
            if data: 
                return data
    
    return {}

SITE_CONFIG = join(appdirs.site_data_dir('binstar'), 'config.yaml')
USER_CONFIG = join(appdirs.user_data_dir('binstar'), 'config.yaml')
def get_config(user=True, site=True):
    
    config = {}
    if site:
        config.update(load_config(SITE_CONFIG))
    if user:
        config.update(load_config(USER_CONFIG))
        
    return config
    
def set_config(data, user=True):
    
    config_file = USER_CONFIG if user else SITE_CONFIG
    
    data_dir = dirname(config_file)
    if not exists(data_dir):
        os.makedirs(data_dir)
    
    with open(config_file, 'w') as fd:
        yaml.dump(data, fd)



def compute_hash(fp, buf_size=8192, size=None, hash_algorithm=md5):
    hash_obj = hash_algorithm()
    spos = fp.tell()
    if size and size < buf_size:
        s = fp.read(size)
    else:
        s = fp.read(buf_size)
    while s:
        hash_obj.update(s)
        if size:
            size -= len(s)
            if size <= 0:
                break
        if size and size < buf_size:
            s = fp.read(size)
        else:
            s = fp.read(buf_size)
    hex_digest = hash_obj.hexdigest()
    base64_digest = base64.encodestring(hash_obj.digest())
    if base64_digest[-1] == '\n':
        base64_digest = base64_digest[0:-1]
    # data_size based on bytes read.
    data_size = fp.tell() - spos
    fp.seek(spos)
    return (hex_digest, base64_digest, data_size)