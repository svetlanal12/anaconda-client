'''
Created on Jan 28, 2014

@author: sean
'''
from __future__ import unicode_literals
from pip.baseparser import ConfigOptionParser
from argparse import ArgumentParser

from os.path import expanduser, join, split, isfile, basename
from os import listdir
from urlparse import urlparse, unquote
from binstar_client.utils import get_binstar, compute_hash, appdirs, bool_input, \
    keys
import re
import getpass
import sys
from binstar_client.utils.keys import generate_keypair

red = lambda text: '\033[91m' + text + '\033[0m'
green = lambda text: '\033[92m' + text + '\033[0m'
orange = lambda text: '\033[93m' + text + '\033[0m'

green_check = green('\u2611')
red_x = red('\u2612')
orange_ = orange('\u2610')

pat = re.compile('^(/pypi)?/(?P<username>\w+)/simple/(?P<package>\w+)/(?P<version>[\w.-]+)/(?P<basename>[\w.-]+)$')

def iter_cache_dir(download_cache):
    for item in  listdir(download_cache):
        if item.endswith('.content-type'):
            continue
        filename = join(download_cache, item)
        with open(filename) as fp:
            md5 = compute_hash(fp)[0]
        uri = unquote(item)
        url = urlparse(uri)
        url.original = uri
        yield filename, md5, url
        

def default_download_cache():
    pip_parser = ConfigOptionParser(name='binstar')
    return expanduser(pip_parser.config.get('global', 'download_cache'))

def list_cache(args):
    
    bs = get_binstar()
    public_key = get_public_key(bs)
    binstar_netloc = urlparse(bs.domain).netloc
    all_valid = True 
    all_signed = True 
    print 'listing files from', args.download_cache
    for filename, md5, url in iter_cache_dir(args.download_cache):
        
        if url.netloc == binstar_netloc:
            
            match = pat.match(url.path)
            
            if not match:
                # TODO: warning
                continue
            
            attrs = match.groupdict()
            dist = bs.distribution(attrs['username'], attrs['package'], attrs['version'], attrs['basename'])
            signatures = bs.get_dist_signatures(attrs['username'], attrs['package'], attrs['version'], attrs['basename'])
            
            your_signature = signatures['your_signature']
            if your_signature and args.type == 'unsigned': continue
            elif not your_signature and args.type == 'signed': continue
            
            if dist['md5'] != md5:
                print '%s %s (from %s) %s' % (red_x, basename(url.path), url.netloc, red('did not pass md5 checksum'))
                all_valid = False
            elif your_signature:
                signature = your_signature['signature']
                if not keys.verify_hash(public_key, md5.decode('hex'), signature):
                    print '%s %s (from %s) %s' % (red_x, basename(url.path), url.netloc, red('did not pass signature validation'))
                    all_valid = False
                else:
                    print '%s %s (from %s)' % (green_check, basename(url.path), url.netloc)
            else:
                print '%s %s (from %s) %s' % (orange_, basename(url.path), url.netloc, 'not signed')
                all_signed = False
            
        else:
            signatures = bs.get_url_signatures(url.original)
            your_signature = signatures['your_signature']
            if your_signature and args.type == 'unsigned': continue
            elif not your_signature and args.type == 'signed': continue

            if your_signature:
                signature = your_signature['signature']
                if not keys.verify_hash(public_key, md5.decode('hex'), signature):
                    print '%s %s (from %s) %s' % (red_x, basename(url.path), url.netloc, red('did not pass signature validation'))
                    all_valid = False
                else:
                    print '%s %s (from %s)' % (green_check, basename(url.path), url.netloc)
            else:
                print '%s %s (from %s) %s' % (orange_, basename(url.path), url.netloc, 'not signed')
                all_signed = False
                
        if args.verbose:
            count = len(signatures['signatures'])
            if your_signature:
                print '  | You and %i people have signed this package' % (count - 1)
            else:
                print '  | %i people have signed this package' % count
    
        if args.fail_fast:
            if not all_valid:
                print red('Error: Detected invalid packages')
                sys.exit(1)
            if args.fail_if_unsigned and not all_signed:
                print red('Error: Detected unsigned packages')
                sys.exit(1)
                
    if not all_valid:
        print red('Error: Detected invalid packages')
        sys.exit(1)
    if args.fail_if_unsigned and not all_signed:
        print red('Error: Detected unsigned packages')
        sys.exit(1)
    if not all_signed:
        print orange('Warning: Detected unsigned packages')


def get_public_key(bs):
    data_dir = appdirs.user_data_dir('binstar', 'ContinuumIO')
    public_keyfile = join(data_dir, 'public.pem')
    if not isfile(public_keyfile):
        public_key = bs.get_public_key()
        with open(public_keyfile, 'w') as fd:
            fd.write(public_key)
            return public_key
    
    with open(public_keyfile) as fd:
        public_key = fd.read()
        return public_key
    
    
def get_keypair(bs):
    data_dir = appdirs.user_data_dir('binstar', 'ContinuumIO')
    private_keyfile = join(data_dir, 'private.pem')
    public_keyfile = join(data_dir, 'public.pem')
    
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
    
    your_public_key_in_binstar = bs.get_public_key()
    if not your_public_key_in_binstar:
        bs.set_public_key(public_key)
    
    return open(private_keyfile).read(), open(public_keyfile).read()

def sign_cache(args):
    bs = get_binstar()
    private_key, public_key = get_keypair(bs)
    
    binstar_netloc = urlparse(bs.domain).netloc
    
    passphrase = getpass.getpass('Please enter your passphrase to sign these packages: ', stream=sys.stderr)
    for filename, md5, url in iter_cache_dir(args.download_cache):
        
        if url.netloc == binstar_netloc:
            print '- binstar', url.path,
            match = pat.match(url.path)
            if not match:
                print
                raise Exception('Can not match path')
            
            attrs = match.groupdict()
            dist = bs.distribution(attrs['username'], attrs['package'], attrs['version'], attrs['basename'])
            
            if dist['md5'] != md5:
                print "  + md5", md5,
                raise Exception('the md5 of this file does not match!!')

            signatures = bs.get_dist_signatures(attrs['username'], attrs['package'], attrs['version'], attrs['basename'])
            
            if signatures['your_signature']:
                print '(signed)'
                continue
            else:
                signature = keys.sign_hash(private_key, md5.decode('hex'), passphrase)
                print '... Adding signature'
                bs.add_dist_signature(attrs['username'], attrs['package'], attrs['version'], attrs['basename'],
                                      signature)
            
        else:
            
            print '- external', url.original,
            signatures = bs.get_url_signatures(url.original)
            if signatures['your_signature']:
                print '(signed)'
                continue
            else:
                signature = keys.sign_hash(private_key, md5.decode('hex'), passphrase)
                print '... Adding signature'
                bs.add_url_signature(url.original, signature)

            


def main():
    
    
    
    parser = ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--download-cache', default=default_download_cache())
    sp = parser.add_subparsers()
    
    listp = sp.add_parser('list')
    listp.add_argument('-o', '--fail-if-unsigned',
                       action='store_true', 
                       help='Return non zero exit status if not all packages are signed (not enabled by default)')
    listp.add_argument('-f', '--fail-fast',
                       action='store_true', 
                       help='Return non zero exit status on first failure')
    g = listp.add_mutually_exclusive_group()
    g.add_argument('-u', '--untrusted',
                       dest='type', action='store_const', const='unsigned',
                       help='list all packages you have not explicitly trusted')
    g.add_argument('-t', '--trusted',
                       dest='type', action='store_const', const='signed',
                       help='list all packages you have explicitly trusted')
    g.add_argument('-a', '--all',
                       dest='type', action='store_const', const='all',
                       help='list all packages', default='all')
    
    listp.set_defaults(func=list_cache)

    signp = sp.add_parser('sign')
    signp.set_defaults(func=sign_cache)
    
    args = parser.parse_args()
    args.func(args)
        

if __name__ == '__main__':
    main()
