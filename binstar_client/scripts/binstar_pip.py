'''
Created on Jan 28, 2014

@author: sean
'''
from __future__ import unicode_literals
from argparse import ArgumentParser, FileType
from binstar_client import __version__ as version, errors
from binstar_client.utils import  get_binstar, compute_hash, \
    bool_input, keys, wrap_main, setup_logging, get_config
from binstar_client.utils.keys import get_keypair, \
    get_public_key
from os.path import expanduser, basename, join
from pip.baseparser import ConfigOptionParser
from urlparse import urlparse, unquote
import getpass
import logging
import re
import sys
import pkg_resources
from binstar_client.commands.collection import collection_spec
from subprocess import check_call, CalledProcessError
from os import listdir


grey = lambda text: '\033[90m' + text + '\033[0m'
red = lambda text: '\033[91m' + text + '\033[0m'
green = lambda text: '\033[92m' + text + '\033[0m'
orange = lambda text: '\033[93m' + text + '\033[0m'

green_check = green('\u2611')
red_x = red('\u2612')
orange_ = orange('\u2610')

pat = re.compile('(?P<username>[\w.-]+)/simple/(?P<package>[\w.-]+)/(?P<version>[\w.-]+)/(?P<basename>[\w.-]+)$')

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
    
    try:
        public_key = get_public_key(bs)
        
        logger.debug("Your public Key")
    
        cloud_public_key = bs.get_public_key()
        if cloud_public_key != public_key:
            logger.warn("Your public in the cloud does not match the one you have on disk")
            
        logger.debug(public_key)
    except errors.BinstarError:
        logger.warn("You don't have a public key yet!!")
        
    binstar_netloc = urlparse(bs.domain).netloc
    all_valid = True 
    all_signed = True 
    print 'listing files from', args.download_cache
    for filename, md5, url in iter_cache_dir(args.download_cache):
        
        if url.netloc == binstar_netloc:
            
            match = pat.search(url.path)
            
            if not match:
                # TODO: warning
                continue
            
            attrs = match.groupdict()
            dist = bs.distribution(attrs['username'], attrs['package'], attrs['version'], attrs['basename'])
            signatures = bs.get_dist_signatures(attrs['username'], attrs['package'], attrs['version'], attrs['basename'])
            rank = signatures['rank']
            
            your_signature = signatures['your_signature']
            if your_signature and args.type == 'unsigned': continue
            elif not your_signature and args.type == 'signed': continue
            
            if dist['md5'] != md5:
                print '%s %s (from %s) %s' % (red_x, basename(url.path), url.netloc, red('did not pass md5 checksum'))
                all_valid = False
            elif your_signature:
                signature = your_signature['signature']
                
                logger.debug('MD5: %s', md5)
                logger.debug('Your signature')
                logger.debug(signature)

                if not keys.verify_hash(public_key, md5.decode('hex'), signature):
                    print '%s %s (from %s) %s' % (red_x, basename(url.path), url.netloc, red('did not pass signature validation'))
                    all_valid = False
                else:
                    print '%s [%s] %s (from %s)' % (green_check, grey('%2i' % rank), basename(url.path), url.netloc)
            else:
                print '%s [%s] %s (from %s) %s' % (orange_, grey('%2i' % rank), basename(url.path), url.netloc, 'not signed')
                all_signed = False
            
        else:
            signatures = bs.get_url_signatures(url.original)
            your_signature = signatures['your_signature']
            if your_signature and args.type == 'unsigned': continue
            elif not your_signature and args.type == 'signed': continue

            if your_signature:
                signature = your_signature['signature']
                logger.debug('MD5: %s', md5)
                logger.debug('Your signature')
                logger.debug(signature)
                
                if not keys.verify_hash(public_key, md5.decode('hex'), signature):
                    print '%s %s (from %s) %s' % (red_x, basename(url.path), url.netloc, red('did not pass signature validation'))
                    all_valid = False
                else:
                    print '%s %s (from %s)' % (green_check, basename(url.path), url.netloc)
            else:
                print '%s %s (from %s) %s' % (orange_, basename(url.path), url.netloc, 'not signed')
                all_signed = False
                
        count = len(signatures['signatures'])
        if your_signature:
            logger.debug('You and %i people have signed this package' % (count - 1))
        else:
            logger.debug('%i people have signed this package' % count)
    
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



def sign_cache(args):
    bs = get_binstar()
    private_key, public_key = get_keypair(bs)
    
    binstar_netloc = urlparse(bs.domain).netloc
    
    invalid_passphrase = True
    logger.info("Please enter your passphrase to sign these packages")
    for i in range(3):  
        passphrase = getpass.getpass('Passphrase: ', stream=sys.stderr)
        invalid_passphrase = not keys.test_passphrase(private_key, passphrase)
        if invalid_passphrase:
            logger.error("Invalid passphrase, pleaes try again")
        else:
            break
    else:
        logger.error("Too many retries. goodby")
        sys.exit(1)
        
    for filename, md5, url in iter_cache_dir(args.download_cache):
        
        if url.netloc == binstar_netloc:
            print '- binstar', url.path,
            match = pat.search(url.path)
            if not match:
                import pdb;pdb.set_trace()
                raise errors.BinstarError('Can not match path %r to a binstar url' % url.path)
            
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
                do_sig = True
                if args.mode == 'interactive':
                    logger.info('')
                    logger.info('Package owner:%s package:%s version:%s filename:%s' % (attrs['username'], attrs['package'], attrs['version'], attrs['basename']))
                    do_sig = bool_input('Would you like to sign this package', default=True)
                if do_sig:
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

            

def is_special_requirement(requirement):
    special = ['-']
    if any(requirement.startswith(item) for item in special):
        return True

def run_cmd(*cmd):
    logger.info('%s %s' % (green('Run:') , ' '.join(cmd)))
    try:
        check_call(cmd)
    except CalledProcessError:
        raise errors.BinstarError("command %s failed" % cmd[0])

def install_collection(args):
    bs = get_binstar(args)
    coll = args.collection
    
    bs.collection(coll.org, coll.name)
    requirements_txt = bs.collection_get_metadata(coll.org, coll.name, 'requirements_txt')
    
    with open('requirements.txt', 'w') as fd:
        fd.write(requirements_txt)
        
    url = urlparse(get_config().get('url'))
    if url.path == '/api': 
        index_base = '%s/pypi' % url.netloc
    elif url.netloc.startswith('api.'):
        index_base = 'pypi.%s' % url.netloc[4:]

    index_url = '%s/collections/%s/%s/simple' % (index_base, coll.org, coll.name)

    run_cmd('pip', 'install', '--no-install',
            '--index-url', index_url,
            '-r', 'requirements.txt')
    run_cmd('binstar-pip', 'list', '--fail-if-unsigned')
        
    
def freeze_collection(args):
    bs = get_binstar(args)
    coll = args.collection
    
    try:
        bs.collection(coll.org, coll.name)
        logger.info("Using existing collection %s/%s" % (coll.org, coll.name))
    except:
        logger.info("Creating now collection %s/%s" % (coll.org, coll.name))
        description = '''
This collection was created from the binstar-pip freeze-collection command
'''
        bs.add_collection(coll.org, coll.name, args.public, description)
    
    bs = get_binstar(args)
    
    requirements = args.requirements.read()
    for requirement in requirements.splitlines():
        
        if is_special_requirement(requirement):
            logger.warn("Not adding %r to the collection" % requirement)
            continue
        try:
            req = next(pkg_resources.parse_requirements(requirement))
        except ValueError as err:
            logger.error(err)
            
        logger.info("Adding package pypi/%s to collection" % req.project_name)
        bs.collection_add_packages(coll.org, coll.name, owner='pypi', package=req.project_name)
    
    logger.info("Attaching requirements.txt to collection metadata")
    bs.collection_attach_metadata(coll.org, coll.name, 'requirements_txt', requirements)
    logger.info("Done")

def main():
    
    
    
    parser = ArgumentParser()
    parser.add_argument('-V', '--version', action='version',
                        version="%%(prog)s command line client (version %s)" % (version,))
    parser.add_argument('-v', '--verbose',
                        action='store_const', help='print debug information ot the console',
                        dest='log_level',
                        default=logging.INFO, const=logging.DEBUG)
    
    parser.add_argument('-t', '--token')
    parser.add_argument('--show-traceback', action='store_true')
    
    parser.add_argument('--download-cache', default=default_download_cache())
    sp = parser.add_subparsers()
    #===========================================================================
    # 
    #===========================================================================
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
    #===========================================================================
    # 
    #===========================================================================
    signp = sp.add_parser('sign')
    signp.add_argument('-i','--interactive', dest='mode', action='store_const', const='interactive')
    signp.set_defaults(func=sign_cache)
    #===========================================================================
    # 
    #===========================================================================
    fcp = sp.add_parser('freeze-collection')
    fcp.add_argument('collection', type=collection_spec,
                     help='Collection to create or add to')
    fcp.add_argument('-r', '--requirements', type=FileType('r'), required=True)
    g = fcp.add_mutually_exclusive_group()
    g.add_argument('--public', dest='public', action='store_true', default=True,
                     help='When creating a collection, make it public (default)')
    g.add_argument('--private', dest='public', action='store_false',
                     help='When creating a collection, make it private')
    
    fcp.set_defaults(func=freeze_collection)
    
    #===========================================================================
    # 
    #===========================================================================
    icp = sp.add_parser('install-collection')
    icp.add_argument('collection', type=collection_spec,
                     help='Collection to create or add to')
    icp.set_defaults(func=install_collection)
    #===========================================================================
    # 
    #===========================================================================
    args = parser.parse_args()
    
    setup_logging(args)
    
    wrap_main(args.func, args)



logger = logging.getLogger('binstar')

if __name__ == '__main__':
    main()
