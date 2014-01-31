'''
Manage Trust relationships
'''
from binstar_client.utils import get_binstar, keys, parse_specs, bool_input
import getpass
import hashlib
import logging
import sys
logger = logging.getLogger('binstar.trust')


def fingerprint(sig):

    md5 = hashlib.md5()
    md5.update(sig)
    
    fp_plain = md5.hexdigest()
    return ':'.join(a + b for a, b in zip(fp_plain[::2], fp_plain[1::2]))

def main_untrust(args):
    bs = get_binstar(args)
    
    if args.user:
        bs.remove_user_signature(args.username)
        logger.info("You don't trust %s" % args.username)
        return 
    
    if args.package:
        spec = parse_specs(args.username)
        bs.remove_dist_signature(spec.user, spec.package, spec.version, spec.basename)
        logger.info("You don't trust this package any more")
        return
    
    if args.url:
        url = args.username
        bs.remove_url_signature(url)
        logger.info("You don't trust this url any more")
        return
    if args.delete_public_key:
        bool_input("Are you sure you want to to this? All signatiures will be removed", default=False)
        bs.remove_public_key()
        keys.remove_keypair(bs)
    
def main(args):
    bs = get_binstar(args)
    
    if args.package:

        private_key, _ = keys.get_keypair(bs)
        passphrase = getpass.getpass('Please enter your passphrase to sign these packages: ', stream=sys.stderr)
        
        spec = parse_specs(args.username)
        dist = bs.distribution(spec.user, spec.package, spec.version, spec.basename)
        
        sig = keys.sign_hash(private_key, dist['md5'].decode('hex'),
                             passphrase)
        
        bs.add_dist_signature(spec.user, spec.package, spec.version, spec.basename, sig)
        logger.info("You now trust this package")
        return
    
    if args.user:
        private_key, _ = keys.get_keypair(bs)
        passphrase = getpass.getpass('Please enter your passphrase to sign these packages: ', stream=sys.stderr)
        
        other_user_public_key = bs.get_public_key(args.username)
        
        if other_user_public_key is None:
            logger.error('User %s has not yet uploaded a public key. You can not trust them yet' % args.username)
            return
        
        sig = keys.sign(private_key, other_user_public_key, passphrase)
        bs.add_user_signature(args.username, sig)
        logger.info('You now trust %s' % args.username)
        return 
    
    if args.generate_keypair:
        private_key, public_key = keys.get_keypair(bs)
        bs.set_public_key(public_key)
        logger.info("public_key:")
        logger.info(public_key)
        return

def main_view(args):
    bs = get_binstar(args)
    
    if args.public_key:
        public_key = bs.get_public_key(args.username)
        if public_key:
            logger.info(public_key)
        else:
            logger.error('User %s has not yet uploaded a public key' % args.username)
        return
    
    if args.username:
        logger.info("%s Trusts:" % args.username)
    else:
        logger.info("You Trust:")

    if args.packages or args.all:
        logger.info("Packages: ")
        trusted_pacakges = bs.get_trusted_dists(args.username)
            
        key = lambda item: item.get('package', {}).get('full_name')
        tp = sorted(trusted_pacakges['signatures'], key=key)
        tp
        from itertools import groupby
        for package, item in groupby(tp, key):
            if package:
                logger.info(package)
                for sig in item:
                    logger.info('  + %s/%s %s' % (
                                        sig['version'],
                                        sig['basename'],
                                        fingerprint(sig['signature']),
                                        ))
                    
            else:
                for sig in item:
                    logger.info('%s %s' % (sig['trusted'], fingerprint(sig['signature'])))
        
    if args.users or args.all:
        logger.info("Users: ")
        trusted_users = bs.get_trusted_users(args.username)
            
        for item in trusted_users['signatures']:
            print '%-20s %s' % (item['trusted']['username'], fingerprint(item['signature'].decode('base64')))
    
    if args.urls or args.all:
        logger.info("URLS: ")
        trusted_users = bs.get_trusted_urls(args.username)
            
        for item in trusted_users['signatures']:
            print '%-20s %s' % (item['trusted'], fingerprint(item['signature'].decode('base64')))
        return
    
def add_parser(subparsers):

    parser = subparsers.add_parser('show-trust',
                                    help='Manage Trust relationships',
                                    description=__doc__)
    parser.add_argument('username', nargs='?')
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument('--public-key', action='store_true')
    g.add_argument('--all', action='store_true',
                   help='Show all signatures')
    g.add_argument('--users', action='store_true',
                   help='Get the list of users this user trusts')
    g.add_argument('--urls', action='store_true',
                   help='Get the list of urls this user trusts')
    g.add_argument('--packages', action='store_true',
                   help='Get the list of packages this user trusts')
    parser.set_defaults(main=main_view, sub_parser=parser)
    
    #===========================================================================
    # 
    #===========================================================================
    parser = subparsers.add_parser('trust',
                                    help='Manage Trust relationships',
                                    description=__doc__)
    parser.add_argument('username', nargs='?')
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument('--user', action='store_true',
                   help='Trust a user')
    g.add_argument('--package', action='store_true',
                   help='Trust a file in a package ')
    g.add_argument('--generate-keypair', action='store_true',
                   help='Generate a keypair')
    parser.set_defaults(main=main, sub_parser=parser)
    #===========================================================================
    # 
    #===========================================================================
    parser = subparsers.add_parser('untrust',
                                    help='Manage Trust relationships',
                                    description=__doc__)
    parser.add_argument('username', nargs='?')
    g = parser.add_mutually_exclusive_group(required=True)
    
    g.add_argument('--delete-public-key', action='store_true',
                   help='Remove your public key from the ecosystem. Your trust rank will be reset to 0')
    
    g.add_argument('--user', action='store_true',
                   help='Untrust a user')
    g.add_argument('--package', action='store_true',
                   help='Untrust a file in a package ')
    g.add_argument('--url', action='store_true',
                   help='Untrust a url')
    
    
    parser.set_defaults(main=main_untrust, sub_parser=parser)
