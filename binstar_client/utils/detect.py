'''
Created on Jan 2, 2014

@author: sean
'''
import tarfile
import json
import yaml
from os.path import basename
from email.parser import Parser
from os import path
import logging
from binstar_client.utils import compute_hash
import hashlib

log = logging.getLogger('binstar.detect')

def detect_yaml_attrs(filename):
    tar = tarfile.open(filename)

    try:
        obj = tar.extractfile('info/recipe/meta.yaml')
    except KeyError:
        return None, None

    attrs = yaml.load(obj)
    about = attrs.get('about')
    description = about.get('home')
    license = about.get('license')

    return description, license

def detect_pypi_attrs(filename):

    with tarfile.open(filename) as tf:
        pkg_info = next(name for name in tf.getnames() if name.endswith('/PKG-INFO'))
        fd = tf.extractfile(pkg_info)
        attrs = dict(Parser().parse(fd).items())

    name = attrs.pop('Name')
    version = attrs.pop('Version')
    summary = attrs.pop('Summary')
    description = attrs.pop('Description')
    license = attrs.pop('License')
    attrs = {'dist':'sdist'}

    filename = basename(filename)
    return filename, name, version, attrs, summary, description, license

arch_map = {('osx', 'x86_64'):'osx-64',
            ('win', 'x86'):'win-32',
            ('win', 'x86_64'):'win-64',
            ('linux', 'x86'):'linux-32',
            ('linux', 'x86_64'):'linux-64',
           }

def detect_conda_attrs(filename):

    tar = tarfile.open(filename)
    obj = tar.extractfile('info/index.json')
    attrs = json.loads(obj.read())

    description, license = detect_yaml_attrs(filename)
    os_arch = arch_map[(attrs['platform'], attrs['arch'])]
    filename = path.join(os_arch, basename(filename))
    return filename, attrs['name'], attrs['version'], attrs, description, description, license

def detect_r_attrs(filename):

    with tarfile.open(filename) as tf:
        pkg_info = next(name for name in tf.getnames() if name.endswith('/DESCRIPTION'))
        fd = tf.extractfile(pkg_info)
        raw_attrs = dict(Parser().parse(fd).items())
    print raw_attrs.keys()
    
    name = raw_attrs.pop('Package')
    version = raw_attrs.pop('Version')
    summary = raw_attrs.pop('Title', None)
    description = raw_attrs.pop('Description', None)
    license = raw_attrs.pop('License', None)
    
    attrs = {}
    attrs['NeedsCompilation'] = raw_attrs.get('NeedsCompilation', 'no')
    attrs['depends'] = raw_attrs.get('Depends', '').split(',')
    attrs['suggests'] = raw_attrs.get('Suggests', '').split(',')
    
    built = raw_attrs.get('Built')
    
    if built:
        r, _, date, platform = built.split(';')
        r_version = r.strip('R ')
        attrs['R'] = r_version
        attrs['os'] = platform.strip()
        attrs['type'] = 'package'
    else:
        attrs['type'] = 'source'
    
    return filename, name, version, attrs, summary, description, license


def mkreq(name, version, flag):
    ret = {}
    version = version and version.rsplit('-', 1)
    if not version:
        pass
    elif len(version) == 2:
        ret['rel'] = version[1] 
        ret['ver'] = version[0]
        ret['epoch'] = 0
    else:
        ret['ver'] = version[0]
        
        
    if (flag & 077) == 012:
        ret['flags'] = 'LE'
    elif (flag & 077) == 010:
        ret['flags'] = 'EQ'

    return ret
    


def detect_rpm_attrs(filename):
    try:
        import rpmfile
    except ImportError:
        log.error("Uploading RPM's requires the rpmfile python module")
        raise

    basefilename = basename(filename)
    
    with rpmfile.open(filename) as rpm:
        package_name = rpm.headers['name']
        version = rpm.headers['version']
        description = rpm.headers['description']
        summary = rpm.headers['summary']
        license = rpm.headers['copyright']
        archive_size = len(rpm.gzip_file.read())
    
    attrs = {}
    with open(filename) as fp:
        sha256, _, _ = compute_hash(fp, hash_algorithm=hashlib.sha256)
        attrs['sha256'] = sha256
        
    attrs['header_range'] = rpm.header_range
    attrs['installed_size'] = rpm.headers['size']
    attrs['archive_size'] = archive_size
    attrs['rel'] = rpm.headers.get('release', 1)
    
    rname = rpm.headers.get('requirename', [])
    rversion = rpm.headers.get('requireversion', [])
    rflags = rpm.headers.get('requireflags', [])
    attrs['requires'] = {name:mkreq(name, version, flag) for (name, version, flag) in zip(rname, rversion, rflags)}
    attrs['os'] = rpm.headers['os']
    attrs['arch'] = rpm.headers['arch']
    attrs['target'] = rpm.headers['target']
    attrs['buildtime'] = rpm.headers['buildtime']
    attrs['provides'] = rpm.headers['provides']
    attrs['group'] = rpm.headers['group']
    attrs['buildhost'] = rpm.headers['buildhost']
    attrs['sourcerpm'] = rpm.headers['sourcerpm']
    
    return basefilename, package_name, version, attrs, summary, description, license
#===============================================================================
# 
#===============================================================================

detectors = {'conda':detect_conda_attrs,
             'pypi': detect_pypi_attrs,
             'r': detect_r_attrs,
             'rpm': detect_rpm_attrs,
             }


def is_conda(filename):
    if filename.endswith('.tar.bz2'):  # Could be a conda package
        try:
            with tarfile.open(filename) as tf:
                tf.getmember('info/index.json')
        except KeyError:
            return False
        else:
            return True
    
def is_pypi(filename):
    if filename.endswith('.tar.gz') or filename.endswith('.tgz'):  # Could be a setuptools sdist or r source package
        with tarfile.open(filename) as tf:
            if any(name.endswith('/PKG-INFO') for name in tf.getnames()):
                return True

def is_r(filename):
    if filename.endswith('.tar.gz') or filename.endswith('.tgz'):  # Could be a setuptools sdist or r source package
        with tarfile.open(filename) as tf:
            
            if (any(name.endswith('/DESCRIPTION') for name in tf.getnames()) and 
                any(name.endswith('/NAMESPACE') for name in tf.getnames())):
                return True

def is_rpm(filename):
    return filename.endswith('.rpm')
    
def detect_package_type(filename):
    
    if is_conda(filename):
        return 'conda'
    elif is_pypi(filename):
        return 'pypi'
    elif is_r(filename):
        return 'r'
    elif is_rpm(filename):
        return 'rpm'
    else:
        return None


def get_attrs(package_type, filename):
    return detectors[package_type](filename)
