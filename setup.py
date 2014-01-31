'''
@author: sean
'''

from setuptools import setup, find_packages
try:
    from binstar_client import __version__ as version
except:
    version = 'dev'
    
setup(
    name='binstar',
    version=version,
    author='Sean Ross-Ross',
    author_email='srossross@gmail.com',
    url='http://github.com/Binstar/binstar_client',
    packages=find_packages(),
    install_requires=['requests>=2.0',
                      'pyyaml',
                      'python-dateutil',
                      'pytz',
                      'PyCrypto'],
    entry_points={
          'console_scripts': [
              'binstar = binstar_client.scripts.cli:main',
              'binstar-pip = binstar_client.scripts.binstar_pip:main',
              ]
                 },

)
