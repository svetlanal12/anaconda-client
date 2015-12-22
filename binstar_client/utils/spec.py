'''
Defines the object specification syntax and object
'''
# Standard library imports
from __future__ import print_function, unicode_literals

# Local imports
from binstar_client.errors import UserError, InvalidPackageSpec


class PackageSpec(object):
    def __init__(self, user, package=None, version=None, basename=None, attrs=None, label=None, spec_str=None):
        self._user = user
        self._package = package
        self._version = version
        self._basename = basename
        self._label = label
        self.attrs = attrs
        if spec_str:
            self.spec_str = spec_str
        else:
            spec_str = str(user)
            if package:
                spec_str = '%s/%s' % (spec_str, package)
            if version:
                spec_str = '%s/%s' % (spec_str, version)
            if basename:
                spec_str = '%s/%s' % (spec_str, basename)
            self.spec_str = spec_str



    def __str__(self):
        return self.spec_str

    def __repr__(self):
        return '<PackageSpec %r>' % (self.spec_str)

    @property
    def user(self):
        if self._user is None:
            raise UserError('user not given (got %r expected <username> )' % (self.spec_str,))
        return self._user

    @property
    def name(self):
        if self._package is None:
            raise UserError('package not given in spec (got %r expected <username>/<package> )' % (self.spec_str,))
        return self._package

    @property
    def package(self):
        if self._package is None:
            raise UserError('package not given in spec (got %r expected <username>/<package> )' % (self.spec_str,))
        return self._package

    @property
    def version(self):
        if self._version is None:
            raise UserError('version not given in spec (got %r expected <username>/<package>/<version> )' % (self.spec_str,))
        return self._version

    @property
    def basename(self):
        if self._basename is None:
            raise UserError('basename not given in spec (got %r expected <username>/<package>/<version>/<filename> )' % (self.spec_str,))
        return self._basename

    @property
    def label(self):
        if self._label is None:
            raise UserError('label not given in spec (got %r expected <username>[<label>])' % (self.spec_str,))
        return self._label


def parse_spec(spec):
    '''
    '@' USERNAME ['[' LABEL_NAME ']' ]  ['/' OBJECT_NAME] ['==' VERSION]
    '''
    if not spec.startswith('@'):
        raise InvalidPackageSpec(
            'User specification should start with "@": %r' % spec)

    label = package = version = None
    user = spec[1:]

    if '[' in user or ']' in user:
        open_index = user.find('[')
        close_index = user.rfind(']')

        if open_index == -1 or close_index == -1:
            raise InvalidPackageSpec(
                'Incomplete label name: %r' % spec)

        user, label, remain = user[:open_index], user[open_index+1:close_index], user[close_index+1:]
    


    return PackageSpec(
        user=user,
        label=label,
        package=package,
        version=version,)
