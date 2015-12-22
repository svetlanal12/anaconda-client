# Standard library imports
from __future__ import print_function, unicode_literals
import unittest

# Local imports
from binstar_client.utils import spec
from binstar_client import errors

class Test(unittest.TestCase):

    def test_empty(self):
        with self.assertRaises(errors.InvalidPackageSpec):
            spec.parse_spec('')

    def test_missing_user(self):
        with self.assertRaises(errors.InvalidPackageSpec):
            spec.parse_spec('foo')

    def test_parse_user(self):
        pkg = spec.parse_spec('@me')
        self.assertEqual(pkg.user, 'me')

    def test_parse_user_unset(self):
        pkg = spec.parse_spec('@me')
        with self.assertRaises(errors.UserError):
            pkg.label
        with self.assertRaises(errors.UserError):
            pkg.package
        with self.assertRaises(errors.UserError):
            pkg.version

    def test_parse_user_label(self):
        pkg = spec.parse_spec('@me[label]')
        self.assertEqual(pkg.user, 'me')
        self.assertEqual(pkg.label, 'label')

    def test_parse_user_label_unset(self):
        pkg = spec.parse_spec('@me[label]')
        with self.assertRaises(errors.UserError):
            pkg.package
        with self.assertRaises(errors.UserError):
            pkg.version

    def test_parse_annoying_label(self):
        pkg = spec.parse_spec('@me[][label-with/super:annoying_chars]')
        self.assertEqual(pkg.user, 'me')
        self.assertEqual(pkg.label, '][label-with/super:annoying_chars')

    def test_parse_open_label(self):
        with self.assertRaises(errors.InvalidPackageSpec):
            spec.parse_spec('@me[label')
        with self.assertRaises(errors.InvalidPackageSpec):
            spec.parse_spec('@melabel]')

    def test_parse_user_package(self):
        pkg = spec.parse_spec('@me/foo')
        self.assertEqual(pkg.user, 'me')
        self.assertEqual(pkg.package, 'foo')

    def test_parse_user_package_unset(self):
        pkg = spec.parse_spec('@me/foo')
        with self.assertRaises(errors.UserError):
            pkg.label
        with self.assertRaises(errors.UserError):
            pkg.version

    def test_parse_user_label_package(self):
        pkg = spec.parse_spec('@me[label]/foo')
        self.assertEqual(pkg.user, 'me')
        self.assertEqual(pkg.label, 'label')
        self.assertEqual(pkg.package, 'foo')

    def test_parse_user_label_package_unset(self):
        pkg = spec.parse_spec('@me[label]/foo')
        with self.assertRaises(errors.UserError):
            pkg.version

    def test_parse_user_label_package_annoying(self):
        pkg = spec.parse_spec('@me[][label-with/super:annoying_chars]/foo')
        self.assertEqual(pkg.user, 'me')
        self.assertEqual(pkg.label, '][label-with/super:annoying_chars')
        self.assertEqual(pkg.package, 'foo')



if __name__ == '__main__':
    unittest.main()
