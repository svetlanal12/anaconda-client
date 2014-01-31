'''
Created on Jan 28, 2014

@author: sean
'''
import urllib

class TrustMixin(object):
    
    def get_private_key(self):
        pass

    def get_public_key(self, username=None):
        if username:
            url = '%s/public-key/%s' % (self.domain, username)
        else:
            url = '%s/public-key' % (self.domain)
            
        res = self.session.get(url, verify=True)
        self._check_response(res)
        return res.text

    def set_public_key(self, public_key):
        url = '%s/public-key' % (self.domain)
        res = self.session.post(url, data=public_key, verify=True)
        self._check_response(res, [201])
        return

    def remove_public_key(self):
        url = '%s/public-key' % (self.domain)
        res = self.session.delete(url, verify=True)
        self._check_response(res, [201])
        return
    
    def get_trusted_dists(self, username=None):
        if username:
            path = 'signatures/dists/%s' % (username)
        else:
            path = 'signatures/dists'
        
        url = '%s/%s' % (self.domain, path)
        res = self.session.get(url, verify=True)
        self._check_response(res)
        return res.json()
    
    def get_dist_signatures(self, owner, package, version, basename):
        path = 'signatures/dist/%s/%s/%s/%s' % (owner, package, version, basename)
        url = '%s/%s' % (self.domain, path)
        res = self.session.get(url, verify=True)
        self._check_response(res)
        return res.json()

    def add_dist_signature(self, owner, package, version, basename, sig):
        path = 'signatures/dist/%s/%s/%s/%s' % (owner, package, version, basename)
        url = '%s/%s' % (self.domain, path)
        res = self.session.post(url, data=sig, verify=True)
        self._check_response(res, [201])
        return
    def remove_dist_signature(self, owner, package, version, basename):
        path = 'signatures/dist/%s/%s/%s/%s' % (owner, package, version, basename)
        url = '%s/%s' % (self.domain, path)
        res = self.session.delete(url, verify=True)
        self._check_response(res, [201])
        return

    def get_url_signatures(self, url):
        url = '%s/%s' % (self.domain, 'signatures/url/trusts/%s' % urllib.quote_plus(url))
        res = self.session.get(url, verify=True)
        self._check_response(res)
        return res.json()

    def add_url_signature(self, url, sig):
        url = '%s/%s' % (self.domain, 'signatures/url/trusts/%s' % urllib.quote_plus(url))
        res = self.session.post(url, data=sig, verify=True)
        self._check_response(res, [201])
        return
    
    def remove_url_signature(self, url):
        url = '%s/%s' % (self.domain, 'signatures/url/trusts/%s' % urllib.quote_plus(url))
        res = self.session.delete(url, verify=True)
        self._check_response(res, [201])
        return

    def get_user_signatures(self, username):
        url = '%s/%s' % (self.domain, 'signatures/user/trusted/%s' % username)
        res = self.session.get(url, verify=True)
        self._check_response(res)
        return res.json()
    
    def get_trusted_users(self, username=None):
        'Get the list of users username trusts'
        if username:
            url = '%s/signatures/user/trusted/%s' % (self.domain, username)
        else:
            url = '%s/signatures/user/trusted' % (self.domain)
            
        res = self.session.get(url, verify=True)
        self._check_response(res)
        return res.json()

    def get_trusted_urls(self, username=None):
        'Get the list of url username trusts'
        if username:
            url = '%s/signatures/url/trusted/%s' % (self.domain, username)
        else:
            url = '%s/signatures/url/trusted' % (self.domain)
            
        res = self.session.get(url, verify=True)
        self._check_response(res)
        return res.json()
    
    def remove_user_signature(self, username):
        url = '%s/%s' % (self.domain, 'signatures/user/trusts/%s' % username)
        res = self.session.delete(url, verify=True)
        self._check_response(res, [201])
        return
    
    def add_user_signature(self, username, sig):
        url = '%s/%s' % (self.domain, 'signatures/user/trusts/%s' % username)
        res = self.session.post(url, data=sig, verify=True)
        self._check_response(res, [201])
        return
