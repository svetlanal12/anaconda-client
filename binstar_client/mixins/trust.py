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
        
        if res.status_code == 200:
            return res.text
        
        return None

    def set_public_key(self, public_key):
        url = '%s/public-key' % (self.domain)
        res = self.session.post(url, data=public_key, verify=True)
        self._check_response(res, [201])
        return
    
    def get_dist_signatures(self, owner, package, version, basename):
        path = 'signatures/%s/%s/%s/%s' % (owner, package, version, basename)
        url = '%s/%s' % (self.domain, path)
        res = self.session.get(url, verify=True)
        self._check_response(res)
        return res.json()

    def add_dist_signature(self, owner, package, version, basename, sig):
        path = 'signatures/%s/%s/%s/%s' % (owner, package, version, basename)
        url = '%s/%s' % (self.domain, path)
        res = self.session.post(url, data=sig, verify=True)
        self._check_response(res, [201])
        return

    def get_url_signatures(self, url):
        url = '%s/%s' % (self.domain, 'url-signatures/%s' % urllib.quote_plus(url))
        res = self.session.get(url, verify=True)
        self._check_response(res)
        return res.json()

    def add_url_signature(self, url, sig):
        url = '%s/%s' % (self.domain, 'url-signatures/%s' % urllib.quote_plus(url))
        res = self.session.post(url, data=sig, verify=True)
        self._check_response(res, [201])
        return
