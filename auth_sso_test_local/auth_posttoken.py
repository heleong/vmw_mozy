#!/usr/bin/env python

"""
auth_posttoken.py

Contains related REST API test cases for POST /<partner_subdomain>/token

Created by Leong He.
Copyright (c) 2011~2012 VMware. All rights reserved.
"""
__date__ = "4th Nov 2011"
__author__ = "Leong He<hel@vmware.com>"
__version__ = "$Revision: #1 $"

import sys, re, logging, ast
import httplib2, urllib
import base64
import unittest
from restclient import Resource, rest
import utils


class AuthPostToken(unittest.TestCase):
    def setUp(self):
        self.http = httplib2.Http()
        self.url = 'http://' + utils.auth_server + '/' + utils.auth_partner + '/token'
        # set logging level
        # Need to be moved to somewhere else for global configuration
        debug = logging.DEBUG
        logging.basicConfig(level = debug, stream = sys.stderr, format = '%(levelname)s %(asctime)s [%(message)s]')
        logging.info("")

    def test_postive_auth_post_token_check_keys(self):
        """
        Check the response contains correct return.
        """
        headers = utils.headers
        # compose basic auth
        headers['Authorization'] = "Basic %s" % base64.encodestring('%s:%s' % (utils.auth_client_id, utils.auth_client_secret))[:-1]
        logging.debug("The requested url is '%s'" % str(self.url))
        # post token 
        body = {'grant_type': 'http://oauth.net/grant_type/assertion/saml/2.0/bearer', 'assertion': utils.SAMLResponse}
        h, c = self.http.request(self.url, 'POST', headers = utils.headers, body = urllib.urlencode(body))
        logging.debug("The response head is '%s'" % str(h))
        logging.debug("The response body is '%s'" % str(c))
        # assert status code is '200'
        self.assertEqual(int(h['status']), 200)
        cd = ast.literal_eval(c)
        keys = ["token_type", "token_secret", "access_token", "expires_in", "refresh_token"]
        for k in cd.keys():
            self.assertTrue(k in keys, "The key '%s' not in '%s'" % (k, keys))
        # assert 'token_type' must be 'bearer'
        tt = ['bearer']
        self.assertTrue(cd['token_type'] in tt, "The 'token_type' is not in %s" % tt)
        self.assertEqual(type(cd['access_token']), type(str()), "The 'access_token' is not a string")
        self.assertEqual(type(cd['token_secret']), type(str()), "The 'token_secret' is not a string")

    def test_negative_auth_post_token_invalid_grant_type(self):
        """
        Check exception raised while posting token with invalid grant_type, and verify the exception contains correct error messages.
        """
        headers = utils.headers
        # compose basic auth
        headers['Authorization'] = "Basic %s" % base64.encodestring('%s:%s' % (utils.auth_client_id, utils.auth_client_secret))[:-1]
        logging.debug("The requested header is '%s'" % str(headers))
        # construct invalid responses
        invalid_grant_type= [utils.random_str(), ' ', '']
        for ig in invalid_grant_type:
            logging.info("The invalid grant_type to be tested is '%s'" % str(ig))
            logging.info("The requested url is '%s'" % self.url)
            # post token 
            body = {'grant_type': ig, 'assertion': utils.SAMLResponse}
            h, c = self.http.request(self.url, 'POST', headers = headers, body = urllib.urlencode(body))
            # assert response head status is 400
            self.assertEqual(int(h['status']), 400)
            # assert error msg is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("UnsupportedGrantType", "AuthPostTokenExceptions"), self)

    def test_negative_auth_post_token_invalid_SAML(self):
        """
        Check exception raised while posting token with invalid SAML, and verify the exception contains correct error messages.
        """
        headers = utils.headers
        # compose basic auth
        headers['Authorization'] = "Basic %s" % base64.encodestring('%s:%s' % (utils.auth_client_id, utils.auth_client_secret))[:-1]
        logging.debug("The requested header is '%s'" % str(headers))
        # construct invalid responses
        invalid_SAML= [utils.random_str()]
        for ism in invalid_SAML:
            logging.info("The invalid SAML to be tested is '%s'" % str(ism))
            logging.info("The requested url is '%s'" % self.url)
            # post token 
            body = {'grant_type': 'http://oauth.net/grant_type/assertion/saml/2.0/bearer', 'assertion': ism}
            h, c = self.http.request(self.url, 'POST', headers = headers, body = urllib.urlencode(body))
            # assert response head status is 400
            self.assertEqual(int(h['status']), 400)
            # assert error msg is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("InvalidSAML", "AuthPostTokenExceptions"), self)

    def test_negative_auth_post_token_empty_SAML(self):
        """
        Check exception raised while posting token with empty SAML, and verify the exception contains correct error messages.
        """
        headers = utils.headers
        # compose basic auth
        headers['Authorization'] = "Basic %s" % base64.encodestring('%s:%s' % (utils.auth_client_id, utils.auth_client_secret))[:-1]
        logging.debug("The requested header is '%s'" % str(headers))
        # construct invalid responses
        invalid_SAML= [' ', '']
        for ism in invalid_SAML:
            logging.info("The invalid SAML to be tested is '%s'" % str(ism))
            logging.info("The requested url is '%s'" % self.url)
            # post token 
            body = {'grant_type': 'http://oauth.net/grant_type/assertion/saml/2.0/bearer', 'assertion': ism}
            h, c = self.http.request(self.url, 'POST', headers = headers, body = urllib.urlencode(body))
            # assert response head status is 400
            self.assertEqual(int(h['status']), 400)
            # assert error msg is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("EmptySAML", "AuthPostTokenExceptions"), self)

    def test_negative_auth_post_token_invalid_client(self):
        """
        Check exception raised while getting auth for invalid client, and verify the exception contains correct error messages.
        """
        # get config 
        headers = utils.headers
        # compose basic auth
        invalid_auth = ["Basic %s" % base64.encodestring('%s:%s' % (utils.auth_client_id, utils.random_str()))[:-1], "Basic %s" % base64.encodestring('%s:%s' % (utils.random_str(), utils.auth_client_secret))[:-1], "", " "]
        body = {'grant_type': 'http://oauth.net/grant_type/assertion/saml/2.0/bearer', 'assertion': utils.SAMLResponse}
        for ia in invalid_auth:
            headers['Authorization'] = ia
            logging.debug("The requested url is '%s'" % str(self.url))
            logging.info("The invalid authentication head is '%s'" % ia)
            h, c = self.http.request(self.url, 'POST', headers = headers, body = urllib.urlencode(body))
            logging.debug("The response head is '%s'" % str(h))
            logging.debug("The response body is '%s'" % str(c))
            # assert status code is '400'
            self.assertEqual(int(h['status']), 400)
            # verify exception content is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("UnknownClient", "AuthGetConfigExceptions"), self)
            # TODO will fail due to defect 42093

    def test_negative_auth_post_token_invalid_partner(self):
        """
        Check exception raised while getting auth for invalid partner, and verify the exception contains correct error messages.
        """
        # get config 
        headers = utils.headers
        # compose basic auth
        headers['Authorization'] = "Basic %s" % base64.encodestring('%s:%s' % (utils.auth_client_id, utils.auth_client_secret))[:-1]
        body = {'grant_type': 'http://oauth.net/grant_type/assertion/saml/2.0/bearer', 'assertion': utils.SAMLResponse}
        invalid_partners = [utils.random_str()]
        for ip in invalid_partners:
            logging.info("The invalid partner is '%s'" % ip)
            url = 'http://' + utils.auth_server + '/' + ip + '/token'
            logging.debug("The requested url is '%s'" % str(url))
            h, c = self.http.request(url, 'POST', headers = utils.headers, body = urllib.urlencode(body))
            logging.debug("The response head is '%s'" % str(h))
            logging.debug("The response body is '%s'" % str(c))
            # assert status code is '400'
            self.assertEqual(int(h['status']), 400)
            # verify exception content is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("UnknownSubdomain", "AuthPostTokenExceptions"), self)

    def test_negative_auth_post_token_empty_partner(self):
        """
        Check exception raised while getting auth for empty partner, and verify the exception contains correct error messages.
        """
        # get config 
        headers = utils.headers
        # compose basic auth
        headers['Authorization'] = "Basic %s" % base64.encodestring('%s:%s' % (utils.auth_client_id, utils.auth_client_secret))[:-1]
        body = {'grant_type': 'http://oauth.net/grant_type/assertion/saml/2.0/bearer', 'assertion': utils.SAMLResponse}
        invalid_partners = [' ']
        for ip in invalid_partners:
            logging.info("The invalid partner is '%s'" % ip)
            url = urllib.quote('http://' + utils.auth_server + '/' + ip + '/token', ':/&=')
            logging.debug("The requested url is '%s'" % str(url))
            h, c = self.http.request(url, 'POST', headers = utils.headers, body = urllib.urlencode(body))
            logging.debug("The response head is '%s'" % str(h))
            logging.debug("The response body is '%s'" % str(c))
            # assert status code is '400'
            self.assertEqual(int(h['status']), 400)
            # verify exception content is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("InvalidSubdomain", "AuthPostTokenExceptions"), self)

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(AuthPostToken)
    unittest.TextTestRunner(verbosity=2).run(suite)
