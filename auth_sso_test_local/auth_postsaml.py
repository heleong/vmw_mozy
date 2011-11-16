#!/usr/bin/env python

"""
auth_postsaml.py

Contains related REST API test cases for POST POST /<partner_subdomain>/saml

Created by Leong He.
Copyright (c) 2011~2012 VMware. All rights reserved.
"""
__date__ = "2nd Nov 2011"
__author__ = "Leong He<hel@vmware.com>"
__version__ = "$Revision: #1 $"

import sys, re, logging, ast
import httplib2, urllib
import unittest
from restclient import Resource, rest
import utils
from urllib import urlencode, quote


class AuthPostSaml(unittest.TestCase):
    def setUp(self):
        self.res = Resource("http://"+utils.auth_server)
        # set logging level
        # Need to be moved to somewhere else for global configuration
        debug = logging.DEBUG
        logging.basicConfig(level = debug, stream = sys.stderr, format = '%(levelname)s %(asctime)s [%(message)s]')
        logging.info("")

    def test_positive_auth_post_saml_check_return(self):
        """
        Check the response contains correct return.
        """
        # get auth first
        head, content = utils.auth_get_auth()
        # get cookie
        cookie = head['set-cookie']
        logging.info("The retrieved cookie from Auth server is '%s'" % str(cookie))
        header = utils.headers
        header['cookie'] = cookie
        logging.debug("The requested headers are '%s'" % str(header))
        # post saml
        http = httplib2.Http()
        url = 'http://' + utils.auth_server + '/' + utils.auth_partner + '/saml'
        logging.debug("The requested url is '%s'" % str(url))
        h, c = http.request(url, 'POST', headers = header, body = utils.auth_body)
        # verification for redirection to resource server e.g. mozypro? check
        logging.info("The retrieved response head is '%s'" % str(h))
        logging.info("The retrieved response content is '%s'" % str(c))
        # assert it's a redirection exception
        self.assertTrue(int(h['status']), 302)
        # assert location is returned
        self.assertTrue(h.has_key('location'))
        # assert location content is correct 
        self.assertTrue(h['location'].find('access_token') != -1, "The access_token isn't returned!")
        self.assertTrue(h['location'].find('token_type=bearer') != -1, "The token_type isn't bearer!")
        
    def test_negative_auth_post_saml_empty_saml(self):
        """
        Check exception raised while posting saml with empty saml, and verify the exception contains correct error messages.
        """
        # get auth first
        head, content = utils.auth_get_auth()
        # get cookie
        cookie = head['set-cookie']
        logging.info("The retrieved cookie from Auth server is '%s'" % str(cookie))
        header = utils.headers
        header['cookie'] = cookie
        logging.debug("The requested headers are '%s'" % str(header))

        http = httplib2.Http()
        # construct invalid responses
        invalid_saml = ['', '  ']
        for isa in invalid_saml:
            logging.info("The invalid saml to be tested is '%s'" % str(isa))
            url = 'http://' + utils.auth_server + '/' + utils.auth_partner + '/saml'
            logging.info("The requested url is '%s'" % url)
            saml = {'SAMLResponse': isa}
            h, c = http.request(url, 'POST', headers = header, body = urlencode(saml))
            # assert response head status is 400
            self.assertEqual(int(h['status']), 400)
            # assert error msg is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("EmptySAML", "AuthPostSamlGrantExceptions"), self)

    def test_negative_auth_post_saml_invalid_saml(self):
        """
        Check exception raised while posting saml with invalid saml, and verify the exception contains correct error messages.
        """
        # get auth first
        head, content = utils.auth_get_auth()
        # get cookie
        cookie = head['set-cookie']
        logging.info("The retrieved cookie from Auth server is '%s'" % str(cookie))
        header = utils.headers
        header['cookie'] = cookie
        logging.debug("The requested headers are '%s'" % str(header))

        http = httplib2.Http()
        # construct invalid responses
        invalid_saml = [utils.random_str()]
        for isa in invalid_saml:
            logging.info("The invalid saml to be tested is '%s'" % str(isa))
            url = 'http://' + utils.auth_server + '/' + utils.auth_partner + '/saml'
            logging.info("The requested url is '%s'" % url)
            saml = {'SAMLResponse': isa}
            h, c = http.request(url, 'POST', headers = header, body = urlencode(saml))
            # assert response head status is 400
            self.assertEqual(int(h['status']), 400)
            # assert error msg is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("InvalidSAML", "AuthPostSamlGrantExceptions"), self)

    def test_negative_auth_post_saml_invalid_cookie(self):
        """
        Check exception raised while posting saml with invalid cookie, and verify the exception contains correct error messages.
        """
        # get auth first
        head, content = utils.auth_get_auth()
        # get cookie
        cookie = head['set-cookie']
        logging.info("The retrieved cookie from Auth server is '%s'" % str(cookie))
        header = utils.headers
        header['cookie'] = cookie
        logging.debug("The requested headers are '%s'" % str(header))
        http = httplib2.Http()
        # construct invalid responses
        invalid_cookies = ['', utils.random_str(), '  ']
        for ic in invalid_cookies:
            logging.info("The invalid cookie to be tested is '%s'" % str(ic))
            header['cookie'] = ic 
            logging.debug("The requested headers are '%s'" % str(header))
            url = 'http://' + utils.auth_server + '/' + utils.auth_partner + '/saml'
            logging.info("The requested url is '%s'" % url)
            h, c = http.request(url, 'POST', headers = header, body = utils.auth_body)
            # assert response head status is 400
            self.assertEqual(int(h['status']), 400)
            # assert error msg is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("UnknownClient", "AuthPostSamlGrantExceptions"), self)

    def test_negative_auth_post_saml_unknown_partner(self):
        """
        Check exception raised while posting saml with unknown partner, and verify the exception contains correct error messages.
        """
        # get auth first
        head, content = utils.auth_get_auth()
        # get cookie
        cookie = head['set-cookie']
        logging.info("The retrieved cookie from Auth server is '%s'" % str(cookie))
        header = utils.headers
        header['cookie'] = cookie
        logging.debug("The requested headers are '%s'" % str(header))

        http = httplib2.Http()
        # construct invalid responses
        invalid_partners = [utils.random_str()]
        for ip in invalid_partners:
            logging.info("The invalid partner to be tested is '%s'" % str(ip))
            url = 'http://' + utils.auth_server + '/' + ip + '/saml'
            logging.info("The requested url is '%s'" % url)
            h, c = http.request(url, 'POST', headers = header, body = utils.auth_body)
            # assert response head status is 400
            self.assertEqual(int(h['status']), 400)
            # assert error msg is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("UnknownSubdomain", "AuthPostSamlGrantExceptions"), self)

    def test_negative_auth_post_saml_invalid_partner(self):
        """
        Check exception raised while posting saml with invalid partner, and verify the exception contains correct error messages.
        """
        # get auth first
        head, content = utils.auth_get_auth()
        # get cookie
        cookie = head['set-cookie']
        logging.info("The retrieved cookie from Auth server is '%s'" % str(cookie))
        header = utils.headers
        header['cookie'] = cookie
        logging.debug("The requested headers are '%s'" % str(header))

        http = httplib2.Http()
        # construct invalid responses
        invalid_partners = [' ']
        for ip in invalid_partners:
            logging.info("The invalid partner to be tested is '%s'" % str(ip))
            url = quote('http://' + utils.auth_server + '/' + ip + '/saml', ':/&=')
            logging.info("The requested url is '%s'" % url)
            h, c = http.request(url, 'POST', headers = header, body = utils.auth_body)
            # assert response head status is 400
            self.assertEqual(int(h['status']), 400)
            # assert error msg is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("InvalidSubdomain", "AuthPostSamlGrantExceptions"), self)

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(AuthPostSaml)
    unittest.TextTestRunner(verbosity=2).run(suite)
