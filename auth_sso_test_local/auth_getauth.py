#!/usr/bin/env python

"""
auth_getauth.py

Contains related REST API test cases for Get /<partner_subdomain>/authorize

Created by Leong He.
Copyright (c) 2011~2012 VMware. All rights reserved.
"""
__date__ = "31st Oct 2011"
__author__ = "Leong He<hel@vmware.com>"
__version__ = "$Revision: #1 $"

import sys, re, logging, ast
import unittest
from restclient import Resource, rest
import httplib2
import urllib
import utils


class AuthGetAuth(unittest.TestCase):
    def setUp(self):
        self.res = Resource("http://"+utils.auth_server)
        # set logging level
        # Need to be moved to somewhere else for global configuration
        debug = logging.DEBUG
        logging.basicConfig(level = debug, stream = sys.stderr, format = '%(levelname)s %(asctime)s [%(message)s]')
        logging.info("")

    def test_postive_auth_get_auth_horizon_check_return(self):
        """
        Check the response contains correct return.
        """
        # get auth
        head, content = utils.auth_get_auth()
        # assert status code is 302 
        self.assertEqual(int(head['status']), 302)
        # assert head has set-cookie keyword
        self.assertTrue(head.has_key('set-cookie'))
        # assert cookie content is correct
        self.assertTrue(head['set-cookie'].find('mozy.auth.horizon') != -1, "The cookie 'mozy.auth.horizon' was not found in reponse head!")
        # assert location is returned
        self.assertTrue(head.has_key('location'))

    def test_postive_auth_get_auth_matched_URI_check_return(self):
        """
        Check the response contains correct return with matched URI is given.
        """
        # get auth
        http = httplib2.Http()
        http.follow_redirects = False
        url = 'http://' + utils.auth_server + '/' + utils.auth_partner + '/authorize?' + 'response_type=token' + '&client_id=' + utils.auth_client_id + '&redirect_uri=' + utils.auth_client_redirect_uri
        logging.info("The requested url is '%s'" % str(url))
        head, content = http.request(url, 'GET', headers = utils.headers)
        logging.info("The retrieved head is '%s'" % str(head))
        logging.info("The retrieved content is '%s'" % str(content))
        # assert status code is 302 
        self.assertEqual(int(head['status']), 302)
        # assert head has set-cookie keyword
        self.assertTrue(head.has_key('set-cookie'))
        # assert cookie content is correct
        self.assertTrue(head['set-cookie'].find('mozy.auth.horizon') != -1, "The cookie 'mozy.auth.horizon' was not found in reponse head!")
        # assert location is returned
        self.assertTrue(head.has_key('location'))

    def test_negative_auth_get_auth_invalid_response_type(self):
        """
        Check exception raised while getting auth for invalid respone type other than 'token', and verify the exception contains correct error messages.
        """
        http = httplib2.Http()
        # construct invalid responses
        invalid_response = ['', utils.random_str()]
        for ir in invalid_response:
            logging.info("The invalid response type to be tested is '%s'" % str(ir))
            url = 'http://' + utils.auth_server + '/' + utils.auth_partner + '/authorize?' + 'response_type=' + ir + '&client_id=' + utils.auth_client_id
            logging.info("The requested url is '%s'" % url)
            h,c = http.request(url, 'GET', headers = utils.headers)
            # assert it's a bad request
            self.assertEqual(int(h['status']), 400)
            # assert the exception content is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception('UnknownResponseType', 'AuthGetAuthExceptions'), self, ir)

    def test_negative_auth_get_auth_invalid_client_id(self):
        """
        Check exception raised while getting auth for invalid client id, and verify the exception contains correct error messages.
        """
        http = httplib2.Http()
        # construct invalid client id 
        invalid_client = ['', utils.random_str(), '  ']
        for ic in invalid_client:
            logging.info("The invalid client id to be tested is '%s'" % str(ic))
            url = 'http://' + utils.auth_server + '/' + utils.auth_partner + '/authorize?' + 'response_type=token' + '&client_id=' + ic
            logging.info("The requested url is '%s'" % url)
            h,c = http.request(url, 'GET', headers = utils.headers)
            logging.debug("The retrieved header is '%s'" % str(h))
            logging.debug("The retrieved content is '%s'" % str(c))
            # assert it's a bad request
            self.assertEqual(int(h['status']), 400)
            # assert the exception content is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception('UnknownClient', 'AuthGetAuthExceptions'), self)

    def test_negative_auth_get_auth_invalid_URI(self):
        """
        Check exception raised while getting auth for uri, and verify the exception contains correct error messages.
        """
        http = httplib2.Http()
        # construct invalid client id 
        invalid_request = [utils.random_str()]
        for ir in invalid_request:
            logging.info("The invalid uri to be tested is '%s'" % str(ir))
            url = urllib.quote('http://' + utils.auth_server + '/' + utils.auth_partner + '/authorize?' + 'response_type=token' + '&client_id=' + utils.auth_client_id + '&redirect_uri=' + ir, ':/&=?')
            logging.info("The requested url is '%s'" % url)
            h,c = http.request(url, 'GET', headers = utils.headers)
            logging.debug("The retrieved header is '%s'" % str(h))
            logging.debug("The retrieved content is '%s'" % str(c))
            # assert it's a bad request
            self.assertEqual(int(h['status']), 400)
            # assert the exception content is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception('UnmatchedURI', 'AuthGetAuthExceptions'), self)

    def test_negative_auth_get_auth_missing_URI(self):
        """
        Check exception raised while getting auth for missing uri, and verify the exception contains correct error messages.
        """
        http = httplib2.Http()
        # construct invalid client id 
        url = 'http://' + utils.auth_server + '/' + utils.auth_partner + '/authorize?' + 'response_type=token' + '&client_id=' + utils.auth_client_id_no_uri
        logging.info("The requested url is '%s'" % url)
        h,c = http.request(url, 'GET', headers = utils.headers)
        logging.debug("The retrieved header is '%s'" % str(h))
        logging.debug("The retrieved content is '%s'" % str(c))
        # assert it's a bad request
        self.assertEqual(int(h['status']), 400)
        # assert the exception content is correct
        utils.verify_rest_requetfailed_exception(c, utils.get_exception('MissingURI', 'AuthGetAuthExceptions'), self)


    def test_negative_auth_get_auth_invalid_partner(self):
        """
        Check exception raised while getting auth with invalid partner, and verify the exception contains correct error messages.
        """
        http = httplib2.Http()
        # construct invalid invalid partner 
        invalid_partners= [utils.random_str()]
        for ip in invalid_partners:
            logging.info("The invalid partner to be tested is '%s'" % str(ip))
            url = 'http://' + utils.auth_server + '/' + ip + '/authorize?' + 'response_type=token' + '&client_id=' + utils.auth_client_id
            logging.info("The requested url is '%s'" % url)
            h,c = http.request(url, 'GET', headers = utils.headers)
            logging.debug("The retrieved header is '%s'" % str(h))
            logging.debug("The retrieved content is '%s'" % str(c))
            # assert it's a bad request
            self.assertEqual(int(h['status']), 400)
            # assert the exception content is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception('UnknownSubdomain', 'AuthGetAuthExceptions'), self)

    def test_negative_auth_get_auth_empty_partner(self):
        """
        Check exception raised while getting auth with empty partner, and verify the exception contains correct error messages.
        """
        http = httplib2.Http()
        # construct invalid invalid partner 
        invalid_partners= [' ']
        for ip in invalid_partners:
            logging.info("The invalid partner to be tested is '%s'" % str(ip))
            url = urllib.quote('http://' + utils.auth_server + '/' + ip + '/authorize?' + 'response_type=token' + '&client_id=' + utils.auth_client_id, ':/&=')
            logging.info("The requested url is '%s'" % url)
            h,c = http.request(url, 'GET', headers = utils.headers)
            logging.debug("The retrieved header is '%s'" % str(h))
            logging.debug("The retrieved content is '%s'" % str(c))
            # assert it's a bad request
            self.assertEqual(int(h['status']), 500)
            # assert the exception content is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception('EmptySubdomain', 'AuthGetAuthExceptions'), self)

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(AuthGetAuth)
    unittest.TextTestRunner(verbosity=2).run(suite)
