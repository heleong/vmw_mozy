#!/usr/bin/env python

"""
auth_getconfig.py

Contains related REST API test cases for GET /<partner_subdomain>/config

Created by Leong He.
Copyright (c) 2011~2012 VMware. All rights reserved.
"""
__date__ = "3rd Nov 2011"
__author__ = "Leong He<hel@vmware.com>"
__version__ = "$Revision: #1 $"

import sys, re, logging, ast
import httplib2, urllib
import base64
import unittest
from restclient import Resource, rest
import utils


class AuthGetConfig(unittest.TestCase):
    def setUp(self):
        self.http = httplib2.Http()
        self.url = 'http://' + utils.auth_server + '/' + utils.auth_partner + '/config'
        # set logging level
        # Need to be moved to somewhere else for global configuration
        debug = logging.DEBUG
        logging.basicConfig(level = debug, stream = sys.stderr, format = '%(levelname)s %(asctime)s [%(message)s]')
        logging.info("")


    def test_positive_auth_get_config_check_keys(self):
        """
        Check the response contains correct keys returned.
        """
        # get config 
        headers = utils.headers
        # compose basic auth
        headers['Authorization'] = "Basic %s" % base64.encodestring('%s:%s' % (utils.auth_client_id, utils.auth_client_secret))[:-1]
        logging.debug("The requested url is '%s'" % str(self.url))
        h, c = self.http.request(self.url, 'GET', headers = utils.headers)
        logging.debug("The response head is '%s'" % str(h))
        logging.debug("The response body is '%s'" % str(c))
        # convert result string to dictionary
        cd = ast.literal_eval(c)
        # assert head is correct
        self.assertEqual(int(h['status']), 200)
        keys = ['type', 'web_endpoint', 'client_endpoint', 'org_name']
        self.assertTrue(utils.is_same_array(keys, cd.keys()), "Keys are not correct!")

        
    def test_positive_auth_get_config_check_values(self):
        """
        Check the response contains correct values.
        """
        # get config 
        headers = utils.headers
        # compose basic auth
        headers['Authorization'] = "Basic %s" % base64.encodestring('%s:%s' % (utils.auth_client_id, utils.auth_client_secret))[:-1]
        logging.debug("The requested url is '%s'" % str(self.url))
        h, c = self.http.request(self.url, 'GET', headers = utils.headers)
        logging.debug("The response head is '%s'" % str(h))
        logging.debug("The response body is '%s'" % str(c))
        # convert result string to dictionary
        cd = ast.literal_eval(c)

        # assert head is correct
        self.assertEqual(int(h['status']), 200)
        types = ['mozy', 'cbeyond', 'horizon']
        logging.debug("The retrieved config type is '%s'" % cd['type'])
        # assert 'type' is in the 3 values
        self.assertTrue(cd['type'] in types, "The 'type' is not in '%s'" % types)
        # assert 'web_endpoint' is the url format
        p = re.compile("(https:\/\/)*[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&amp;:/~\+#]*[\w\-\@?^=%&amp;/~\+#])?")
        self.assertTrue(p.match(cd['web_endpoint']), "The 'web_endpoint' does not match URL format")
        # assert 'client_endpoint' is the url format
        self.assertTrue(p.match(cd['client_endpoint']), "The 'client_endpoint' does not match URL format")
        # assert 'horizon_org_name' is at least a string type
        self.assertEqual(type(cd['org_name']), type(str("")), "The 'org_name' is not string type")

    def test_negative_auth_get_config_invalid_client(self):
        """
        Check exception raised while getting auth for invalid client, and verify the exception contains correct error messages.
        """
        # get config 
        headers = utils.headers
        # compose basic auth
        invalid_auth = ["Basic %s" % base64.encodestring('%s:%s' % (utils.auth_client_id, utils.random_str()))[:-1], "Basic %s" % base64.encodestring('%s:%s' % (utils.random_str(), utils.auth_client_secret))[:-1], "", " "]
        for ia in invalid_auth:
            headers['Authorization'] = ia
            logging.debug("The requested url is '%s'" % str(self.url))
            logging.info("The invalid authentication head is '%s'" % ia)
            h, c = self.http.request(self.url, 'GET', headers = utils.headers)
            logging.debug("The response head is '%s'" % str(h))
            logging.debug("The response body is '%s'" % str(c))
            # assert status code is '400'
            self.assertEqual(int(h['status']), 400)
            # verify exception content is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("UnknownClient", "AuthGetConfigExceptions"), self)
            # TODO will fail due to defect 42093

    def test_negative_auth_get_config_invalid_partner(self):
        """
        Check exception raised while getting auth for invalid partner, and verify the exception contains correct error messages.
        """
        # get config 
        headers = utils.headers
        # compose basic auth
        headers['Authorization'] = "Basic %s" % base64.encodestring('%s:%s' % (utils.auth_client_id, utils.auth_client_secret))[:-1]
        invalid_partners = [utils.random_str()]
        for ip in invalid_partners:
            logging.info("The invalid partner is '%s'" % ip)
            url = 'http://' + utils.auth_server + '/' + ip + '/config'
            logging.debug("The requested url is '%s'" % str(url))
            h, c = self.http.request(url, 'GET', headers = utils.headers)
            logging.debug("The response head is '%s'" % str(h))
            logging.debug("The response body is '%s'" % str(c))
            # assert status code is '400'
            self.assertEqual(int(h['status']), 400)
            # verify exception content is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("UnknownSubdomain", "AuthGetConfigExceptions"), self)
            
    def test_negative_auth_get_config_empty_partner(self):
        """
        Check exception raised while getting auth for empty partner, and verify the exception contains correct error messages.
        """
        # get config 
        headers = utils.headers
        # compose basic auth
        headers['Authorization'] = "Basic %s" % base64.encodestring('%s:%s' % (utils.auth_client_id, utils.auth_client_secret))[:-1]
        invalid_partners = [' ']
        for ip in invalid_partners:
            logging.info("The invalid partner is '%s'" % ip)
            url = urllib.quote('http://' + utils.auth_server + '/' + ip + '/config', ':/&=')
            logging.debug("The requested url is '%s'" % str(url))
            h, c = self.http.request(url, 'GET', headers = utils.headers)
            logging.debug("The response head is '%s'" % str(h))
            logging.debug("The response body is '%s'" % str(c))
            # assert status code is '500'
            self.assertEqual(int(h['status']), 500)
            # verify exception content is correct
            utils.verify_rest_requetfailed_exception(c, utils.get_exception("EmptySubdomain", "AuthGetConfigExceptions"), self)

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(AuthGetConfig)
    unittest.TextTestRunner(verbosity=2).run(suite)
