#!/usr/bin/env python

"""
postsamlgrant.py

Contains related REST API test cases for POST /oauth/saml_grant/<partner_subdomain>

Created by Leong He.
Copyright (c) 2011~2012 VMware. All rights reserved.
"""
__date__ = "20th Oct 2011"
__author__ = "Leong He<leongh@mozy.com>"
__version__ = "$Revision: #1 $"

import sys, re, logging, ast
import unittest
from restclient import Resource, rest
from urllib import urlencode
import utils

class PostSamlGrant(unittest.TestCase):
    def setUp(self):
        # set logging level
        # Need to be moved to somewhere else for global configuration
        debug = logging.DEBUG
        logging.basicConfig(level = debug, stream = sys.stderr, format = '%(levelname)s %(asctime)s [%(message)s]')
        logging.info("")
        self.token= utils.retrieve_token()

    def test_positive_post_saml_grant_check_keys(self):
        """
        Check the response contains correct keys.
        """
        rd = self.token
        logging.info("Return response in dictionary format is '%s'" % rd)
        keys = ['scope', 'access_token', 'token_type', 'expires_in', 'token_secret']
        self.assertTrue(utils.is_same_array(keys, rd.keys()), "Keys are not correct!")

    def test_positive_post_saml_grant_check_values(self):
        """
        Check the response contains correct values.
        """
        rd = self.token
        logging.info("Return response in dictionary format is '%s'" % rd)
        token_types = ['bearer']
        # assert 'token_type' is in the given values
        self.assertTrue(rd['token_type'] in token_types, "The 'token_type' is not in '%s'" % token_types)
        # assert 'access_token' is string type
        self.assertEqual(type(rd['access_token']), type(str("")), "The 'access_token' is not string type")
        # assert 'access_token' is 32 character-length
        self.assertEqual(len(rd['access_token']), 32, "The 'access_token' is not 32 character-long")
        # assert 'expires_in' is the integer type 
        self.assertEqual(type(rd['expires_in']), type(1), "The 'access_token' is not string type")
        # assert 'scope' ... (placeholder)

    def test_negative_post_saml_grant_partner_not_exist(self):
        """
        Check exception raised while posting for saml grant for not existent partner, and verify the exception contains correct error messages.
        """
        res = Resource("http://"+utils.sso_server)
        malpayloads = [utils.random_str()]
        for mp in malpayloads:
            logging.info("The malpayload acting not existent partner is '%s'" % mp)
            with self.assertRaises(rest.RequestFailed) as e:
                res.post('/oauth/saml_grant/' + mp, payload=utils.payload, headers=utils.headers)
            self.assertEqual(res.response.status, 400)
            # verify the retrieved exception is expected
            utils.verify_rest_requetfailed_exception(e, utils.get_exception('UnknownSubdomain', 'PostSamlGrantExceptions'), self)
        
    def test_negative_post_saml_grant_parameter_missing(self):
        """
        Check exception raised while posting for saml grant without required parameters (client_id, assertion), and verify the exception contains correct error messages.
        """
        res = Resource("http://"+utils.sso_server)
        malpayloads = [{'client_id': utils.client_id}, {'assertion': utils.assertion}, {}]
        for mp in malpayloads:
            logging.info("The malpayload acting parameter missing is '%s'" % mp)
            with self.assertRaises(rest.RequestFailed) as e:
                res.post('/oauth/saml_grant/' + utils.partner, payload=urlencode(mp), headers=utils.headers)
            self.assertEqual(res.response.status, 400)
            # verify the retrieved exception is expected
            utils.verify_rest_requetfailed_exception(e, utils.get_exception('ParameterMissing', 'PostSamlGrantExceptions'), self)

    def test_negative_post_saml_grant_access_denied(self):
        """
        Check exception raised while posting for saml grant with invalid assertion, and verify the exception contains correct error messages.
        """
        res = Resource("http://"+utils.sso_server)
        malpayloads = [{'client_id': utils.client_id, 'assertion': utils.random_str()}, {'client_id': utils.client_id, 'assertion': ''}]
        for mp in malpayloads:
            logging.info("The malpayload acting invalid assertion is '%s'" % mp)
            with self.assertRaises(rest.RequestFailed) as e:
                res.post('/oauth/saml_grant/'+utils.partner, payload=urlencode(mp), headers={'accept': 'application/json'})
            self.assertEqual(res.response.status, 400)
            # verify the retrieved exception is expected
            utils.verify_rest_requetfailed_exception(e, utils.get_exception('ParameterMissing', 'PostSamlGrantExceptions'), self)

    def test_negative_post_saml_grant_unauth_client(self):
        """
        Check exception raised while posting for saml grant with unauthorized client, and verify the exception contains correct error messages.
        """
        res = Resource("http://"+utils.sso_server)
        malpayloads = [{'client_id': utils.random_str(), 'assertion': utils.assertion}, {'assertion': '', 'client_id': ''}]
        for mp in malpayloads:
            logging.info("The malpayload acting unauthorized client is '%s'" % mp)
            with self.assertRaises(rest.RequestFailed) as e:
                res.post('/oauth/saml_grant/' + utils.partner, payload=urlencode(mp), headers=utils.headers)
            self.assertEqual(res.response.status, 400)
            # verify the retrieved exception is expected
            utils.verify_rest_requetfailed_exception(e, utils.get_exception('UnknownClient', 'PostSamlGrantExceptions'), self)


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(PostSamlGrant)
    unittest.TextTestRunner(verbosity=2).run(suite)
