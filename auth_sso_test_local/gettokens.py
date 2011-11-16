#!/usr/bin/env python

"""
gettokens.py

Contains related REST API test cases for GET /tokens/<access_token>

Created by Leong He.
Copyright (c) 2011~2012 VMware. All rights reserved.
"""
__date__ = "20th Oct 2011"
__author__ = "Leong He<leongh@mozy.com>"
__version__ = "$Revision: #1 $"

import sys, re, logging, ast
import unittest
from restclient import Resource, rest
import utils

class GetTokens(unittest.TestCase):
    def setUp(self):
        self.res = Resource("http://"+utils.sso_server)
        # set logging level
        # Need to be moved to somewhere else for global configuration
        debug = logging.DEBUG
        logging.basicConfig(level = debug, stream = sys.stderr, format = '%(levelname)s %(asctime)s [%(message)s]')
        logging.info("")
        # post saml grant
        self.token = utils.retrieve_token()

    def test_positive_get_tokens_check_keys(self):
        """
        Check the response contains correct keys.
        """
        r = self.res.get('/tokens/'+self.token['access_token'], headers=utils.headers)
        logging.info("Return response is '%s'" % r)
        # convert string to dictionary
        rd = ast.literal_eval(r)
        logging.info("Return response in dictionary format is '%s'" % rd)
        self.assertEqual(self.res.response.status, 200)
        keys = ['access_token_expires_at', 'user_id', 'access_token', 'user', 'client_id', 'access_token_secret', 'permissions']
        self.assertTrue(utils.is_same_array(keys, rd.keys()), "Keys are not correct!")

    def test_positive_get_tokens_check_values(self):
        """
        Check the response contains correct values.
        """
        r = self.res.get('/tokens/'+self.token['access_token'], headers=utils.headers)
        logging.info("Return response is '%s'" % r)
        # convert string to dictionary
        rd = ast.literal_eval(r)
        logging.info("Return response in dictionary format is '%s'" % rd)
        self.assertEqual(self.res.response.status, 200)
        # assert 'access_token_expires_at' is in the given values
        p = re.compile("\d{4,4}(\-\d\d){2,2}T(\d\d:){2,2}\d\dZ")
        self.assertTrue(p.match(rd['access_token_expires_at']), "The 'access_token_expires_at' does not match '2011-10-21T11:28:39Z'")
        # assert 'user_id' is integer
        self.assertEqual(type(rd['client_id']), type(1), "The 'client_id' is not integer")
        # assert 'access_token' is equal to the one given in token
        self.assertEqual(rd['access_token'], self.token['access_token'], "The 'access_token' is not equal to the one given in token")
        # assert 'user' is a dictionary object
        self.assertEqual(type(rd['user']), type({}), "The 'user' is not dictionary")
        # assert 'user' has the 'name', 'custom_permission', 'email' and 'id' fields.
        keys = ['name', 'custom_permission', 'email', 'id']
        self.assertTrue(utils.is_same_array(keys, rd['user'].keys()), "The 'user' keys are not correct!")
        #   assert 'user:name' is string
        self.assertEqual(type(rd['user']['name']), type(""), "The 'user:name' is not string")
        #   assert 'user:custom_permission' is list
        self.assertEqual(type(rd['user']['custom_permission']), type([]), "The 'user:custom_permission' is not list")
        #   assert 'user:email' is correct format
        pe = re.compile("[\w\-\._]+@[\w]+\.[\w]+")
        self.assertTrue(pe.match(rd['user']['email']), "The 'user:email' does not match email address")
        #   assert 'user:id' is integer and equal to the 'user_id'
        self.assertEqual(rd['user']['id'], rd['user_id'], "The 'user:id' does not equal to 'user_id'")
        # assert 'client_id' is integer
        self.assertEqual(type(rd['client_id']), type(1), "The 'client_id' is not integer")
        # assert 'access_token_secret' is 32 character long
        self.assertEqual(len(rd['access_token_secret']), 32, "The  'access_token_secret' is not 32 character-long")
        # assert 'permissions' is a list and values are in the given range
        self.assertEqual(type(rd['permissions']), type([]), "The 'permissions' is not a list")
        permissions = ['triton_manifest', 'triton_read', 'triton_write', 'mip_fs_read', 'mip_fs_write', 'mip_photos_read', 'mip_photos_write']
        for p in rd['permissions']:
            assertTrue( p in permissions, "The 'permissions' - '%s' is not in the permission list" % p)

    def test_negative_get_tokens_invalid_token(self):
        """
        Check exception raised while getting tokens information with invalid tokens, and verify the exception contains correct error messages.
        """
        malpayloads = [utils.random_str()]
        for mp in malpayloads:
            logging.info("The malpayload acting unauthorized client is '%s'" % mp)
            with self.assertRaises(Exception) as e:
                self.res.get('/tokens/'+mp, headers=utils.headers)
            self.assertEqual(self.res.response.status, 404)
            # verify the retrieved exception is expected
            utils.verify_rest_requetfailed_exception(e, utils.get_exception('InvalidToken', 'GetTokensExceptions'), self)
            
    def test_negative_get_tokens_parameter_missing(self):
        """
        Check exception raised while getting tokens information without tokens given, and verify the exception contains correct error messages.
        """
        malpayloads = ['']
        for mp in malpayloads:
            logging.info("The malpayload acting unauthorized client is '%s'" % mp)
            with self.assertRaises(Exception) as e:
                self.res.get('/tokens/'+mp, headers=utils.headers)
            self.assertEqual(self.res.response.status, 405)
            # verify the retrieved exception is expected
            # Marked out due to behavior changed
            # utils.verify_rest_requetfailed_exception(e, utils.get_exception('ParameterMissing', 'GetTokensExceptions'), self)

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(GetTokens)
    unittest.TextTestRunner(verbosity=2).run(suite)
