#!/usr/bin/env python

"""
deletetokens.py

Contains related REST API test cases for DELETE /tokens/<access_token>

Created by Leong He.
Copyright (c) 2011~2012 VMware. All rights reserved.
"""
__date__ = "21th Oct 2011"
__author__ = "Leong He<leongh@mozy.com>"
__version__ = "$Revision: #1 $"

import sys, re, logging, ast, random
import unittest
from urllib import urlencode
from restclient import Resource, rest
import utils

class DeleteTokens(unittest.TestCase):
    def setUp(self):
        self.res = Resource("http://"+utils.sso_server)
        # set logging level
        # Need to be moved to somewhere else for global configuration
        debug = logging.DEBUG
        logging.basicConfig(level = debug, stream = sys.stderr, format = '%(levelname)s %(asctime)s [%(message)s]')
        logging.info("")
        self.token = utils.retrieve_token()

    def test_positive_delete_tokens_check_keys(self):
        """
        Check the response contains correct keys.
        """
        r = self.res.delete('/tokens/'+self.token['access_token'], headers=utils.headers)
        logging.info("Return response is '%s'" % r)
        # convert string to dictionary
        rd = ast.literal_eval(r)
        logging.info("Return response in dictionary format is '%s'" % rd)
        self.assertEqual(self.res.response.status, 200)
        keys = ['revoked_token_num']
        self.assertTrue(utils.is_same_array(keys, rd.keys()), "Keys are not correct!")

    def test_positive_delete_tokens_exist(self):
        """
        Delete tokens exist and check the 'revoked_token_num' is '1'
        """
        token = utils.retrieve_token(another=True)
        r = self.res.delete('/tokens/'+token['access_token'], headers=utils.headers)
        logging.info("Return response is '%s'" % r)
        self.assertEqual(self.res.response.status, 200)
        # convert string to dictionary
        rd = ast.literal_eval(r)
        logging.info("Return response in dictionary format is '%s'" % rd)
        # assert 'revoked_token_num' is 1
        self.assertEqual(rd['revoked_token_num'], 1, "The 'revoked_token_num' is not equal to 1")

    def test_negative_delete_tokens_not_exist(self):
        """
        Delete tokens not exist and check the 'revoked_token_num' is '0'
        """
        r = self.res.delete('/tokens/'+utils.random_str(), headers=utils.headers)
        logging.info("Return response is '%s'" % r)
        self.assertEqual(self.res.response.status, 200)
        # convert string to dictionary
        rd = ast.literal_eval(r)
        logging.info("Return response in dictionary format is '%s'" % rd)
        # assert 'revoked_token_num' is 1
        self.assertEqual(rd['revoked_token_num'], 0, "The 'revoked_token_num' is not equal to 0")

    def test_negative_delete_tokens_parameter_missing(self):
        """
        Check exception raised while deleting tokens without giving parameter, and verify the exception contains correct error messages.
        """
        malpayloads = ['']
        for mp in malpayloads:
            logging.info("The malpayload acting unauthorized client is '%s'" % mp)
            with self.assertRaises(rest.RequestFailed) as e:
                self.res.delete('/tokens/'+mp, headers=utils.headers)
            self.assertEqual(self.res.response.status, 400)
            # verify the retrieved exception is expected
            utils.verify_rest_requetfailed_exception(e, utils.get_exception('ParameterMissing', 'DeleteTokensExceptions'), self)
            
    def test_positive_delete_tokens_condition_exist(self):
        """
        Delete tokens with existing user_id and check the 'revoked_token_num' is >= '1'
        """
        token = utils.retrieve_token(another=True)
        r = self.res.get('/tokens/'+token['access_token'], headers=utils.headers)
        token = ast.literal_eval(r)
        r = self.res.delete('/tokens/?user_id='+str(token['user_id']), headers=utils.headers)
        logging.info("Return response is '%s'" % r)
        self.assertEqual(self.res.response.status, 200)
        # convert string to dictionary
        rd = ast.literal_eval(r)
        logging.info("Return response in dictionary format is '%s'" % rd)
        # assert 'revoked_token_num' is >= 1
        self.assertTrue((rd['revoked_token_num'] >= 1), "The 'revoked_token_num' is not >= 1")
        
    def test_negative_delete_tokens_condition_user_not_exist(self):
        """
        Delete tokens with not existing user_id and check the 'revoked_token_num' '0'
        """
        malpayloads = [str(random.randint(0,99)), utils.random_str()]
        for mp in malpayloads:
            logging.info("The malpayload acting not existent user_id is '%s'" % mp)
            r = self.res.delete('/tokens/?user_id='+mp, headers=utils.headers)
            self.assertEqual(self.res.response.status, 200)
            # convert string to dictionary
            rd = ast.literal_eval(r)
            logging.info("Return response in dictionary format is '%s'" % rd)
            # assert 'revoked_token_num' is 0
            self.assertEqual(rd['revoked_token_num'], 0, "The 'revoked_token_num' is not 0")
    
    def test_negative_delete_tokens_condition_parameter_missing(self):
        """
        Check exception raised while deleting tokens without giving client_id, and verify the exception contains correct error messages.
        """
        malpayloads = ['', 'client_id=']
        for mp in malpayloads:
            logging.info("The malpayload acting unauthorized client is '%s'" % mp)
            with self.assertRaises(rest.RequestFailed) as e:
                self.res.delete('/tokens/?'+mp, headers=utils.headers)
            self.assertEqual(self.res.response.status, 400)
            # verify the retrieved exception is expected
            utils.verify_rest_requetfailed_exception(e, utils.get_exception('ParameterMissing', 'DeleteTokensExceptions'), self)
            
    def test_negative_delete_tokens_condition_invalid_user(self):
        """
        Check exception raised while deleting tokens with invalid user_id, and verify the exception contains correct error messages.
        """
        malpayloads = ['', ' ']
        for mp in malpayloads:
            logging.info("The malpayload acting invalid user_id is '%s'" % mp)
            with self.assertRaises(rest.RequestFailed) as e:
                url = '/tokens/?user_id='+mp
                logging.debug("The requested url is '%s'" % url)
                self.res.delete(url, headers=utils.headers)
            # verify the retrieved exception is expected
            self.assertEqual(self.res.response.status, 400)


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(DeleteTokens)
    unittest.TextTestRunner(verbosity=2).run(suite)
