#!/usr/bin/env python

"""
getauth.py

Contains related REST API test cases for Get /auth/config/<partner_subdomain>

Created by Leong He.
Copyright (c) 2011~2012 VMware. All rights reserved.
"""
__date__ = "19th Oct 2011"
__author__ = "Leong He<leongh@mozy.com>"
__version__ = "$Revision: #1 $"

import sys, re, logging, ast
import unittest
from restclient import Resource, rest
import utils


class GetAuth(unittest.TestCase):
    def setUp(self):
        self.res = Resource("http://"+utils.sso_server)
        # set logging level
        # Need to be moved to somewhere else for global configuration
        debug = logging.DEBUG
        logging.basicConfig(level = debug, stream = sys.stderr, format = '%(levelname)s %(asctime)s [%(message)s]')
        logging.info("")

    def test_postive_get_auth_horizon_check_keys(self):
        """
        Check the response contains correct keys.
        """
        r = self.res.get('/auth/config/'+utils.partner, headers=utils.headers)
        logging.info("Return response is '%s'" % r)
        # convert string to dictionary
        rd = ast.literal_eval(r)
        logging.info("Return response in dictionary format is '%s'" % rd)
        self.assertEqual(self.res.response.status, 200)
        keys = ['type', 'web_endpoint', 'client_endpoint', 'org_name']
        self.assertTrue(utils.is_same_array(keys, rd.keys()), "Keys are not correct!")

    def test_positive_get_auth_horizon_check_values(self):
        """
        Check the response contains correct values.
        """
        r = self.res.get('/auth/config/'+(utils.partner), headers=utils.headers)
        logging.info("Return response is '%s'" % r)
        # convert string to dictionary
        rd = ast.literal_eval(r)
        logging.info("Return response in dictionary format is '%s'" % rd)
        self.assertEqual(self.res.response.status, 200)
        types = ['mozy', 'cbeyond', 'horizon']
        # assert 'type' is in the 3 values
        self.assertTrue(rd['type'] in types, "The 'type' is not in '%s'" % types)
        # assert 'web_endpoint' is the url format
        p = re.compile("(https:\/\/)*[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&amp;:/~\+#]*[\w\-\@?^=%&amp;/~\+#])?")
        self.assertTrue(p.match(rd['web_endpoint']), "The 'web_endpoint' does not match URL format")
        # assert 'client_endpoint' is the url format
        self.assertTrue(p.match(rd['client_endpoint']), "The 'client_endpoint' does not match URL format")
        # assert 'horizon_org_name' is at least a string type
        self.assertEqual(type(rd['org_name']), type(str("")), "The 'org_name' is not string type")

    def test_negative_get_auth_horizon_partner_not_exist(self):
        """
        Check exception raised while getting auth for not existent partner, and verify the exception contains correct error messages.
        """
        nosub = utils.random_str()
        logging.info("The not existent subdomain to be tested is '%s'" % nosub)
        with self.assertRaises(rest.RequestFailed) as e:
            self.res.get('/auth/config/' + (nosub), headers=utils.headers)
        self.assertEqual(self.res.response.status, 400)
        # verify the exception is expected
        utils.verify_rest_requetfailed_exception(e,utils.get_exception('UnknownSubdomain', 'GetAuthExceptions'), self) 


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(GetAuth)
    unittest.TextTestRunner(verbosity=2).run(suite)
