#!/usr/bin/env python

"""
auth_getspmeta.py

Contains related REST API test cases for GET /<partner_subdomain>/saml/metadata/sp.xml

Created by Leong He.
Copyright (c) 2011~2012 VMware. All rights reserved.
"""
__date__ = "9th Nov 2011"
__author__ = "Leong He<hel@vmware.com>"
__version__ = "$Revision: #1 $"

import sys, re, logging, ast
import httplib2, urllib
import xml.dom.minidom
import base64
import unittest
from restclient import Resource, rest
import utils


class AuthGetSPMeta(unittest.TestCase):
    def setUp(self):
        self.http = httplib2.Http()
        self.url = 'http://' + utils.auth_server + '/' + utils.auth_partner + '/saml/metadata/sp.xml'
        # set logging level
        # Need to be moved to somewhere else for global configuration
        debug = logging.DEBUG
        logging.basicConfig(level = debug, stream = sys.stderr, format = '%(levelname)s %(asctime)s [%(message)s]')
        logging.info("")


    def test_positive_auth_get_sp_metadata_check_return(self):
        """
        Check the response contains correct return, and validate xml file syntax is correct.
        """
        # get metadata xml 
        logging.debug("The requested url is '%s'" % str(self.url))
        h, c = self.http.request(self.url, 'GET', headers = utils.headers)
        logging.debug("The response head is '%s'" % str(h))
        logging.debug("The response body is '%s'" % str(c))
        # assert head is correct
        self.assertEqual(int(h['status']), 200)
        # validate xml syntax is correct 
        xml.dom.minidom.parseString(c)
        

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(AuthGetSPMeta)
    unittest.TextTestRunner(verbosity=2).run(suite)
