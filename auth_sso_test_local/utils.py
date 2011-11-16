#!/usr/bin/env python

"""
utils.py

Contains utilities leveraged by cases

Created by Leong He.
Copyright (c) 2011~2012 VMware. All rights reserved.
"""
__date__ = "19th Oct 2011"
__author__ = "Leong He<leongh@mozy.com>"
__version__ = "$Revision: #1 $"

import os, sys, re, logging, ast, random
import ConfigParser
import xml.dom.minidom
import httplib2
import unittest

from restclient import Resource, rest
from urllib import urlencode

token = None
auth_server = 'auth.mozy.com'
auth_partner = 'fedid'
auth_client_id = 'xanadu'
auth_client_secret = 'muse'
auth_client_redirect_uri = 'http://xanadu/'
auth_client_id_no_uri = 'leong_client_id'
auth_client_secret_no_uri = '123456'
sso_server = '10.135.16.139'
partner = 'fedid'
client_id = 'xanadu'
client_secret = 'muse'
headers = {'accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded'}
assertion = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWxwOlJlc3BvbnNlIERlc3RpbmF0aW9uPSJodHRwczovL2F1dGgubW96eS5jb20vZmVkaWQvc2FtbCIgSUQ9Il83ZTA3YzNhZjdkOTA0ZGJjMjM1OTM1YTI1NzMzZmRiYyIgSXNzdWVJbnN0YW50PSIyMDExLTExLTE1VDA3OjIwOjEwLjM0NloiIFZlcnNpb249IjIuMCIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCI+PHNhbWw6SXNzdWVyIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vbW96eWFkYXB0ZXIuaG9yaXpvbmxhYnMudm13YXJlLmNvbS9TQUFTL0FQSS8xLjAvR0VUL21ldGFkYXRhL2lkcC54bWw8L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgo8ZHM6U2lnbmVkSW5mbz4KPGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPgo8ZHM6UmVmZXJlbmNlIFVSST0iI183ZTA3YzNhZjdkOTA0ZGJjMjM1OTM1YTI1NzMzZmRiYyI+CjxkczpUcmFuc2Zvcm1zPgo8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz4KPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyI+PGVjOkluY2x1c2l2ZU5hbWVzcGFjZXMgUHJlZml4TGlzdD0iZHMgc2FtbCBzYW1scCIgeG1sbnM6ZWM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3JtPgo8L2RzOlRyYW5zZm9ybXM+CjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPgo8ZHM6RGlnZXN0VmFsdWU+RDI5bWlQNUtMQXppYWM1am5iRWM2ZGYzcXFRPTwvZHM6RGlnZXN0VmFsdWU+CjwvZHM6UmVmZXJlbmNlPgo8L2RzOlNpZ25lZEluZm8+CjxkczpTaWduYXR1cmVWYWx1ZT4KVE1WaEVuWWV2NUl5SGJKTXpiTTE4bXBiUFNrTytBRXRmUTlNamZIQkJpV1ArTGhBNzNRamJIaFBPcC8yM3hWMXJSOFdxdG5jMHlKYwpZTGI5TVFyeXg4ci9uemgvc1JlN21CN2NkbUZPanQ4cGdtNmlPTHcyM1p3QmY5eTVJalFWR0kvd2hmVGJWM3VWVkE5dzIycGJoQnR2CnhERFcvcUErczB5bG85ZGZhYmc9CjwvZHM6U2lnbmF0dXJlVmFsdWU+CjwvZHM6U2lnbmF0dXJlPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6U3RhdHVzPjxzYW1sOkFzc2VydGlvbiBJRD0iXzhlMjZhYjhkODVhZjQ2MjhhMTMxOGE5NTVjZGVlMDVhIiBJc3N1ZUluc3RhbnQ9IjIwMTEtMTEtMTVUMDc6MjA6MTAuMzQ2WiIgVmVyc2lvbj0iMi4wIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48c2FtbDpJc3N1ZXI+aHR0cHM6Ly9tb3p5YWRhcHRlci5ob3Jpem9ubGFicy52bXdhcmUuY29tL1NBQVMvQVBJLzEuMC9HRVQvbWV0YWRhdGEvaWRwLnhtbDwvc2FtbDpJc3N1ZXI+PHNhbWw6U3ViamVjdD48c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiIE5hbWVRdWFsaWZpZXI9Imh0dHBzOi8vbW96eWFkYXB0ZXIuaG9yaXpvbmxhYnMudm13YXJlLmNvbS9TQUFTL0FQSS8xLjAvR0VUL21ldGFkYXRhL2lkcC54bWwiPmFkbWluaXN0cmF0b3JAcWE1Lm1venlvcHMuY29tPC9zYW1sOk5hbWVJRD48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgTm90T25PckFmdGVyPSIyMDExLTExLTE1VDA3OjIzOjMwLjM0NloiIFJlY2lwaWVudD0iaHR0cHM6Ly9hdXRoLm1venkuY29tL2ZlZGlkL3NhbWwiLz48L3NhbWw6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWw6U3ViamVjdD48c2FtbDpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAxMS0xMS0xNVQwNzoxOTo1NS4zNDZaIiBOb3RPbk9yQWZ0ZXI9IjIwMTEtMTEtMTVUMDc6MjM6MzAuMzQ2WiI+PHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDpBdWRpZW5jZT5odHRwczovL2F1dGgubW96eS5jb20vZmVkaWQvc2FtbDwvc2FtbDpBdWRpZW5jZT48L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTEtMTEtMTVUMDc6MjA6MTAuMzQ2WiIgU2Vzc2lvbkluZGV4PSJfNzU0ZDQ1NWE3OTU0NTJmYmI2YjE3NzNiMzA2M2M4MDciPjxzYW1sOkF1dGhuQ29udGV4dD48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWw6QXV0aG5Db250ZXh0Pjwvc2FtbDpBdXRoblN0YXRlbWVudD48c2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQvPjwvc2FtbDpBc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4="
p = {"client_id": client_id, "assertion": assertion}
payload = urlencode(p)
SAMLResponse = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWxwOlJlc3BvbnNlIERlc3RpbmF0aW9uPSJodHRwczovL2F1dGgubW96eS5jb20vZmVkaWQvc2FtbCIgSUQ9Il83ZTA3YzNhZjdkOTA0ZGJjMjM1OTM1YTI1NzMzZmRiYyIgSXNzdWVJbnN0YW50PSIyMDExLTExLTE1VDA3OjIwOjEwLjM0NloiIFZlcnNpb249IjIuMCIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCI+PHNhbWw6SXNzdWVyIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vbW96eWFkYXB0ZXIuaG9yaXpvbmxhYnMudm13YXJlLmNvbS9TQUFTL0FQSS8xLjAvR0VUL21ldGFkYXRhL2lkcC54bWw8L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgo8ZHM6U2lnbmVkSW5mbz4KPGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPgo8ZHM6UmVmZXJlbmNlIFVSST0iI183ZTA3YzNhZjdkOTA0ZGJjMjM1OTM1YTI1NzMzZmRiYyI+CjxkczpUcmFuc2Zvcm1zPgo8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz4KPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyI+PGVjOkluY2x1c2l2ZU5hbWVzcGFjZXMgUHJlZml4TGlzdD0iZHMgc2FtbCBzYW1scCIgeG1sbnM6ZWM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3JtPgo8L2RzOlRyYW5zZm9ybXM+CjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPgo8ZHM6RGlnZXN0VmFsdWU+RDI5bWlQNUtMQXppYWM1am5iRWM2ZGYzcXFRPTwvZHM6RGlnZXN0VmFsdWU+CjwvZHM6UmVmZXJlbmNlPgo8L2RzOlNpZ25lZEluZm8+CjxkczpTaWduYXR1cmVWYWx1ZT4KVE1WaEVuWWV2NUl5SGJKTXpiTTE4bXBiUFNrTytBRXRmUTlNamZIQkJpV1ArTGhBNzNRamJIaFBPcC8yM3hWMXJSOFdxdG5jMHlKYwpZTGI5TVFyeXg4ci9uemgvc1JlN21CN2NkbUZPanQ4cGdtNmlPTHcyM1p3QmY5eTVJalFWR0kvd2hmVGJWM3VWVkE5dzIycGJoQnR2CnhERFcvcUErczB5bG85ZGZhYmc9CjwvZHM6U2lnbmF0dXJlVmFsdWU+CjwvZHM6U2lnbmF0dXJlPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6U3RhdHVzPjxzYW1sOkFzc2VydGlvbiBJRD0iXzhlMjZhYjhkODVhZjQ2MjhhMTMxOGE5NTVjZGVlMDVhIiBJc3N1ZUluc3RhbnQ9IjIwMTEtMTEtMTVUMDc6MjA6MTAuMzQ2WiIgVmVyc2lvbj0iMi4wIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48c2FtbDpJc3N1ZXI+aHR0cHM6Ly9tb3p5YWRhcHRlci5ob3Jpem9ubGFicy52bXdhcmUuY29tL1NBQVMvQVBJLzEuMC9HRVQvbWV0YWRhdGEvaWRwLnhtbDwvc2FtbDpJc3N1ZXI+PHNhbWw6U3ViamVjdD48c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiIE5hbWVRdWFsaWZpZXI9Imh0dHBzOi8vbW96eWFkYXB0ZXIuaG9yaXpvbmxhYnMudm13YXJlLmNvbS9TQUFTL0FQSS8xLjAvR0VUL21ldGFkYXRhL2lkcC54bWwiPmFkbWluaXN0cmF0b3JAcWE1Lm1venlvcHMuY29tPC9zYW1sOk5hbWVJRD48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgTm90T25PckFmdGVyPSIyMDExLTExLTE1VDA3OjIzOjMwLjM0NloiIFJlY2lwaWVudD0iaHR0cHM6Ly9hdXRoLm1venkuY29tL2ZlZGlkL3NhbWwiLz48L3NhbWw6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWw6U3ViamVjdD48c2FtbDpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAxMS0xMS0xNVQwNzoxOTo1NS4zNDZaIiBOb3RPbk9yQWZ0ZXI9IjIwMTEtMTEtMTVUMDc6MjM6MzAuMzQ2WiI+PHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDpBdWRpZW5jZT5odHRwczovL2F1dGgubW96eS5jb20vZmVkaWQvc2FtbDwvc2FtbDpBdWRpZW5jZT48L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTEtMTEtMTVUMDc6MjA6MTAuMzQ2WiIgU2Vzc2lvbkluZGV4PSJfNzU0ZDQ1NWE3OTU0NTJmYmI2YjE3NzNiMzA2M2M4MDciPjxzYW1sOkF1dGhuQ29udGV4dD48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWw6QXV0aG5Db250ZXh0Pjwvc2FtbDpBdXRoblN0YXRlbWVudD48c2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQvPjwvc2FtbDpBc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4="
b = {'SAMLResponse': SAMLResponse}
auth_body = urlencode(b)

def auth_get_auth(auth_server = auth_server, partner = partner, auth_client_id = auth_client_id):
    """ Get Auth SAML from Horizon
    """
    # get auth first
    url = 'http://' + auth_server + '/' + auth_partner + '/authorize?' + 'response_type=token' + '&client_id=' + auth_client_id
    logging.info("The requested url is '%s'" % url)
    http = httplib2.Http()
    http.follow_redirects = False
    head, content = http.request(url, 'GET', headers = headers)
    logging.info("Return head is '%s'" % head)
    logging.info("Return content is '%s'" % content)
    return head, content

def is_same_array(arrayA, arrayB):
    """ Compare 2 given arrays if contain the same content.
        True:   If 2 arrays contain the same content regardless of order.
        False:  If 2 arrays contain different content.
    """
    issame = True
    logging.info("Array A length is '%s' and contents are '%s'" % (len(arrayA), str(arrayA)))
    logging.info("Array B length is '%s' and contents are '%s'" % (len(arrayB), str(arrayB)))
    for a in arrayA:
        if not (a in arrayB):
            issame = False
            return issame
    for a in arrayB:
        if not (a in arrayA):
            issame = False
            return issame
    return issame

def retrieve_token(sso_server = sso_server, partner = partner, payload = payload, another = False):
    """ Retrieve token grant by posting to /oauth/saml_grant/<partner_subdomain>
        Parameters:
            sso_server
            partner subdomain
            payload includes client_id and assertion
            another True - Retrieve a new SAML. False - Return the existing one
        Return: 
            SAML
    """
    global token 
    if token and not another:
    # Not need another and return the existing one
        return token
    elif not token and not another:
    # Not need another but not have an existing one, retrieve one
        res = Resource("http://"+sso_server)
        r = res.post('/oauth/saml_grant/'+partner, payload=payload, headers=headers)
        token = ast.literal_eval(r)
        logging.info("The token retrieved is '%s'" % str(token))
        return token
    else:
    # Retrieve another one
        res = Resource("http://"+sso_server)
        r = res.post('/oauth/saml_grant/'+partner, payload=payload, headers=headers)
        ntoken = ast.literal_eval(r)
        logging.info("The another token retrieved is '%s'" % str(ntoken))
        return ntoken
        

def random_str(count = 10, chars = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        """ Used to generate a random string in which all the character is from '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' defaultly, you can also specify the source string.
        Parameters:
             count - is the lenth of the random string.
        """
        logging.debug('Generating a random string')
        i = 0
        randomstr = ''
        while i < count:
            randomstr += random.choice(chars)
            i += 1
        logging.debug("The generated random string is '%s'" % randomstr)
        return randomstr

def get_exception(item, itemgroup, tdf = 'testdata/sso_td.xml'):
    """ Return exceptions including 'error_description' and 'error' pair as dictionary"""
    exc = {'error': '', 'error_description': ''}
    d = get_dom(tdf)
    i = handle_itemgroup(d, itemgroup)
    itemNames = i.getElementsByTagName("item")
    for itemname in itemNames:
        if itemname.getAttribute("name") == item:
            exc['error'] = itemname.getAttribute("error")
            exc['error_description'] = itemname.getAttribute("error_description")
    return exc

def get_testdata(item, itemgroup, tdf = 'testdata/sso_td.xml'):
    """ Return values array with given itemgroup and item name"""
    d = get_dom(tdf)
    i = handle_itemgroup(d, itemgroup)
    v = handle_items(i, item)
    r = handle_values(v)
    return r

def handle_values(itemelement):
    values = itemelement.getElementsByTagName("value")
    r = []
    for v in values:
        if None == v.firstChild: 
            r.append('')
        else:
            r.append(v.firstChild.data)
    return r
            
def handle_items(groupelement, item):
    itemNames = groupelement.getElementsByTagName("item")
    for itemname in itemNames:
        if itemname.getAttribute("name") == item:
            return itemname

def handle_itemgroup(dom, group):
    itemGroups = dom.getElementsByTagName("itemgroup")
    for itemgroup in itemGroups:
        if itemgroup.getAttribute("name") == group:
            return itemgroup
    
def get_dom(file):
    """ Get dom from the given test data xml file"""
    sourceDir = os.path.dirname(os.path.abspath(sys.argv[0]))
    fileDir = file
    if not os.path.isabs(file):
        # not absolute path
        fileDir = os.path.join(sourceDir, file)
    datasource = open(fileDir)
    dom = xml.dom.minidom.parse(datasource)
    datasource.close()        
    return dom

def get_config(option, section = 'sso', cfg = 'testdata/sso.conf'):
    """ Get configured value from given config file"""
    sourceDir = os.path.dirname(os.path.abspath(sys.argv[0]))
    fileDir = cfg
    if not os.path.isabs(cfg):
        # not absolute path
        fileDir = os.path.join(sourceDir, cfg)
    config = ConfigParser.ConfigParser()
    config.read(fileDir)
    return config.get(section, option)

def verify_rest_requetfailed_exception(restexc, expectexc, tc, malparameter = None):
    """ Verify the rest.RequestFailed exception equals the expected exception.
        Parameters:
             restexc - rest.RequestFailed exception object
             expectexc - homemade expected exception in dictionary object {"error_description":"Unkown client.","error":"invalid_client"}
             tc - the test case instance
             malparameter - the malparameter caused the exception
    """
    if type(restexc) == unittest.case._AssertRaisesContext:
        logging.debug("The retrieved exception message is '%s'" % str(restexc.exception))
        exc = ast.literal_eval(str(restexc.exception))
    elif type(restexc) == type(str()):
        exc = ast.literal_eval(restexc)
    else:
        exc = restexc
    if not malparameter == None:
        errormsg = expectexc['error_description'] % malparameter
    else:
        errormsg = expectexc['error_description']
    logging.info("The retrieved exception is '%s'" % str(exc))
    logging.info("The expected exception is '%s'" % str(errormsg))
    # assert the 'error_description' is correct
    tc.assertEqual(exc['error_description'], errormsg)
    # assert the 'error' is correct
    tc.assertEqual(exc['error'], expectexc['error'])
