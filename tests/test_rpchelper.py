# Copyright 2014 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit test for RpcHelper."""
try:
    from io import StringIO
    from unittest import mock
except ImportError:
    from StringIO import StringIO
    import mock

import unittest
import simplejson
import sys

from identitytoolkit import errors
from identitytoolkit import rpchelper


class RpcHelperTestCase(unittest.TestCase):

  def setUp(self):
    self.api_url = '/widget'
    self.service_email = 'dev@content.google.com'
    self.rpchelper = rpchelper.RpcHelper(self.service_email, '', self.api_url,
                                         'api_key', None)

  def testGitkitClientError(self):
    error_response = {
        'error': {
            'code': 400,
            'message': 'invalid email'
        }
    }
    try:
      self.rpchelper._CheckGitkitError(simplejson.dumps(error_response))
      self.fail('GitkitClientException expected')
    except errors.GitkitClientError as error:
      self.assertEqual(error_response['error']['message'], error.value)

  def testGitkitServerError(self):
    try:
      self.rpchelper._CheckGitkitError('')
      self.fail('GitkitServerException expected')
    except errors.GitkitServerError as error:
      self.assertEqual('null error code from Gitkit server', error.value)

  def testGetAccessToken(self):
    self.rpchelper._GenerateAssertion = mock.MagicMock()
    if sys.version_info[0] > 2:
      str_urlopen = 'urllib.request.urlopen'
    else:
      str_urlopen = 'urllib2.urlopen'
    with mock.patch(str_urlopen) as url_mock:
      url_mock.return_value = StringIO('{"access_token": "token"}')
      result = self.rpchelper._GetAccessToken()
      self.assertEqual('token', result)
    

  def testGenerateAssertion(self):
    with mock.patch('oauth2client.crypt.Signer.from_string') as signer_mock:
      signer_mock.return_value = ''
      with mock.patch('oauth2client.crypt.make_signed_jwt') as crypt_mock:
        self.rpchelper._GenerateAssertion()
        _, args, _ = crypt_mock.mock_calls[0]
        payload = args[1]  # args[0] is signer
        self.assertEqual('https://accounts.google.com/o/oauth2/token',
                         payload['aud'])
        self.assertEqual(self.service_email, payload['iss'])
        self.assertEqual('https://www.googleapis.com/auth/identitytoolkit',
                         payload['scope'])

if __name__ == '__main__':
  unittest.main()
