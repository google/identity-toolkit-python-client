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

"""Unit test for GitkitClient."""

import base64
import unittest
import urlparse

import mock

from identitytoolkit import gitkitclient


class GitkitClientTest(unittest.TestCase):

  def setUp(self):
    self.widget_url = 'http://localhost:9000/widget'
    self.gitkitclient = gitkitclient.GitkitClient('', '', '', self.widget_url)
    self.user_id = '1234'
    self.email = 'user@example.com'
    self.user_name = 'Joe'
    self.user_photo = 'http://idp.com/photo'

  def testVerifyToken(self):
    with mock.patch('identitytoolkit.rpchelper.RpcHelper.GetPublicCert') as rpc_mock:
      rpc_mock.return_value = {'kid': 'cert'}
      with mock.patch('oauth2client.crypt.'
                      'verify_signed_jwt_with_certs') as crypt_mock:
        crypt_mock.return_value = {
            'localId': self.user_id,
            'email': self.email,
            'display_name': self.user_name
        }
        gitkit_user = self.gitkitclient.VerifyGitkitToken('token')
        self.assertEqual(self.user_id, gitkit_user.user_id)
        self.assertEqual(self.email, gitkit_user.email)
        self.assertEqual(self.user_name, gitkit_user.name)
        self.assertIsNone(gitkit_user.photo_url)
        self.assertEqual({}, gitkit_user.provider_info)

  def testGetAccountInfo(self):
    with mock.patch('identitytoolkit.rpchelper.RpcHelper._InvokeGitkitApi') as rpc_mock:
      rpc_mock.return_value = {'users': [{
          'email': self.email,
          'localId': self.user_id,
          'displayName': self.user_name,
          'photoUrl': self.user_photo
      }]}
      gitkit_user = self.gitkitclient.GetUserByEmail(self.email)
      self.assertEqual(self.user_id, gitkit_user.user_id)
      self.assertEqual(self.email, gitkit_user.email)
      self.assertEqual(self.user_name, gitkit_user.name)
      self.assertEqual(self.user_photo, gitkit_user.photo_url)

  def testUploadAccount(self):
    hash_algorithm = gitkitclient.ALGORITHM_HMAC_SHA256
    hash_key = 'key123'
    upload_user = gitkitclient.GitkitUser.FromDictionary({
        'email': self.email,
        'localId': self.user_id,
        'displayName': self.user_name,
        'photoUrl': self.user_photo
    })
    with mock.patch('identitytoolkit.rpchelper.RpcHelper._InvokeGitkitApi') as rpc_mock:
      rpc_mock.return_value = {}
      self.gitkitclient.UploadUsers(hash_algorithm, hash_key, [upload_user])
      expected_param = {
          'hashAlgorithm': hash_algorithm,
          'signerKey': base64.urlsafe_b64encode(hash_key),
          'users': [{
              'email': self.email,
              'localId': self.user_id,
              'displayName': self.user_name,
              'photoUrl': self.user_photo
          }]
      }
      rpc_mock.assert_called_with('uploadAccount', expected_param)

  def testDownloadAccount(self):
    with mock.patch('identitytoolkit.rpchelper.RpcHelper._InvokeGitkitApi') as rpc_mock:
      # First paginated request
      rpc_mock.return_value = {
          'nextPageToken': '100',
          'users': [
              {'email': self.email, 'localId': self.user_id},
              {'email': 'another@example.com', 'localId': 'another'}
          ]
      }
      iterator = self.gitkitclient.GetAllUsers()
      self.assertEqual(self.email, iterator.next().email)
      self.assertEqual('another@example.com', iterator.next().email)

      # Should stop since no more result
      rpc_mock.return_value = {}
      self.assertRaises(StopIteration, iterator.next)

      expected_call = [(('downloadAccount', {'maxResults': 10}),),
                       (('downloadAccount',
                         {'nextPageToken': '100', 'maxResults': 10}),)]
      self.assertEqual(expected_call, rpc_mock.call_args_list)

  def testGetOobResult(self):
    code = '1234'
    with mock.patch('identitytoolkit.rpchelper.RpcHelper._InvokeGitkitApi') as rpc_mock:
      rpc_mock.return_value = {'oobCode': code}
      widget_request = {
          'action': 'resetPassword',
          'email': self.email,
          'response': '8888'
      }
      result = self.gitkitclient.GetOobResult(widget_request, '1.1.1.1')
      self.assertEqual('resetPassword', result['action'])
      self.assertEqual(self.email, result['email'])
      self.assertEqual(code, result['oob_code'])
      self.assertEqual('{"success": true}', result['response_body'])
      self.assertTrue(result['oob_link'].startswith(self.widget_url))
      url = urlparse.urlparse(result['oob_link'])
      query = urlparse.parse_qs(url.query)
      self.assertEqual('resetPassword', query['mode'][0])
      self.assertEqual(code, query['oobCode'][0])

  def testGetEmailVerificationLink(self):
      code = '1234'
      with mock.patch('identitytoolkit.rpchelper.RpcHelper._InvokeGitkitApi') as rpc_mock:
          rpc_mock.return_value = {'oobCode': code}
          result = self.gitkitclient.GetEmailVerificationLink('user@example.com')
          self.assertTrue(result.startswith(self.widget_url))
          url = urlparse.urlparse(result)
          query = urlparse.parse_qs(url.query)
          self.assertEqual('verifyEmail', query['mode'][0])
          self.assertEqual(code, query['oobCode'][0])

if __name__ == '__main__':
  unittest.main()
