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

"""Google Identity Toolkit remote API wrapper.

Used by gitkitclient.py to handle http interactions with Gitkit server. Third
party developers do not need to call this class directly.
"""

import time
import urllib
import urllib2

import httplib2
from oauth2client import client
from oauth2client import crypt
import simplejson

import errors


class RpcHelper(object):
  """Helper class to invoke Gitkit remote API."""

  TOKEN_ENDPOINT = 'https://accounts.google.com/o/oauth2/token'
  MAX_TOKEN_LIFETIME_SECS = 3600  # 1 hour in seconds

  def __init__(self, service_account_email, service_account_key,
               google_api_url, server_api_key, http):
    self.service_account_email = service_account_email
    self.service_account_key = service_account_key
    self.google_api_url = google_api_url + 'identitytoolkit/v3/relyingparty/'
    self.server_api_key = server_api_key
    if http is None:
      self.http = httplib2.Http(client.MemoryCache())
    else:
      self.http = http

  def GetAccountInfoByEmail(self, email):
    """Gets account info of an email.

    Args:
      email: string, user email.

    Returns:
      A dict of user attribute.
    """
    response = self._InvokeGitkitApi('getAccountInfo', {'email': [email]})
    # pylint does not recognize the return type of simplejson.loads
    # pylint: disable=maybe-no-member
    return response['users'][0]

  def GetAccountInfoById(self, user_id):
    """Gets account info of a user id.

    Args:
      user_id: string, user id.

    Returns:
      A dict of user attribute.
    """
    response = self._InvokeGitkitApi('getAccountInfo', {'localId': [user_id]})
    # pylint does not recognize the return type of simplejson.loads
    # pylint: disable=maybe-no-member
    return response['users'][0]

  def GetOobCode(self, request):
    """Gets out-of-band code requested by user.

    Args:
      request: dict, the request details.

    Returns:
      Out of band code string.
    """
    response = self._InvokeGitkitApi('getOobConfirmationCode', request)
    # pylint does not recognize the return type of simplejson.loads
    # pylint: disable=maybe-no-member
    return response.get('oobCode', None)

  def DownloadAccount(self, next_page_token=None, max_results=None):
    """Downloads multiple accounts from Gitkit server.

    Args:
      next_page_token: string, pagination token.
      max_results: pagination size.

    Returns:
      An array of accounts.
    """
    param = {}
    if next_page_token:
      param['nextPageToken'] = next_page_token
    if max_results:
      param['maxResults'] = max_results
    response = self._InvokeGitkitApi('downloadAccount', param)
    # pylint does not recognize the return type of simplejson.loads
    # pylint: disable=maybe-no-member
    return response.get('nextPageToken', None), response.get('users', {})

  def UploadAccount(self, hash_algorithm, hash_key, accounts):
    """Uploads multiple accounts to Gitkit server.

    Args:
      hash_algorithm: string, algorithm to hash password.
      hash_key: string, base64-encoded key of the algorithm.
      accounts: array of accounts to be uploaded.

    Returns:
      Response of the API.
    """
    param = {
        'hashAlgorithm': hash_algorithm,
        'signerKey': hash_key,
        'users': accounts
    }
    # pylint does not recognize the return type of simplejson.loads
    # pylint: disable=maybe-no-member
    return self._InvokeGitkitApi('uploadAccount', param)

  def DeleteAccount(self, local_id):
    """Deletes an account.

    Args:
      local_id: string, user id to be deleted.

    Returns:
      API response.
    """
    # pylint does not recognize the return type of simplejson.loads
    # pylint: disable=maybe-no-member
    return self._InvokeGitkitApi('deleteAccount', {'localId': local_id})

  def GetPublicCert(self):
    """Download Gitkit public cert.

    Returns:
      dict of public certs.
    """

    if self.server_api_key:
      cert_url = self.google_api_url + 'publicKeys?key=' + self.server_api_key
      headers = None
    else:
      cert_url = self.google_api_url + 'publicKeys'
      headers = {'Authorization': 'Bearer ' + self._GetAccessToken()}

    resp, content = self.http.request(cert_url, headers=headers)
    if resp.status == 200:
      return simplejson.loads(content)
    else:
      raise errors.GitkitServerError('Error response for cert url: %s' %
                                     content)

  def _InvokeGitkitApi(self, method, params, need_service_account=True):
    """Invokes Gitkit API, with optional access token for service account.

    Args:
      method: string, the api method name.
      params: dict of optional parameters for the API.
      need_service_account: false if service account is not needed.

    Raises:
      GitkitClientError: if the request is bad.
      GitkitServerError: if Gitkit can not handle the request.

    Returns:
      API response as dict.
    """
    body = simplejson.dumps(params)
    req = urllib2.Request(self.google_api_url + method)
    req.add_header('Content-type', 'application/json')
    if need_service_account:
      req.add_header('Authorization', 'Bearer ' + self._GetAccessToken())
    raw_response = urllib2.urlopen(req, body).read()
    return self._CheckGitkitError(raw_response)

  def _GetAccessToken(self):
    """Gets oauth2 access token for Gitkit API using service account.

    Returns:
      string, oauth2 access token.
    """
    body = urllib.urlencode({
        'assertion': self._GenerateAssertion(),
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    })
    req = urllib2.Request(RpcHelper.TOKEN_ENDPOINT)
    req.add_header('Content-type', 'application/x-www-form-urlencoded')
    raw_response = urllib2.urlopen(req, body)
    return simplejson.loads(raw_response.read())['access_token']

  def _GenerateAssertion(self):
    """Generates the signed assertion that will be used in the request.

    Returns:
      string, signed Json Web Token (JWT) assertion.
    """
    now = long(time.time())
    payload = {
        'aud': RpcHelper.TOKEN_ENDPOINT,
        'scope': 'https://www.googleapis.com/auth/identitytoolkit',
        'iat': now,
        'exp': now + RpcHelper.MAX_TOKEN_LIFETIME_SECS,
        'iss': self.service_account_email
    }
    return crypt.make_signed_jwt(
        crypt.Signer.from_string(self.service_account_key),
        payload)

  def _CheckGitkitError(self, raw_response):
    """Raises error if API invocation failed.

    Args:
      raw_response: string, the http response.

    Raises:
      GitkitClientError: if the error code is 4xx.
      GitkitServerError: if the response if malformed.

    Returns:
      Successful response as dict.
    """
    try:
      response = simplejson.loads(raw_response)
      if 'error' not in response:
        return response
      else:
        error = response['error']
        if 'code' in error:
          code = error['code']
          if str(code).startswith('4'):
            raise errors.GitkitClientError(error['message'])
          else:
            raise errors.GitkitServerError(error['message'])
    except simplejson.JSONDecodeError:
      pass
    raise errors.GitkitServerError('null error code from Gitkit server')
