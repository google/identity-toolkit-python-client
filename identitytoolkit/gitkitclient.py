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

"""Google Identity Toolkit Python client library.

Client library for third party web sites to integrate with Gitkit service.

Usage example:

# Initialize with Google Developer Console information
gitkit = gitkitclient.GitkitClient(
    client_id=GOOGLE_OAUTH2_WEB_CLIENT_ID,
    service_account_email=SERVICE_ACCOUNT_EMAIL,
    service_account_key=SERVICE_ACCOUNT_PRIVATE_KEY_P12,
    widget_url=FULL_URL_OF_GITKIT_WIDGET,
    cookie_name='gtoken',
    http=None,
    project_id=GOOGLE_DEVELOPER_CONSOLE_PROJECT_ID)

# Verify Gitkit token locally
user = gitkit.VerifyGitkitToken(token_string)

# Get user account by email
user = gitkit.GetUserByEmail('user@example.com')

# Delete an user
gitkit.DeleteUser(user.user_id)

# Download all user accounts from Gitkit server
for account in gitkit.GetAllUsers():
  pprint(vars(account))
"""

import base64
import urllib
try:
    from urllib import parse
except ImportError:
    import urlparse as parse

from oauth2client import crypt
import simplejson

from identitytoolkit import errors
from identitytoolkit import rpchelper


# Symbolic constants for hash algorithms supported by Gitkit service.
ALGORITHM_HMAC_SHA256 = 'HMAC_SHA256'
ALGORITHM_HMAC_SHA1 = 'HMAC_SHA1'
ALGORITHM_HMAC_MD5 = 'HMAC_MD5'
ALGORITHM_PBKDF_SHA1 = 'PBKDF_SHA1'
ALGORITHM_MD5 = 'MD5'
ALGORITHM_SCRYPT = 'SCRYPT'


class GitkitUser(object):
  """Map between gitkit api request/response dict and object attribute."""

  def __init__(self, decode=True, **kwargs):
    self.email = kwargs['email']
    self.user_id = kwargs.get('user_id', kwargs.get('localId'))
    self.name = kwargs.get('displayName', kwargs.get('display_name', None))
    self.photo_url = kwargs.get('photoUrl', kwargs.get('photo_url', None))
    self.provider_id = kwargs.get('provider_id', None)
    self.email_verified = kwargs.get(
        'emailVerified', kwargs.get('verified', None))
    if 'passwordHash' in kwargs:
      if decode:
        self.password_hash = base64.urlsafe_b64decode(kwargs['passwordHash'])
      else:
        self.password_hash = kwargs['passwordHash']
    else:
      self.password_hash = None
    if 'salt' in kwargs:
      if decode:
        self.salt = base64.urlsafe_b64decode(kwargs['salt'])
      else:
        self.salt = kwargs['salt']
    else:
      self.salt = None
    self.provider_info = kwargs.get('providerUserInfo', {})

  @classmethod
  def FromApiResponse(cls, response):
    """Initializes from gitkit api response.

    Args:
      response: dict, the Gitkit API response.
    Returns:
      GitkitUser object
    """
    return cls(**response)

  @classmethod
  def FromToken(cls, token):
    """Initializes from token (Gitkit API request).

    Args:
      token: dict, the Gitkit API request.
    Returns:
      GitkitUser object
    """
    return cls(decode=False, **token)

  @classmethod
  def FromDictionary(cls, dictionary):
    """Initializes from user specified dictionary.

    Args:
      dictionary: dict of user specified attributes
    Returns:
      GitkitUser object
    """
    if 'user_id' in dictionary:
      raise errors.GitkitClientError('use localId instead')
    if 'localId' not in dictionary:
      raise errors.GitkitClientError('must specify localId')
    if 'email' not in dictionary:
      raise errors.GitkitClientError('must specify email')

    return cls(decode=False, **dictionary)

  def ToRequest(self):
    """Converts to gitkit api request parameter dict.

    Returns:
      Dict, containing non-empty user attributes.
    """
    param = {}
    if self.email:
      param['email'] = self.email
    if self.user_id:
      param['localId'] = self.user_id
    if self.name:
      param['displayName'] = self.name
    if self.photo_url:
      param['photoUrl'] = self.photo_url
    if self.email_verified is not None:
      param['emailVerified'] = self.email_verified
    if self.password_hash:
      param['passwordHash'] = base64.urlsafe_b64encode(self.password_hash)
    if self.salt:
      param['salt'] = base64.urlsafe_b64encode(self.salt)
    if self.provider_info:
      param['providerUserInfo'] = self.provider_info
    return param


class GitkitClient(object):
  """Public interface of Gitkit client library.

  This class is the only interface that third party developers needs to know to
  integrate Gitkit with their backend server. Main features are Gitkit token
  verification and Gitkit remote API wrapper.
  """

  GOOGLE_API_BASE = 'https://www.googleapis.com/'
  RESET_PASSWORD_ACTION = 'resetPassword'
  CHANGE_EMAIL_ACTION = 'changeEmail'

  def __init__(self, client_id='', service_account_email='', service_account_key='',
               widget_url='', cookie_name='gtoken', http=None, project_id=''):
    """Inits the Gitkit client library.

    Args:
      client_id: string, developer's Google oauth2 web client id.
      service_account_email: string, Google service account email.
      service_account_key: string, Google service account private key.
      widget_url: string, Gitkit widget URL.
      cookie_name: string, Gitkit cookie name.
      http: Http, http client which support cache.
      project_id: string, developer console's project id.
    """
    self.client_id = client_id
    self.widget_url = widget_url
    self.cookie_name = cookie_name
    self.project_id = project_id
    self.rpc_helper = rpchelper.RpcHelper(service_account_email,
                                          service_account_key,
                                          GitkitClient.GOOGLE_API_BASE,
                                          http)
    self.config_data_cached = None
    if not self.client_id:
      self.client_id = self.GetClientId()

  def _RetrieveProjectConfig(self):
    if not self.config_data_cached:
      self.config_data_cached = self.rpc_helper.GetProjectConfig()
    return self.config_data_cached

  def GetClientId(self):
    config_data = self._RetrieveProjectConfig()
    client_id = None
    for idp in config_data['idpConfig']:
      if idp['provider'] == 'GOOGLE':
        client_id = idp['clientId']
    if not client_id:
        raise errors.GitkitServerError('Google client ID not configured yet.')
    return client_id

  def GetBrowserApiKey(self):
    config_data = self._RetrieveProjectConfig()
    return config_data['apiKey']

  def GetSignInOptions(self):
    config_data = self._RetrieveProjectConfig()
    sign_in_options = []
    for idp in config_data['idpConfig']:
      if idp['enabled']:
        sign_in_options.append(str(idp['provider']).lower())
    if config_data['allowPasswordUser']:
      sign_in_options.append('password')
    if not sign_in_options:
      raise errors.GitkitServerError('no sign in option configured')
    return sign_in_options


  @classmethod
  def FromConfigFile(cls, config):
    json_data = simplejson.load(open(config))

    key_file = open(json_data['serviceAccountPrivateKeyFile'], 'rb')
    key = key_file.read()
    key_file.close()

    clientId = json_data.get('clientId')
    projectId = json_data.get('projectId')
    if not clientId and not projectId:
      raise errors.GitkitClientError('Missing projectId or clientId in server configuration.')

    return cls(
        clientId,
        json_data['serviceAccountEmail'],
        key,
        json_data['widgetUrl'],
        json_data['cookieName'],
        None,
        projectId)

  def VerifyGitkitToken(self, jwt):
    """Verifies a Gitkit token string.

    Args:
      jwt: string, the token to be checked

    Returns:
      GitkitUser, if the token is valid. None otherwise.
    """
    certs = self.rpc_helper.GetPublicCert()
    crypt.MAX_TOKEN_LIFETIME_SECS = 30 * 86400  # 30 days
    parsed = None
    for aud in filter(lambda x: x is not None, [self.project_id, self.client_id]):
      try:
        parsed = crypt.verify_signed_jwt_with_certs(jwt, certs, aud)
      except crypt.AppIdentityError as e:
        if "Wrong recipient" not in e.message:
          return None
      if parsed:
        return GitkitUser.FromToken(parsed)
    return None # Gitkit token audience doesn't match projectId or clientId in server configuration

  def GetUserByEmail(self, email):
    """Gets user info by email.

    Args:
      email: string, the user email.

    Returns:
      GitkitUser, containing the user info.
    """
    user = self.rpc_helper.GetAccountInfoByEmail(email)
    return GitkitUser.FromApiResponse(user)

  def GetUserById(self, local_id):
    """Gets user info by id.

    Args:
      local_id: string, the user id at Gitkit server.

    Returns:
      GitkitUser, containing the user info.
    """
    user = self.rpc_helper.GetAccountInfoById(local_id)
    return GitkitUser.FromApiResponse(user)

  def UploadUsers(self, hash_algorithm, hash_key, accounts):
    """Uploads multiple users to Gitkit server.

    Args:
      hash_algorithm: string, the hash algorithm.
      hash_key: array, raw key of the hash algorithm.
      accounts: list of GitkitUser.

    Returns:
      A dict of failed accounts. The key is the index of the 'accounts' list,
          starting from 0.
    """
    return self.rpc_helper.UploadAccount(hash_algorithm,
                                         base64.urlsafe_b64encode(hash_key),
                                         [GitkitUser.ToRequest(i) for i in accounts])

  def GetAllUsers(self, pagination_size=10):
    """Gets all user info from Gitkit server.

    Args:
      pagination_size: int, how many users should be returned per request.
          The account info are retrieved in pagination.

    Yields:
      A generator to iterate all users.
    """
    next_page_token, accounts = self.rpc_helper.DownloadAccount(
        None, pagination_size)
    while accounts:
      for account in accounts:
        yield GitkitUser.FromApiResponse(account)
      next_page_token, accounts = self.rpc_helper.DownloadAccount(
          next_page_token, pagination_size)

  def DeleteUser(self, local_id):
    """Deletes a user at Gitkit server.

    Args:
      local_id: string, id of the user to be deleted

    Returns:
      a dict, containing 'error' key if the API failed.
    """
    return self.rpc_helper.DeleteAccount(local_id)

  def GetOobResult(self, param, user_ip, gitkit_token=None):
    """Gets out-of-band code for ResetPassword/ChangeEmail request.

    Args:
      param: dict of HTTP POST params
      user_ip: string, end user's IP address
      gitkit_token: string, the gitkit token if user logged in

    Returns:
      A dict of {
        email: user email who initializes the request
        new_email: the requested new email, for ChangeEmail action only
        oob_link: the generated link to be send to user's email
        oob_code: the one time out-of-band code
        action: OobAction
        response_body: the http body to be returned to Gitkit widget
      }
    """
    if 'action' in param:
      try:
        if param['action'] == GitkitClient.RESET_PASSWORD_ACTION:
          request = self._PasswordResetRequest(param, user_ip)
          oob_code, oob_link = self._BuildOobLink(request,
                                                  param['action'])
          return {
              'action': GitkitClient.RESET_PASSWORD_ACTION,
              'email': param['email'],
              'oob_link': oob_link,
              'oob_code': oob_code,
              'response_body': simplejson.dumps({'success': True})
          }
        elif param['action'] == GitkitClient.CHANGE_EMAIL_ACTION:
          if not gitkit_token:
            return self._FailureOobResponse('login is required')
          request = self._ChangeEmailRequest(param, user_ip, gitkit_token)
          oob_code, oob_link = self._BuildOobLink(request,
                                                  param['action'])
          return {
              'action': GitkitClient.CHANGE_EMAIL_ACTION,
              'email': param['oldEmail'],
              'new_email': param['newEmail'],
              'oob_link': oob_link,
              'oob_code': oob_code,
              'response_body': simplejson.dumps({'success': True})
          }
      except errors.GitkitClientError as error:
        return self._FailureOobResponse(error.value)
    return self._FailureOobResponse('unknown request type')

  def GetEmailVerificationLink(self, email):
    """Get the url to verify user's email

    Args:
      email: string, user's email to be verified

    Returns:
      The email verification link.
    """
    param = {
      'email': email,
      'requestType': 'VERIFY_EMAIL'
    }
    return self._BuildOobLink(param, "verifyEmail")[1]

  def _FailureOobResponse(self, error_msg):
    """Generates failed response for out-of-band operation.

    Args:
      error_msg: string, error message

    Returns:
      A dict representing errors.
    """
    return {'response_body': simplejson.dumps({'error': error_msg})}

  def _BuildOobLink(self, param, mode):
    """Builds out-of-band URL.

    Gitkit API GetOobCode() is called and the returning code is combined
    with Gitkit widget URL to building the out-of-band url.

    Args:
      param: dict of request.
      mode: string, Gitkit widget mode to handle the oob action after user
          clicks the oob url in the email.

    Raises:
      GitkitClientError: if oob code is not returned.

    Returns:
      A string of oob url.
    """
    code = self.rpc_helper.GetOobCode(param)
    if code:
      parsed = list(parse.urlparse(self.widget_url))

      query = dict(parse.parse_qsl(parsed[4]))
      query.update({'mode': mode, 'oobCode': code})

      try:
        parsed[4] = parse.urlencode(query)
      except AttributeError:
        parsed[4] = urllib.urlencode(query)

      return code, parse.urlunparse(parsed)
    raise errors.GitkitClientError('invalid request')

  def _PasswordResetRequest(self, param, user_ip):
    return {
        'email': param['email'],
        'userIp': user_ip,
        'captchaResp': param['response'],
        'requestType': 'PASSWORD_RESET'}

  def _ChangeEmailRequest(self, param, user_ip, id_token):
    return {
        'email': param['oldEmail'],
        'newEmail': param['newEmail'],
        'userIp': user_ip,
        'idToken': id_token,
        'requestType': 'NEW_EMAIL_ACCEPT'}
