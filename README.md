This is the python client library for Google Identity Toolkit services.

[![Build Status](https://travis-ci.org/google/identity-toolkit-python-client.svg)](https://travis-ci.org/google/identity-toolkit-python-client)

Installation
=====================

```
pip install identity-toolkit-python-client
```

If you run into issues installing, you may be missing some dependencies such as `libffi` or `python-dev`. On Debian, you can install these with:
```
sudo apt-get install python-dev libffi-dev
```

*(replace python-dev with python3-dev if using Python 3)*

Usage
=====================

Initialize Gitkit client instance
--------------

```python 
  p12_file = 'YOUR_SERVICE_ACCOUNT_PRIVATE_KEY_FILE.p12'
  f = file(p12_file, 'rb')
  key = f.read()
  f.close()
  gitkit_instance = gitkitclient.GitkitClient(
      client_id='YOUR_WEB_APPLICATION_CLIENT_ID_AT_GOOGLE_DEVELOPER_CONSOLE',
      service_account_email='YOUR_SERVICE_ACCOUNT_EMAIL@developer.gserviceaccount.com',
      service_account_key=key,
      widget_url='URL_ON_YOUR_SERVER_TO_HOST_GITKIT_WIDGET')
```

Verify Gitkit Token in HTTP request cookie
--------------
```python
  user = gitkit_instance.VerifyGitkitToken(request.COOKIES['gtoken'])
```
  
Upload Multiple Accounts
--------------

```python
  hashKey = 'hash-key'
  user1 = gitkitclient.GitkitUser()
  user1.email = '1234@example.com'
  user1.user_id = '1234'
  user1.salt = 'salt-1'
  user1.passwordHash = calcHmac(hashKey, '1111', 'salt-1')

  user2 = gitkitclient.GitkitUser()
  user2.email = '5678@example.com'
  user2.user_id = '5678'
  user2.salt = 'salt-2'
  user2.passwordHash = calcHmac(hashKey, '5555', 'salt-2')

  gitkit_instance.UploadUsers('HMAC_SHA1', hashKey, [user1, user2])
```

Download Accounts
--------------

```python
  for account in gitkit_instance.GetAllUsers(2):
    pprint(vars(account))
```

Get Account Info
--------------

```python
  pprint(vars(gitkit_instance.GetUserById('1234')))
  pprint(vars(gitkit_instance.GetUserByEmail('5678@example.com')))
```

Delete Account
--------------
```python
  gitkit_instance.DeleteUser('1234')
```
