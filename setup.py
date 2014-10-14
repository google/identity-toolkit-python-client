from setuptools import setup

install_requires = [
  'oauth2client>=1.2',
  'pyOpenSSL==0.13',
  'simplejson>=2.3.2',
  ]

packages = ['identitytoolkit',]

setup(
  name = 'identity-toolkit-python-client',
  packages = packages,
  install_requires = install_requires,
  license="Apache 2.0",
  version = '0.1.3',
  description = 'Google Identity Toolkit python client library',
  author = 'Jin Liu',
  url = 'https://github.com/google/identity-toolkit-python-client',
  download_url = 'https://github.com/google/identity-toolkit-python-client/archive/master.zip',
  keywords = ['identity', 'google', 'login', 'toolkit'], # arbitrary keywords
  classifiers = [],
)
