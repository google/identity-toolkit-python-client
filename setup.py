from setuptools import setup
import sys

install_requires = [
  'oauth2client>=1.3.2',
  'pyOpenSSL>=0.14',
  'simplejson>=2.3.2',
  ]
tests_require = list(install_requires)

# Python 2 requires Mock to run tests
if sys.version_info < (3, 0):
    tests_require += ['pbr==1.6', 'Mock']

packages = ['identitytoolkit',]

setup(
  name = 'identity-toolkit-python-client',
  packages = packages,
  license="Apache 2.0",
  version = '0.1.11',
  description = 'Google Identity Toolkit python client library',
  author = 'Jin Liu',
  url = 'https://github.com/google/identity-toolkit-python-client',
  download_url = 'https://github.com/google/identity-toolkit-python-client/archive/master.zip',
  keywords = ['identity', 'google', 'login', 'toolkit'], # arbitrary keywords
  classifiers = [
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: Apache Software License',
    'Operating System :: OS Independent',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3.3',
    'Programming Language :: Python :: 3.4',
    'Topic :: Internet :: WWW/HTTP',
  ],
  install_requires = install_requires,
  tests_require = tests_require,
  test_suite = 'tests',
)
