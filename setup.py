#
"""
Installation script for the core elements of the Natural Message command line client (natmsgcc).

This requires
 * pycrypto: https://www.dropbox.com/s/n6rckn0k6u4nqke/pycrypto-2.6.1.zip?dl=1
 * requests: https://github.com/kennethreitz/requests/tarball/master
 * RNCryptor: https://github.com/RNCryptor/RNCryptor-python/tarball/master
   (RNCryptor pure python module is included in this package, so you do not need to download it).
 * Natural Message Server Verification programs (C programs that are needed if 
   you want to verify the identity of servers).
"""

# Notes for Bob to create the distribution:
# run python3 setup.py sdist, then distribute the tar.gz file in the 
# sdist directory.
from setuptools import setup

setup(name='natmsgcc',
	version='0.1',
	package_dir = {'natmsgcc': 'natmsgcc'},
	description='A command-line client for sending and receiving secure messages using the Natural Message network.',
	long_description='A command-line client for sending and receiving secure messages using the Natural Message network or by sending a link over regular email that allows the recipient to retrieve the message over the Natural Message network.  The keys to the message are encrypted and split into pieces and held by custodians who have no information about the location of the message.',
	author='Robert E. Hoot',
	author_email='naturalmessage@fastmail.nl',
	url='http://naturalmessage.com',
	licence='GPL3',
	packages=['natmsgcc'],
	py_modules = ['natmsgcc.natmsgcc', 'natmsgcc.natmsg_offline_reader',
		'natmsgcc.natmsgclib', 'natmsgcc.natmsgactions', 'natmsgcc.RNCryptor'] )
#
#
#install_requires=['pycrypto>=2.6.1', 'requests'],
