# natmsgclib.py
#
# A collection of functions for the Natural Message Command-Line client
#
###############################################################################
# Copyright 2015 Natural Message, LLC.
# Author: Robert Hoot (naturalmessage@fastmail.fm)
#
# This file is part of the Natural Message Command-Line Client.
#
# The Natural Message Command-Line Client is free software: you can
# redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.
#
# Natural Message Command-Line Client is distributed in the hope that it will
# be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Natural Message Command-Line Client.  If not,
# see <http://www.gnu.org/licenses/>.
###############################################################################
"""A library of functions used for the Natural Message Command-Line Client

This module contains functions for the basic operation of the command-line
client: Encryption; server verification; proof of work; debug messaging;
class objects and functions for mult-threaded send and receive of shards
(shards are pieces of messages); reading, writing, and recovering
lost shards (using the parity block); sending messages; reading
the inbox; creating and verifying shard IDs.
"""
###############################################################################
# to do:
#  implement unrtf on linux and bsd, and 'textutil -cat txt fname'
# to convert rtf to txt on mac os X

# dd if=/dev/urandom of=AAAtest.gz bs=600 count=1 conv=notrunc oflag=append
VERBOSITY = 2
MAIN_CONFIG = {}  # main configuration dictionary loaded during nm_start
CONFIG_FNAME = None
RESERVED_EMAIL_DEST_ID = 'PUB004001010100000000000000000000000000' \
                         '000000000000000000000000000000000000000' \
                         '000000000000000000000000000000000000000' \
                         '000000000000000000019999'
#
NATMSG_ARCH_HEADER = 'nmf1'

SESSION_PW = ''  # loaded during start after calling pbkdf2_nm

EXPECTED_BOX_ID_LEN = 141
import natmsgcc.RNCryptor as RNCryptor
import hmac  # for KDF
import hashlib  # for KDF
from Crypto.Protocol import KDF

import base64
import codecs
import configparser
import datetime
import getpass
import hashlib
import io
import json
import math
import os
import platform
import re
import requests
import shutil
import subprocess
import sys
import tempfile
import threading
import time

if platform.system().lower() != 'windows':
    import pwd

MAX_INPUT_SIZE_BYTES = 193000
DEFAULT_TARGET_BLOCK_SIZE = 20000
FILE_SUFFIX = '"}]'
#
CURRENT_YYYYMMDD = int(datetime.datetime.utcnow().strftime("%Y%m%d"))
# allow an account created on oct 1 to extedn to jan 31 a year and 3 mths
#   >>> datetime.datetime(2015, 10, 1)  + + datetime.timedelta(488,0,0)
#   datetime.datetime(2017, 1, 31, 0, 0)
d_tmp = datetime.datetime.utcnow() + datetime.timedelta(489, 0, 0)
ID_CUTOFF_YYYYMMDD = int(d_tmp.strftime("%Y%m%d"))


def print_err(err_nbr, err_msg=None):
    """Print an error number and message to stderr.

    Positional (required) arguments:
    err_nbr -- An error number.

    Keyword arguments:
    err_msg -- Text to display.
    """
    if err_msg is None:
        print('Error ' + "%05d" % err_nbr, file=sys.stderr)
    else:
        if not isinstance(err_msg, str):
            err_msg = str(err_msg)

        print('Error ' + "%05d" % err_nbr + '.  ' + err_msg, file=sys.stderr)

    return(err_nbr)


def debug_msg(test_val, msg):
    """Display a message if the verbosity level is high enough.

    I should replace with with references to the logging module.

    Call this with the user's option for verbosity as the first argument
    (0=no messages) and value greater than 1 and usually less than 10
    for the test_val.

    If the user's option for verbosity is >= the specified value,
    the message (msg) will print to std.err.

    Enter high values for test_val if you want to show the message
    only when the verbosity is set to an extremely high value > 5.

    For verbosity messages of level 1, 2, 3, the message will print
    as specified, but for higher level verbosity, a prefix of "DEBUG "
    will be added to the message.

    Positional arguments:
    test_val -- A numeric value (usually 1-10).  If this number is
        greater than or equal to the global verbosity level, then
        print the message.

    Keyword arguments:
    msg -- The message to display.

    """

    if 'SETTINGS' not in MAIN_CONFIG:
        # During initial setup, the config is not ready
        verbosity = 2
    else:
        if 'verbosity' in MAIN_CONFIG['SETTINGS']:
            tmp = MAIN_CONFIG['SETTINGS']['verbosity']
            if tmp.isnumeric():
                verbosity = int(tmp)
        else:
            verbosity = 2

    if test_val > 10:
        test_val = 10

    if verbosity >= test_val:
        if verbosity > 3:
            print('DEBUG: ' + msg, file=sys.stderr)
        else:
            print(msg, file=sys.stderr)

    return(0)


def validate_id_chars(id_chunk):
    """Validate that the characters in IDs are in a valid range.

    This will take the portion of a box_id/shard_id (excluding the prefix)
    and confirm that the characters are 0-9 or A-F (or a-f). Each program
    should upcase the box_id to standardize appearance.

    Positional arguments:
    id_chunk -- The portion of the ID that contains the random characters
        (do not include the prefix of the ID).

    Returns:
    0 if good, otherwise nonzer.
    """
    out_msg = {}
    rc = 0

    # Remove hex chars
    tmp1 = re.sub(r'[0-9A-Fa-f]+', '', id_chunk)
    tmp2 = re.sub(r'[_-]+', '', tmp1)
    if (len(tmp2) != 0):
        # Bad characters remain.
        return(print_err(
            20500, 'Illegal characters (' + tmp2
            + ') in the random part of the id: '
            + id_chunk))

    return(0)


def verify_id_format(id, expected_prefix, version=1):
    """Verify the prefix, length, and character range of IDs.

    This function will check an ID to see if it has the proper
    character set and length.

    This does not check the complexity of the randomness of the
    random portion of an ID.

    If the format looks good, this will return 0.  If the
    box ID has expired, this will return 1.  If there
    is another error, this will return something greater than 100.

    Positional arguments:
    id -- The ID to verify.
    expected_prefix -- The prefix (e.g., PRV, PUB, SID, SMD..).

    Keyword arguments:
    version -- If the structure of the IDs changes, then code
        this with a different number.  Default value is the current
        version (1).

    Return value:
    0 on success, else nonzero.
    """

    # Function:
    # Use regular expressions to remove good characters,
    # then see if there is anything left.
    # Example of the re library:
    #     >>> s = 'abcdefg1234a#@+sdfljsad97ADFADSF1234!@#$%^&*('
    #     >>> re.sub(r'\w+', '', s)
    #     '#@+!@#$%^&*('

    rc = 0

    global RESERVED_EMAIL_DEST_ID

    debug_msg(5, '=== In nm_verify_id_format')

    if id == RESERVED_EMAIL_DEST_ID:
        # Accept the reserved email-transport ID
        return(0)

    if expected_prefix is None:
        return(print_err(
            20600,
            'There was no expected_prefix '
            'passed to verify_id_format.'))

    if id is None:
        return(print_err(20700, 'There was no ID passed to verify_id_format.'))

    if (id[0:3] not in ('PUB', 'PRV', 'SID', 'SMD', 'MIX')):
        return(print_err(20800, 'Invalid ID prefix: ' + id[0:3]))

    if (id[0:3] != expected_prefix):
        return(print_err(
            20900,
            'The prefix (' + id[0:3]
            + ') was not what was expected (' + expected_prefix + ').'))

    if (expected_prefix in ('SID', 'SMD', 'MIX')):
        # shard IDs have no embedded date or fingerprint,
        # and have 32 character random component
        if (len(id) == 35):
            # Good so far. Verify that the random part of the
            # ID has valid characters
            rc = validate_id_chars(id[3:])
            if (rc != 0):
                return(rc)

        else:
            return(print_err(
                21000,
                'Length of a shard ID must be 35. Observed length was: '
                + str(len(id))))
    else:
        # PUB key and PRV (prv has expiration date 40010101)
        if (len(id) == 141):
            # Good so far. Keep checking.
            # charcter format offset 0-2 = prefix; 3-4 = reserved;
            # 5-12 = yyyymmdd; 13-52 = fingerprint; 53-84 = random
            rc = validate_id_chars(id[13:])
            if (rc != 0):
                print_err(
                    rc,
                    'The set of characters for this ID was illegal: ' + id)
                return(rc)

            test_yyyymmdd = int(id[5:13])
            test_mm = int(id[9:11])
            test_dd = int(id[11:13])
            if (id[0:3] == 'PRV'):
                if (test_yyyymmdd != 40010101):
                    # private boxes don't expire
                    return(print_err(
                        21200,
                        'The expiration date for PRV IDs should be 40010101, '
                        + 'but this one is:' + str(test_yyyymmdd)))
            else:
                if (test_yyyymmdd > ID_CUTOFF_YYYYMMDD):
                    return(print_err(
                        21300,
                        'The expire date for this account is too '
                        + 'far in the future zzz: ' + str(test_yyyymmdd)))

                if (test_yyyymmdd < CURRENT_YYYYMMDD):
                    return(print_err(
                        1,
                        'This ID expired on: ' + str(test_yyyymmdd)))

                if (test_mm > 12):
                    return(print_err(
                        21500,
                        'invalid month for ID: ' + str(test_mm)))

                if (test_mm > 31):
                    return(print_err(
                        21600,
                        'invalid day for ID: ' + str(test_dd)))

        else:
            return(print_err(
                21700,
                'Length of ID must be 141 (3-letter code + '
                + '2-byte reserved + 8-byte date + '
                + '65 bytes server fingerprint + 32 bytes random).  '
                + 'I found length=' + str(len(id)) + ' for id: ' + id))
            # raise Exception('Illegal ID length')

    debug_msg(5, 'At the end of nm_verify_id_format')
    return(0)


###############################################################################
#
# TO DO:
#  1) get the POW parameters from the natural message server.
def pow_target_bits(file_size, pow_factor, bit_constant, min_bits):
    """Show the number of bits for Proof of Work for a given file size.

    This will take the file size and three paramaters that
    come from the shard server, then use that information
    to determine the number of bits that are needed
    in the proof of work.  It is possible that a shard server
    operator will change the requirements a few times
    in one day or that the parameters will stay the same
    all year.

    Positional arguments:
    file_size -- The size of the payload being sent to a shard server.
    pow_factory -- A scaling factor used in the proof of work calcuation.
        Shard servers can set their own parameters to require more or less
        proof of work.
    bit_constant -- The intercept in the proof of work calculatoin.
    min_bits -- The minimun number of bits required by the shard server
        for proof of work.

    Return value:
    Number of bits needed for this proof of work for a file of the given size.
    """

    # Find the log, base 2, of the file size:
    log_fs = math.log(file_size * pow_factor, 2)

    # 'target_bits' is the number of 1-bits that we need to find
    # is determined by the size of the file and
    # the three proof-of-work requirements for each
    # shard server.
    target_bits = int(log_fs) + bit_constant
    if target_bits < min_bits:
        target_bits = min_bits

    return(target_bits)


###############################################################################
class RNCrypt_bob(RNCryptor.RNCryptor):
    """RNCryptor AES256 adapted for Python3.

    This is a modified RNCryptor for Python 3 that
    provides an option to omit the conversion to str()
    after decryption.  This is needed so that I can
    encrypt and decrypt binary files that are invalid
    under UTF-8.

    This version retains the default password hashing that
    is used by RNCryptor and the Mac OS X client.

    Bob added 'decrypt_to_str' and set it disable str conversion.

    Positional arguments for initialization:
    data = a Python bytes object with the thing to be encrypted.

    Keyword arguments for initialization:
    decrypt_to_str -- Leave this at the default value of False.
    """
    def post_decrypt_data(self, data, decrypt_to_str=False):
        """
        Removes useless symbols which appear over padding for AES (PKCS#7). """

        # data = data[:-bord(data[-1])]
        # Python 3 does not need the bord command
        data = data[:-data[-1]]
        # Bob expanded the old'to_str' to avoid copying the setup macros.
        # (not tested in python 2).
        if decrypt_to_str:
            if isinstance(data, bytes):
                data = data.decode('utf-8')

        return (data)

    def decrypt(self, data, password, decrypt_to_str=False):
        data = self.pre_decrypt_data(data)
        # Bob expanded the old 'to_bytes' this to avoid
        # copying the setup macros
        if not isinstance(password, bytes):
            password = bytes(password, 'utf-8')

        n = len(data)

        version = data[0]
        options = data[1]
        encryption_salt = data[2:10]
        hmac_salt = data[10:18]
        iv = data[18:34]
        cipher_text = data[34:n - 32]
        hmac = data[n - 32:]

        encryption_key = self._pbkdf2(password, encryption_salt)
        hmac_key = self._pbkdf2(password, hmac_salt)

        if self._hmac(hmac_key, data[:n - 32]) != hmac:
            raise Exception("Bad data (HMAC was bad, wrong password?)")

        # to do: i can not raise this unless i trap or or else people can
        # send invalid data and crash the client
        decrypted_data = self._aes_decrypt(encryption_key, iv, cipher_text)

        return self.post_decrypt_data(
            decrypted_data,
            decrypt_to_str=decrypt_to_str)


#
class RNCrypt_zero(RNCryptor.RNCryptor):
    """RNCryptor with no PBKDF2 password hashing.

    This is a modified RNCryptor for Python 3 that
    provides two changes:
    1) an option to omit the conversion to str()
    after decryption.  This is needed so that I can
    encrypt and decrypt binary files that are invalid
    under UTF-8.
    2) zero hash rounds by default.

    I use this version for decrypting things that are used
    locally because if I encrypt or decrypt many things
    individually, then the extra hashing makes everything
    super slow.  Do NOT use this on any packets that are
    sent across the Internet because the recipient
    will not know that the password hashing has changed.

    This requires access to some extra python libraries,
    including one that come from the pycrypto package from
    https://www.dlitz.net/software/pycrypto/:
        import hmac # for KDF
        import hashlib # for KDF
        from Crypto.Protocol import KDF
    """
    def _pbkdf2(self, password, salt, iterations=0, key_length=32):
        """
        Positional arguments:
        password -- A bytes object.
        salt -- Salt for AES encryption.
        dkLen -- Key length ???.
        count -- number of hash iterations used to strengthen the password.
            Once you start using a value, do not change it.
        prf -- The function used to hash the password.

        Return value:
        The hashed password.
        """
        return(KDF.PBKDF2(
            password,
            salt,
            dkLen=key_length,
            count=iterations,
            prf=lambda p, s: hmac.new(p, s, hashlib.sha256).digest()))

    def post_decrypt_data(self, data, decrypt_to_str=False):
        """Removes useless symbols related to padding for AES (PKCS#7)."""

        # data = data[:-bord(data[-1])]
        # Python 3 does not need the bord command
        data = data[:-data[-1]]
        # Bob expanded the old'to_str' to avoid copying the setup macros.
        # (not tested in python 2).
        if decrypt_to_str:
            if isinstance(data, bytes):
                data = data.decode('utf-8')

        return (data)

    def decrypt(self, data, password, decrypt_to_str=False):
        """Decrypt something that was encrypted with this clas."""
        data = self.pre_decrypt_data(data)
        # Bob expanded the old 'to_bytes' this to avoid
        # copying the setup macros
        if not isinstance(password, bytes):
            password = bytes(password, 'utf-8')

        n = len(data)

        version = data[0]
        options = data[1]
        encryption_salt = data[2:10]
        hmac_salt = data[10:18]
        iv = data[18:34]
        cipher_text = data[34:n - 32]
        hmac = data[n - 32:]

        encryption_key = self._pbkdf2(password, encryption_salt)
        hmac_key = self._pbkdf2(password, hmac_salt)

        if self._hmac(hmac_key, data[:n - 32]) != hmac:
            raise Exception("Bad data")

        decrypted_data = self._aes_decrypt(encryption_key, iv, cipher_text)

        return(self.post_decrypt_data(
            decrypted_data,
            decrypt_to_str=decrypt_to_str))


class ShardSendQueueArgs(object):
    """Hold arguments that go into the shard-send queue.

    This class will hold data that is queued for the shard-read process.
    The content includes data needed to send a shard. A list of objects
    of this class will be sent to nm_send_shards(), and ultimately
    it is ThreadShardSend.run() that will process the data in this object.

    Maybe send EITHER cargo_bytes or input_fname.

    Keyword arguments for initialization:
    web_host -- the first part of the URL, like https://123.456.789:4430.
    shard_id -- a shard ID from nm_gen_shard_id().
    cargo_bytes -- A Python bytes object with the payload. Specify either
        this or input_fpath.
    input_fpath -- The input directory that contains shards to send. Specify
        either this or cargo_bytes.
    wrk_dir -- A work directory where all shards in a message are stored. This
        directory will be used for temporary storage and the status files
        while the message is being sent.
    add_proof_of_work -- Boolean.  Truee if the shard server requires proof
        of work.

    """
    def __init__(
            self,
            web_host=None,
            shard_id=None,
            cargo_bytes=None,
            input_fpath=None,
            wrk_dir=None,
            add_proof_of_work=True):

        # fpath is used for verification and loading before sending
        # to the shard_send routine
        self.input_fpath = input_fpath
        if web_host.startswith('https'):
            self.web_host = web_host
        else:
            raise RuntimeError('The web_host sent to ShardSendQueueArgs '
                + 'must start with https. I found: ' + web_host)
        self.shard_id = shard_id
        self.cargo_bytes = cargo_bytes
        self.wrk_dir = wrk_dir
        self.add_proof_of_work = add_proof_of_work

    def web_host(self):
        return(self.web_host)

    def shard_id(self):
        return(self.shard_id)

    def cargo_bytes(self):
        return(self.cargo_bytes)

    def input_fpath(self):
        return(self.input_fpath)

    def wrk_dir(self):
        return(self.wrk_dir)

    def add_proof_of_work(self):
        return(self.add_proof_of_work)


#
class ThreadShardSend(threading.Thread):
    """A thread to send a shard to a shard server.

    Arguments are passed during initialization in the form of a
    ShardSendQueueArgs object.

    The sending process...
    nm_actions.nm_send_message()
        prepare all the arguments and directories.
        archive the input file(s) with natmsgclib.nm_archiver2().
        nm_actions.shard_and_send()
            nm_actions.nm_send_shards()
                start ThreadShardSend
                put data into a ShardSendQueueArgs, which will
                execute ThreadShardSend.run()
                Resend if there is an error

    Positional arguments during initialization:
    A ShardSendQueueArgs that contains input paths other things.
    """
    def __init__(self, qa):
        # qa is my queue args class
        threading.Thread.__init__(self)
        # Take the argument and save it
        # do not "get" yet because this will
        # be called before there is anything
        # in the queue
        self.qa = qa
        self.init_failed = False

    def _process_good_response(self):
        # _process_good_response
        # If the response is good, write the shard status
        # as 'sent' and call self.qa.task_done().
        # If the response from the server is not good,
        # register a bad code in the shard status file
        # and call self.qa.task_done().

        self.svr_response = None
        try:
            self.svr_response = self.r.json()['shard_create']
        except:
            self.err_msg = 'The response does not have ' \
                + 'the JSON entry for shard_create. ' + str(r.text)
            nm_write_shard_status(
                self.status_fname,
                'failed',
                error_detail=self.err_msg)
            self.qa.task_done()  # tell the queue that the task is finished
            return(23700)

        if self.svr_response is not None:
            # valid JSON response... check for error mesages.
            if 'Error' in  self.svr_response.keys():
                nm_write_shard_status(
                    self.status_fname,
                    'failed',
                    error_detail=self.err_response)
                self.qa.task_done()  # Tell the queue that the task is finished
                return(23800)
            elif 'status' in  self.svr_response.keys():
                status = self.svr_response['status']

                if status.upper() == 'OK':
                    debug_msg(5, '=== Good shard status for ' + self.shard_id)
                    nm_write_shard_status(self.status_fname, 'sent')
                    # Tell the queue that the task is finished
                    self.qa.task_done()
                    return(0)
                else:
                    nm_write_shard_status(self.status_fname, 'failed')
                    self.qa.task_done()
                    return(24000)
        else:
            # The shard server returned something, but it could
            # not be parsed into JSON.
            nm_write_shard_status(self.status_fname, 'failed')
            self.qa.task_done()  # tell the queue that the task is finished
            return(24100)
        return(0)

    def run(self):
        """Push one shard to a shard server.

        This will return a tuple with err_nbr and err_msgd as a dictionary.

        If cargo_bytes is None, I will read from input_fpath.

        I am modifying this to facilitate the change to multithreading and
        recovery after a crash of the client computer.  I will write a .status
        file for each shard, initially with status=initializing, then update
        that status to either 'sending', 'sent' or 'failed' (written to the
        .status file on disk in JSON format).  If there is a failure, I
        will retain a failure_count, first_error_msg, latest_error_msg, time
        of first failure.
        """

        my_args = self.qa.get()
        self.wrk_dir = my_args.wrk_dir
        self.web_host = my_args.web_host
        self.shard_id = my_args.shard_id
        self.cargo_bytes = my_args.cargo_bytes
        self.input_fpath = my_args.input_fpath
        self.add_proof_of_work = my_args.add_proof_of_work

        if self.wrk_dir is None:
            # I can not write the status to disk because there is no path
            # to the output directory.
            #
            # tell the queue that the task is finished (doesn't help)
            self.qa.task_done()
            raise RuntimeError('There was no wrk_dir sent to ThreadShardSend.')

        if self.shard_id is None:
            self.qa.task_done()
            raise RuntimeError('There was no shard_id sent to ThreadShardSend.')

        self.status_fname = os.path.join(
            self.wrk_dir,
            self.shard_id + '.status')
        nm_write_shard_status(self.status_fname, 'initializing')

        debug_msg(
            5,
            'In ThreadShardSend, status fname is ' + self.status_fname)

        if self.cargo_bytes is None:
            # read from the input file:
            try:
                self.fd_in = open(self.input_fpath, 'rb')
                try:
                    self.cargo_bytes = self.fd_in.read()
                except:
                    # The error is trapped below when checking cargo_bytes
                    pass
                finally:
                    self.fd_in.close()
            except:
                self.e = str(sys.exc_info()[0:2])
                try:
                    self.fd_in.close()
                except:
                    pass

                nm_write_shard_status(self.status_fname, 'failed')
                self.qa.task_done()  # tell the queue that the task is finished
                return(print_err(
                    23100,
                    'Failed to open the input_fpath (file '
                    + 'containing the shard to send) '
                    + 'for ThreadShardSend: '
                    + str(self.input_fpath) + '. ' + self.e))


        if not isinstance(self.cargo_bytes, bytes):
            self.err_msg = 'Cargo_bytes sent to ThreadShardSend was not ' \
                + 'in python bytes() format.'
            nm_write_shard_status(
                self.status_fname,
                'failed',
                error_detail={'Error-detail': self.err_msg})

            self.qa.task_done()  # Tell the queue that the task is finished.
            return(23400)

        self.cargo_sha1 = hashlib.sha1(self.cargo_bytes).digest()  # Binary SHA1

        # #hdrs = {'NM-Signature': sig}
        if self.add_proof_of_work:
            self.nm_pow = create_shard_pow(
                self.cargo_sha1,
                len(self.cargo_bytes), pow_factor=.05,
                min_bits=2, bit_constant=0)

            debug_msg(
                5,
                'In ThreadShardSend, final pow is ' + self.nm_pow)

            self.url = self.web_host + '/shard_create?shard_id=' \
                + self.shard_id \
                + '&nm_pow=' + self.nm_pow
        else:
            self.url = self.web_host + '/shard_create?shard_id=' \
                + self.shard_id

        # #attached_files = {'shard_data': ('overrideinputfilenamegoeshere',
        self.attached_files = {'shard_data': (
            'shard_data',
            self.cargo_bytes,
            'application/x-download', {'Expires': '0'})}

        nm_write_shard_status(self.status_fname, 'sending')

        debug_msg(
            5,
            'Making https request for url: ' + self.url
            + ' with cargo len ' + str(len(self.cargo_bytes)))

        self.r = None
        requests.packages.urllib3.disable_warnings()
        try:
            self.r = requests.post(
                self.url,
                headers={'User-Agent': ''},
                verify=False,
                files=self.attached_files)
        except:
            self.e = str(sys.exc_info()[0:2])
            self.err_msg = 'Error. Could not create shard: ' \
                + self.shard_id + ' Python err msg: ' + self.e

            nm_write_shard_status(
                self.status_fname,
                'failed',
                error_detail='The HTML '
                + 'request failed. ' + self.err_msg)

            self.qa.task_done()  # tell the queue that the task is finished
            return(23500)

        self.json_err_msg = None
        if self.r is not None:
            # # try:
            # #     # see if there is a JSON error message:
            # #     self.json_err_msg = self.r.json()['shard_create']['Error']
            # # except:
            # #     # There is no error message that is logged
            # #     # under the key "Error" (case sensitive),
            # #     # which is good.
            # #     # I will use the "None" test below
            # #     pass

            # # if self.json_err_msg is not None:
            # #     # There is an error message in the JSON,
            # #     # record an error and log it.
            # #     nm_write_shard_status(
            # #         self.status_fname, 'failed', error_detail='The server '
            # #         + 'returned an error while I was pushing a '
            # #         + 'shard to a shard server: '
            # #         + str(self.json_err_msg))
            # #     self.qa.task_done()  # tell the queue that the task is finished
            # #     return(23600)
            try:
                svr_response = self.r.json()['shard_create']
            except:
                nm_write_shard_status(
                    self.status_fname, 'failed', error_detail='The server '
                    + 'did not return a valid response')
                self.qa.task_done()  # tell the queue that the task is finished
                return(23600)

            if 'Error' in svr_response.keys():
                print('++ temp debug is Error.')
                nm_write_shard_status(
                    self.status_fname, 'failed', error_detail='The server '
                    + 'returned an error: ' + svr_response['Error'])
                self.qa.task_done()  # tell the queue that the task is finished
                return(23601)
            elif 'status' in svr_response.keys():
                print('++ temp debug status is a key.')
                if 'OK' == svr_response['status']:
                    print('++ temp debug is OK')
                    rc = self._process_good_response()
                    debug_msg( 4, 'Good response with rc=' + str(rc))
                    return(rc)
                else:
                    print('++ temp debug of NON-OK' + svr_response['status'])

            nm_write_shard_status(
                self.status_fname, 'failed',
                error_detail='Unexpected server response: ' + repr(svr_response))
            print('++ temp debug of keys')
            for k in svr_response.keys():
                print(k + ' = <' + svr_response['status'] + '> in brackets.')
            self.qa.task_done()  # tell the queue that the task is finished
            return(23603)
        else:
            # Tell the queue that the task is finished.
            self.qa.task_done()
            return(24200)

        # Tell the queue that the task is finished
        self.qa.task_done()
        return(0)  # end of run() method


###############################################################################
###############################################################################
###############################################################################
class ShardReceiveQueueArgs(object):
    """Hold data that is queued for the shard-read process."""

    def __init__(
            self,
            web_host=None,
            shard_id=None,
            out_dir=None,
            add_proof_of_work=True,
            output_fname=None):

        # fname is used for verification and loading before sending to
        # the shard_send routine
        self.web_host = web_host
        self.shard_id = shard_id
        self.output_fname = output_fname
        self.out_dir = out_dir

    def web_host(self):
        return(self.web_host)

    def shard_id(self):
        return(self.shard_id)

    def output_fname(self):
        return(self.output_fname)

    def out_dir(self):
        return(self.out_dir)


###############################################################################
#
class ThreadShardReceive(threading.Thread):
    """A thread to get shards from a shard server.

    The arguments are sent in ShardRecieveQueueArguments qa.

    The shard-receive process:

    read_inbox()
        unpack_metadata_files()
            nm_recieve_shards()
                ThreadShardReceive.run()
    """
    def __init__(self, qa):
        # qa is my queue args class
        threading.Thread.__init__(self)
        # Take the argument and save it
        # do not "get" yet because this will
        # be called before there is anything
        # in the queue
        self.qa = qa

    def run(self):
        # execute get() in the run routine, not in __init__
        my_args = self.qa.get()
        self.out_dir = my_args.out_dir
        self.output_fname = my_args.output_fname
        self.web_host = my_args.web_host
        self.shard_id = my_args.shard_id

        if self.out_dir is None:
            # I can not write the status to disk because there is no path
            # to the output directory.
            # To Do: this should probably raise an exception
            # ... or catch the error
            # during the final status verification (detect missing file).
            #
            # Tell the queue that the task is finished
            self.qa.task_done()
            return(print_err(
                25000,
                'There was no output directory  sent to ThreadShardReceive.'))

        self.status_fname = os.path.join(
            self.out_dir,
            self.shard_id + '.status')
        nm_write_shard_status(self.status_fname, 'initializing')

        self.url = self.web_host + '/shard_read?shard_id=' + self.shard_id

        if not os.path.isdir(self.out_dir):
            try:
                os.makedirs(self.out_dir, mode=0o700)
            except:
                # Tell the queue that the task is finished
                self.qa.task_done()
                return(print_err(
                    25100,
                    'Could not create the directory to save shard data.'))

        self.output_fpath = os.path.join(self.out_dir, self.output_fname)

        self.r = None
        nm_write_shard_status(self.status_fname, 'receiving')
        requests.packages.urllib3.disable_warnings()
        try:
            self.r = requests.get(
                self.url,
                headers={'User-Agent': ''}, verify=False)
        except:
            self.e = str(sys.exc_info()[0:2])
            nm_write_shard_status(
                self.status_fname,
                'failed', error_detail=self.e)
            # Tell the queue that the task is finished
            self.qa.task_done()
            return(print_err(
                25200,
                'The HTML request for the shard read failed. '
                + 'The URL was ' + self.url + '. ' + str(self.e)))

        if self.r is not None:
            try:
                # save the shard to disk
                self.fd_fileout = open(self.output_fpath, 'wb')
                self.shard_fd = io.BytesIO(self.r.content)
                self.fd_fileout.write(self.shard_fd.read())

            except:
                self.e = str(sys.exc_info()[0:2])
                nm_write_shard_status(
                    self.status_fname,
                    'failed',
                    error_detail='Failed to save the shard to disk')
                # cleanup after any exception

                if self.fd_fileout:
                    os.fsync(self.fd_fileout.fileno())
                    self.fd_fileout.close()
                if self.shard_fd:
                    # shard_fd is a BytesIO object is is being read
                    # ... no fsync needed
                    self.shard_fd.close()

                # I can not rely on self.e existing here.
                # Tell the queue that the task is finished
                self.qa.task_done()
                # # threading.lock.release()
                return(print_err(
                    25300,
                    'Failed to send the shard to disk: '
                    + str(sys.exc_info()[0:2])))

            # No error so far:
            os.fsync(self.fd_fileout.fileno())
            self.fd_fileout.close()
            self.shard_fd.close()

        else:
            nm_write_shard_status(
                self.status_fname,
                'failed',
                error_detail='Response for HTML GET was None.')
            # Tell the queue that the task is finished
            self.qa.task_done()
            return(print_err(25400, 'The server did not respond.'))

        self.fd_fileout.close()
        self.shard_fd.close()
        nm_write_shard_status(self.status_fname, 'received')
        # Tell the queue that the task is finished
        self.qa.task_done()
        return(0)


###############################################################################
###############################################################################
###############################################################################
def nm_verify_server_files(
        nonce,
        nonce_signature,
        fname_server_online_pub_key,
        fname_server_offline_pub_key,
        fname_signed_online_key,
        verify_pgm_name='nm_verify'):
    """Verify a server using a nonce and signing.

    This can be called by most of the server-related methods that pass
    a nonce to a Natural Message directory server and ask the server to
    sign it. This serves as validation of that the directory server
    is the one that you accessed when you created your box ID.

    Some of the arguments are filenames. The caller can keep the
    key files for the directory server on disk and put the filenames
    in the MAIN_CONFIG dictionary. Keys for the shard servers
    might be less likely to be reused in the future.

    Positional arguments:
    nonce = ASCII text that was sent to the server to sign.

    nonce_signature = the detatched Natural Message signature that
    was created by the server using the online key for the server.

    fname_server_online_pub_key = A filename pointing to a file that
    contains the full public key of the online server.  This
    can come from the serverFarm list on the directory server or an
    independent source.

    fname_server_offline_public_key = A filename pointing to a file that
    contains the full public key that is associated with
    the offline private key for the server.  The SHA384 of this file is
    the fingerprint of the server--the same fingerprint that is embedded
    into the Natural Message box IDs. The server_offline_public_key can
    be obtained from the serverFarm list or from another source.  An IP
    address should be associated with exactly one signature.  There should
    not be multiple IPs associated with the same signature, but perhaps
    there will be one regular and one backup IP listed in the public key
    itself.  The exact usage has yet to be determined, but the offline
    private key should never be on a computer that connects to any network.

    fname_signed_online_key = A filename pointing to a file that contains
    a detached signature of the online public key
    that is made by the offline key.  The signed_online_key is available
    from the serverFarm list or from another source.  The file is
    proof that the current online key (which should expire within a month or
    so), has been signed by the offline private key. If the server is overtaken
    by a hostile force, the online key will expire and the hostile agents
    will not have the offline key to keep the server active.  Client
    applications should reject an expired online key.  Client applications that
    are accessing a directory server should reject an online
    key that is not signed by an offline public key that has the SHA384
    fingerprint that matches the fingerprint in the users box ID.

    This calls a compiled program called nm_sign that was created by
    Natural Message.  The keys here are built using libgcrypt (which is
    the engine behind GnuPG), but the keys are stored as S-expressions
    that can be used by libgcrypt--the keys are not in GnuPG/PGP format.
    """

    # I created the original, Natural
    # Message nm_verify program because I didn't find a reliable python library
    # for the new libgcrypt (Bob, 2015).

    # Write the contents of everything to files because that is what
    # the verify program wants.

    fname_nonce = tempfile.mktemp(prefix='natmsg-tmpver-')
    fname_nonce_sig = tempfile.mktemp(prefix='natmsg-tmpver-')

    # Check the signature on the nonce.
    pid = subprocess.Popen(
        [
            verify_pgm_name,
            '--in',
            fname_nonce,
            '--signature',
            fname_nonce_sig,
            '--key',
            fname_server_online_pub_key
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE)
    rc = pid.wait()
    if rc != 0:
        # not verified
        return(26000)

    # Now check the signature on the nonce.
    pid = subprocess.Popen(
        [
            './nm_verify',
            '--in',
            fname_server_online_pub_key,
            '--signature', fname_signed_online_key,
            '--key',
            fname_server_offline_pub_key
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE)
    rc = pid.wait()
    if rc != 0:
        # not verified
        return(26100)

    # erase temp files
    for f in fnames:
        os.remove(f)

    return(0)


###############################################################################
# The input code will probably be the SHA1 of the
# payload--in base64 with utf8.
def create_shard_pow(
        payload_sha128,
        file_size,
        pow_factor,
        min_bits=12,
        bit_constant=3):
    """Create a proof of work signature for a shard.

    This creates a Proof-of-Work (POW) for a shard.  This is a feature
    that might be enforced in the future if there is a problem with abuse
    of the shard servers.  The sender would have to perform some
    CPU-intensive calculations that are unique to each shard, and if the
    servers turn on the POW requirement, shards will not be saved unless
    they have performed the work.  Servers can set the parameters that
    determine how much POW they want for a shard of a given size.

    The payload_sha128 will be prepended to the current YYYYMMDD and then
    this function will find a nonce_hex_str that can be appended to the
    other data to produce a hash that has sufficient number of leading,
    binary ones to meet the proof of work requirement for posting the
    shard (the server will allow some degree of leeway on the YYYYMMDD).

    The pow factor is a scaling factor for the required amount of proof of
    work.    Natural Message servers will eventually post the parameters in a
    JSON web page called serverFarm with options for pow_factor,
    intercept, and min_bits (vaguely similar to slope, intercept, minimum
    value so that we can use plug the size of a shard into an equation to
    know how many leading zeroes are needed in the proof of work --the
    intercept could be negative, so the minimum compensates).

    If there is a problem with abuse of the servers, the pow_factor
    might be set to 1.5 or 3.5 or something like that.
    """

    # Hash_len_bytes will be hard-coded and will correspond to
    # the number of bytes that are produced by the chosen hash algo.
    hash_len_bytes = 20

    target_bits = pow_target_bits(
        file_size,
        pow_factor,
        bit_constant,
        min_bits)
    # ##########################################################
    start_time = time.time()

    nonce_hex_str = ''

    dt = datetime.date.today()

    # current yyyymmdd such as 20140931
    # (remember leading zeroes for day and month).
    yyyymmdd_str = str(dt.year) + "%02d" % dt.month + "%02d" % dt.day

    debug_msg(7, 'yymmdd_str for POW is ' + yyyymmdd_str)

    # Construct a bit mask using the number of number
    # of bytes in hash_len_bytes, with some of the
    # high-order bits turned on (big-endian)
    # according to the number in target_bits:
    mask = 1 << (8 * hash_len_bytes - 1)
    for i in range(target_bits - 1):
        mask = mask | 1 << (hash_len_bytes * 8 - i - 1)

    # Find the number of bits in my mask as a double-check.
    # Note that the python 'string representation' of the bit array
    # adds two bytes of junk.
    bit_len = len(str(bin(mask))) - 2

    debug_msg(9, 'In create_shard_pow, mask is  ' + str(bin(mask)))

    # Conduct a brute-force loop to determine
    # the nonce_hex_str that can be added to the other codes
    # so that the resulting SHA1 has "target_bits"
    # number of leading ones:
    j = 1
    found = False
    while not found:
        # Generate a nonce_hex_str (one-time random value) that will be
        # put inside the hash string in an attempt to find a value
        # that results in leading digest bits set to 1.
        nonce_hex_str = base64.b16encode(
            RNCryptor.Random.new().read(
                int((target_bits + 2) / 8 + 1))).decode('utf-8').lower()
        h = hashlib.sha1(
            b''.join(
                [
                    payload_sha128,
                    bytes(yyyymmdd_str + nonce_hex_str, 'utf-8')
                ])).digest()

        i = int().from_bytes(h, 'big')
        if mask & i == mask:
            debug_msg(
                7,
                'Found a good proof of work key on iteration ' + str(j)
                + ' with mask\n' + bin(mask) + '\nand hash\n' + bin(i))

            found = True

        j += 1

    end_time = time.time()
    ellapsed_time = end_time - start_time

    # Final report:
    # The user will submit the nonce_hex_str value as proof of work.
    debug_msg(
        9,
        'Proof of work info: File size: ' + str(file_size) + ' bits: '
        + str(target_bits) + ' elapsed time: ' + str(ellapsed_time))

    # I found a nonce_hex_str that can be added to the hash routine
    # to make the has have the required number of bits set to 1.
    return(nonce_hex_str)


def verify_pow(
        nonce_hex_str,
        fsize,
        payload_sha128,
        pow_factor,
        bit_constant,
        min_bits):
    """Verify a Proof of Work value."""
    if not isinstance(nonce_hex_str, str):
        print('Error.  The nonce_hex_str needs to be of type Python str()')
        return(-12)

    debug_msg(
        7,
        'In verify_pow, the nonce_hex_str sent to verify_pow was: '
        + bin(int().from_bytes(nonce_hex_str, sys.byteorder))
        + ' (that nonce_hex_str is added to a string and hashed)')

    # Hash_len_bytes will be hard-coded and will correspond to
    # the number of bytes that are produced by the chosen hash algo.
    hash_len_bytes = 20

    # ------------------------------------------------------------
    # The server would now verify the nonce_hex_str
    # using today's date, or yesterday's, or the day before that
    # or tomorrow's date
    good = False
    dt_adjust = (0, -1, -2, 1)
    j = 0
    while not good:
        # This loop tries to verify the POW using today's date,
        # yesterday's date, and a couple other dates.

        # Try to verify each of the days listed in dt_adjust
        dt = datetime.date.today() + datetime.timedelta(days=dt_adjust[j])

        # Create the YYYYMMDD string that goes in the hash
        # (remember leading zeroes for day and month).
        yyyymmdd_str = str(dt.year) + "%02d" % dt.month + "%02d" % dt.day

        # Recalculate the hash:
        h = hashlib.sha1(
            b''.join(
                payload_sha128,
                bytes(
                    yyyymmdd_str + nonce_hex_str, 'utf-8'))).digest()

        debug_msg(
            7,
            'Length of hash in verify_pow is : ' + str(len(h))
            + ' for ' + str(h))

        # Construct a bit mask.  It will contain
        # 1-bits in the high-order part so that the
        # number of high-order 1 equals "target_bits"
        # (big-endian).
        # When the bitwise & of the mas and the "found
        # hash codes" is all 1s, then we have found
        # a key the produces the desired number of leading
        # 1-bites.
        mask = 1 << (8 * hash_len_bytes - 1)
        for i in range(target_bits - 1):
            mask = mask | 1 << (hash_len_bytes * 8 - i - 1)

        i = int().from_bytes(h, 'big')
        if mask & i == mask:
            debug_msg(
                7,
                'Proof of work verified with mask\n' + bin(mask)
                + '\nand hash\n' + bin(i))

            good = True

        j += 1

    #
    if good:
        debug_msg(5, 'The POW is good.')

        return(0)
    else:
        debug_msg(5, 'The POW is bad.')

        return(-1)


###############################################################################
###############################################################################
def xor_and_write(fname_prefix=None, msg_chunks=None, out_dir=None):
    """Create the parity block and write shards to disk.

    This will accept an array of data, create the parity block for them,
    then write all the files to disk using fname_prefix as the prefix
    of each filename along with a letter suffix to indicate which shard it is.

    Keyword arguments:
    fname_prefix -- A prefix for a set of temporary file names that are created
        when the message is cut into shards.  Thos prefixes also appear on the
        receiving end, so they should follow the prescribed values in
        natmsgactions.metadata_prefixes (such as _P for password shards).
    msg_chunks -- A list object containing the shards.
    out_dir -- A directory where the shard files will be written.

    Return value:
    0 for success, else nonzero.
    """

    if msg_chunks is None:
        print('Error. The msg_chunks array was not sent to xor_and_write.')
        return(27000)

    if not isinstance(msg_chunks, list):
        print('Error. The msg_chunks array was not of type list '
              + 'in xor_and_write.')
        return(27100)

    if fname_prefix is None:
        print('Error. The fname_prefix option was not sent to xor_and_write.')
        return(27200)

    if fname_prefix == '':
        print('Error. The fname_prefix option was blank in xor_and_write.')
        return(27300)

    msg_parity = None
    err_nbr, msg_parity = shard_xor(action='c', chunks_array=msg_chunks)
    if msg_parity is None:
        return(print_err(27400, 'Error. I could not get the msg parity.'))

    output_idx = 0
    for c in msg_chunks:
        # Write shards to the output directory
        #
        # shard_letter = chr(ord('a') + output_idx)
        shard_letter = str(output_idx + 1)

        if out_dir is None:
            shard_fname = fname_prefix + str(output_idx)
        else:
            shard_fname = out_dir + os.sep + fname_prefix + shard_letter

        debug_msg(4, 'Preparing to write shard to ' + shard_fname)

        fd_o = open(shard_fname, 'wb')
        fd_o.write(c)
        os.fsync(fd_o.fileno())
        fd_o.close()
        output_idx += 1

    # Write the parity block, but this needs to be converted to b64 first.
    if out_dir is None:
        shard_fname = fname_prefix + 'X'
    else:
        shard_fname = out_dir + os.sep + fname_prefix + 'X'

    fd_o = open(shard_fname, 'wb')
    fd_o.write(msg_parity)
    os.fsync(fd_o.fileno())
    fd_o.close()

    debug_msg(3, 'Wrote shard to file: ' + shard_fname)
    return(0)


##############################################################################
###############################################################################
###############################################################################
###############################################################################
###############################################################################
def nm_write_shard_status(
        fname,
        status,
        return_err_nbr=0,
        error_detail=None):
    """Write status to disk for a shard that is coming or going.

    This will write a brief status report to a file or update an
    existing one.  This was designed to keep status of incoming
    or outgoing shards on disk so that (in the future) I might
    be able to continue sending or receiving after the client
    computer crashes in the middle of a big operation.

    status is defined by the caller, but probably contains
    string values like 'initializing,' 'sending,' 'receiving,'
    'failed,' 'sent,' 'received'

    error_detail can be a string or dictionary object that
    provides more information about an error. This function
    will keep the first error and the latest error along with
    the time that the file was originally created and the
    time of the latest update.

    To Do: decide if if the caller should trap the error or
    if I should raise an error and halt. I could also let
    the caller end processing when the error_count in the
    status file reaches as specified number or when a time
    limit has been reached.

    Positional arguments:
    fname -- Name of status file (one file per shard ID).
    status -- The text that represents the status of the shard.

    Keyword arguments:
    return_err_nbr -- Defaults to 0.  This is the return code.
        Not sure why this is specified as an argument.
    """
    #  global lock

    output_d = {}  # Staging for the JSON that this will write to disk.

    time_stamp = int(datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S"))

    out_dir = os.path.dirname(fname)
    if not os.path.isdir(out_dir):
        # if the output directory does not exist, create it
        os.makedirs(out_dir, exist_ok=True)

    if os.path.isfile(fname):
        # Read the existing data and keep some parts of it:
        try:
            fd = codecs.open(fname, 'r', 'utf-8')
            # Load the data and make it a dictionary object.
            output_d = json.loads(fd.read())
            fd.close()
        except:
            e = str(sys.exc_info()[0:2])
            print_err(
                5850,
                'Could not read the existing status file: '
                + fname + '. ' + e)
            # keep going..
        if fd:
            fd.close()

        try:
            output_d['status'] = status
            output_d['time'] = time_stamp
        except:
            e = str(sys.exc_info()[0:2])
            return(print_err(
                5851,
                'Could not update dictionary for: ' + fname + '. ' + e))

        if status.lower() == 'error':
            if 'error_count' in output_d.keys():
                # Update the error count
                output_d['error_count'] = output_d['error_count'] + 1
            else:
                # Initialize the error count
                output_d['error_count'] = 1

        if error_detail is not None:
            if 'first_error' not in output_d.keys():
                output_d['first_error'] = error_detail
            else:
                output_d['latest_error'] = error_detail

    else:
        # Try to create a new status file:
        output_d['status'] = status
        output_d['first_time'] = time_stamp
        output_d['time'] = time_stamp
        if error_detail is not None:
            output_d['first_error'] = error_detail

        if status.lower() == 'error':
            # Initialize the error count
            output_d['error_count'] = 1

    zzz = json.dumps(output_d)
    # #lock.acquire()
    try:
        fd2 = open(fname, 'wb')
        fd2.write(bytes(zzz, 'utf-8'))
    except:
        e = str(sys.exc_info()[0:2])
        try:
            fd2.close()
        except:
            pass

        return(print_err(
            28000,
            'Could not write to the status file: ' + fname + '. ' + e))
    finally:
        os.fsync(fd2.fileno())
        fd2.close()

    # ### redundant file close?
    # #os.fsync(fd2.fileno())
    # #fd2.close()

    return(return_err_nbr)


###############################################################################
def get_status(status_fname):
    """Read the status (from disk) of a shard-in-progress.

    If the specified JSON is found, it will be loaded into
    a Python dictionary object and returned.

    This returns a tuple: (return_code, dictionary)
    but the dictionary will be None if there is an error
    or if the file is not found.

    Positional arguments:
    status_fname -- The filename of the file that contains the status code
        for one shard.
    """

    if not os.path.isfile(status_fname):
        # Not a file
        debug_msg(4, 'Status file not found: ' + status_fname)
        return(28100, None)
    else:
        status_json = None
        try:
            fd_status = codecs.open(status_fname, 'r', 'utf-8')
            status_json = json.loads(fd_status.read())
        except:
            e = str(sys.exc_info()[0:2])
            try:
                fd_status.close()
            except:
                pass
            return((print_err(
                28200,
                'Can not load the JSON from the status file: '
                + str(status_fname)), None))

    return((0, status_json))


# ---------------------------------------------------------------------
def show_shard_status(wrk_dir, shard_args, interval=3):
    """Display the status of shards listed in shard_args.

    For each entry in the shard_args (based on class ShardSendQueueArgs),
    get the shard_id and read .status files in the specified
    directory that correspond to the shard IDs in shard_args.shard_ID,
    and print a line that summarizes the results.

    The output looks something like:

            Shards sent: 3, shards failed: 0, shards sending: 1

    This will loop until all the shards report as 'sent' or
    'received' or 'failed'.

    shard_args should be an array of class objects that define
    .shard_id.

    Positional arguments:
    wrk_dir -- A working directory where status file are saved.
    shard_args -- An object of class ShardSendQueueArgs), which
        contains file paths and other things for the shards.

    Keyword arguments:
    interval = The time (in seconds) between reports of the shard
        status.

    Return value:
    0 on success, else nonzero.
    """
    loop_count = 0
    completed = False
    while not completed:
        status_dict = {}
        finalized_count = 0
        for sa in shard_args:
            # For each shard_ID, verify that the status is 'sent'. If
            # status is 'failed', then resend.  If it has been more than
            # 5 minutes, resend (allow time for slow uploads?).
            status_fname = os.path.join(wrk_dir, sa.shard_id + '.status')
            st = None
            status_json = None
            try:
                fd_status = open(status_fname, 'r')
                status_json = json.loads(fd_status.read())
            except:
                e = str(sys.exc_info()[0:2])
                try:
                    fd_status.close()
                except:
                    pass
                if loop_count > 1:
                    return(print_err(
                        28300,
                        'In show_shard_status, status file is not ready yet: '
                        + status_fname + '. ' + (e)))
            else:
                # The inital parse of JSON is OK.
                fd_status.close()

                try:
                    st_value = status_json['status']
                except:
                    e = str(sys.exc_info()[0:2])
                    return(print_err(28400, 'In show_shard_status: ' + (e)))

                if st_value is not None:
                    if st_value in status_dict.keys():
                        # If the current status value is already in my
                        # local status_dict, update my local status_dict
                        # with the count.
                        # 'st_value' is the value of the status, like
                        # 'failed' or 'sent', and
                        # that becomes the key in status_dict and points
                        # to a count.
                        status_dict.update(
                            {st_value: status_dict[st_value] + 1})
                    else:
                        status_dict.update({st_value: 1})
                    if st_value in ['sent', 'received', 'failed']:
                        finalized_count += 1

            if finalized_count == len(shard_args):
                completed = True

        print('shard status... ', end='')
        for d in status_dict.keys():
            print(d + '=' + str(status_dict[d]) + '  ', end='')

        print('')  # EOL

        if len(status_dict) == 1:
            if 'sent' in status_dict.keys() \
                    or 'received' in status_dict.keys() \
                    or 'failed' in status_dict.keys():
                completed = True
            else:
                time.sleep(interval)
        else:
            time.sleep(interval)

        loop_count += 1
    return(0)


###############################################################################
###############################################################################
###############################################################################
###############################################################################
def nm_smd_create(
        web_host,
        dest_box_id,
        cargo_bytes=None,
        add_proof_of_work=False):
    """Create a shard metadata record to send a message.

    This is for creating normal shard metadata record
    to send a NM message on the NM network.  This version
    is not ready for SMTP transport.

    The shard metadata file contains the destination ID, a legal message,
    a list of URLs where shards are stored, a key-encryption key (it
    unlocks pieces of an encrypted password, then that password can
    decrypt the shard), and a few other things.

    When the shared secret is implemented, the metadata will
    contain the destination ID, the legal notice, and a block
    of encrypted data that only the recipient can read.

    This will return a tuple with err_nbr and err_msgd
    where err_msgd is a dictionary object.

    Positional arguments:

    Keyword arguments:
    cargo_bytes -- A bytes object with the metadata (base64 format?).
    add_proof_of_work -- Boolean.  True if POW is needed.


    Return value:
    a tuple (return_code, msg)
    """

    if dest_box_id is None:
        return((29000, {'Error': 'dest_box_id was missing in nm_smd_create.'}))

    if not isinstance(cargo_bytes, bytes):
        return((
            29100,
            {'Error': 'Cargo_bytes sent to nm_smd_create was not in '
             + 'python bytes() format.'}))

    cargo_sha1 = hashlib.sha1(cargo_bytes).digest()  # binary

    nm_pow = create_shard_pow(
        cargo_sha1,
        len(cargo_bytes),
        pow_factor=1,
        min_bits=12,
        bit_constant=3)

    debug_msg(6, 'In nm_smd_create, final pow is ' + nm_pow)

    if add_proof_of_work:
        url = web_host + '/smd_create?public_recipient=' + dest_box_id \
            + '&nm_pow=' + nm_pow
    else:
        url = web_host + '/smd_create?dest_public_box_id=' + dest_box_id

    attached_files = {
        'shard_metadata': (
            'shard_metadata',
            cargo_bytes,
            'application/x-download', {'Expires': '0'})}

    r = None
    requests.packages.urllib3.disable_warnings()
    try:
        r = requests.post(
            url,
            headers={'User-Agent': ''}, verify=False, files=attached_files)
    except:
        err_msg = 'Faled to post shard_metadata'
        if r is not None:
            err_msg += '  Detail' + r.text
        return((29200, {'Error': 'Could not create smd record.'}))

    debug_msg(5, 'In nm_smd_create, url was ' + url)

    json_err_msg = None
    if r is None:
        return((29203, {'Error': 'Server result is unexpectedly undefined.'}))
    else:
        try:
            # see if there is a JSON error message:
            json_err_msg = r.json()['smd_create']['Error']
        except:
            # There is no error message that is logged
            # under the key "Error" (case sensitive),
            # which is good.
            # I will use the "None" test below
            pass

        if json_err_msg is not None:
            # There is an error message in the JSON,
            # record an error and log it.
            return((29300, {'Error': json_err_msg}))
        else:
            # There was no error message (case sensitive).
            svr_response = None
            try:
                svr_response = r.json()['smd_create']
            except:
                return((29400, {
                    'Error': 'The response does not have '
                    + 'the JSON entry for smd_create.' + str(r.text)}))

            if svr_response is not None:
                # valid JSON response... check for error mesages.
                err_response = None
                try:
                    err_response = r.json()['smd_create']['Error']
                except:
                    pass

                if err_response is not None:
                    return((29500, {'Error': err_response}))
                else:
                    # good
                    return((0, dict(svr_response)))


###############################################################################
###############################################################################
###############################################################################
###############################################################################
def nm_gen_shard_id():
    """Generate a random shard ID.

    This will generate a random, 128-bit shard ID that will
    be used as the destination address for shards that are
    pushed to shard servers.  The resultign prefix is SID.
    """
    return(
        'SID'
        + base64.b16encode(
            RNCryptor.Random.new().read(
                17)).decode('utf8').upper()[0:32])


###############################################################################
###############################################################################
###############################################################################
###############################################################################
###############################################################################
###############################################################################
# This version finds parity block for an arbitrary number
# of blocks, and automatically calculates the block size,
# but it does not enforce a minimum block size.
#
# New programmer notes: python3 uses utf8 by default and handles
# all the decoding automagically.  Given s = 'abcdefg',
# s[0] refers to
# the first "character," regardless of its encoding.
# I will perform the parity operations using the 'bytes' view
# of the data (so that python looks at the integer representation
# of each character). I will add a pad byte if I need to make
# the byte-count even.
def shard_xor(
        action,
        chunks_array=None,
        chunks_fname_array=None,
        recovered_shard_fname=None):
    """Peform XOR operations on a shard for redundancy.

    Action is either 'c' for Creating a parity block, or 'r' to
    Reconstruct a missing block. The required order of items in the chunks
    array depends on the action code.

    This returns err_nbr, err_msg, and data block (or None if there is no
    data block).

    ======= FOR ACTION C -- CREATING A PARITY BLOCK ========
    Supply EITHER chunks_array as an array of data or chunks_fname_array
    as an array of ordered fnames with the parity block last.

    This method will xor the data together and return the result.  If
    recovered_shard_fname is given, the result will be written only
    to that location, otherwise the xor-ed result will be returned.

    When CREATING a parity block, all but the last chunk
    needs to have the same length.  The last chunk must have a
    length equal to the others or one or two bytes shorter.

    When CREATING a parity block, all shards must be present
    (do not call this with a shard missing).

    ======= FOR ACTION R -- RECONSTRUCTING A MISSING SHARD ========
    When recovering a missing block, the last thing in the
    array is the parity block, and the next-to-the last
    thing would be the last block from the original set
    of chunks (if that shard is present).

    A missing shard is represented with a null bytes object
    (b'') in the chunks_array or null string for fnames ('').

    """
    action = action.lower()

    # Note that python xor (^) works on integers only.
    block_sizes = []
    save_block_size = -1

    if chunks_array is None:
        # load all the files into buffers and then process using the existing
        # buffer logic below
        chunks_array = [b''] * len(chunks_fname_array)
        idx = 0
        for f in chunks_fname_array:
            if f != '':
                try:
                    fd = open(f, 'rb')
                    chunks_array[idx] = fd.read()
                    fd.close()
                except:
                    e = repr(sys.exc_info()[0:2])
                    return((print_err(
                        29600,
                        'Could not read shard #'
                        + str(idx) + ' in shard_xor. ' + e), None))

            idx += 1

    if chunks_array is not None:
        debug_msg(8, 'In shard_xor, CHUNK lengths are:\n')
        for junks in chunks_array:
            debug_msg(8, str(len(junks)))

        debug_msg(
            8,
            'In shard_xor, CHUNKS contents are:\n' + repr(chunks_array))
        block_count = len(chunks_array)

        if action == 'r':
            if not isinstance(chunks_array[-1], bytes):
                return((print_err(
                    29700,
                    'The last input chunk to shard_xor was not a bytes '
                    + 'object.'), None))

        # Some error checking:
        for b in chunks_array:
            if not isinstance(b, bytes):
                return((print_err(
                    29800,
                    'One of the chunks sent to shard_xor was not a bytes '
                    + 'object.'), None))

            block_sizes.append(len(b))

            if b == b'':
                if action == 'c':
                    return((print_err(
                        29900,
                        'In shard_xor, a block has zero length for '
                        + 'action=c.'), None))

            if save_block_size < 0 and b != b'':
                # save the block len but ignore an empty chunk.
                save_block_size = len(b)
                debug_msg(5, 'In shard_xor, block size is ' + str(len(b)))

            if block_sizes[-1] != save_block_size:
                # For action 'c', the last block length can be short, but
                # the others need to be the same as the first
                # block length.
                # For action 'l', the next-to-the-last block
                # length can be short.
                if action == 'c':
                    if len(block_sizes) != len(chunks_array):
                        # This is not the last chunk, so the sizes
                        # should be the same.
                        return((print_err(
                            30000,
                            'The chunks sent to shard_xor() had '
                            + 'inconsistent lengths.'), None))

                    if block_sizes[-1] > save_block_size:
                        return((print_err(
                            30100,
                            'A chunk sent to shard_xor() had was bigger '
                            + 'than the first chunk'), None))
                else:
                    # action == 'r'
                    if b != b'' and len(block_sizes) != len(chunks_array) - 1:
                        # This is not the next-to-last chunk, so the
                        # sizes should be the same.
                        return((print_err(
                            30200,
                            'The chunks sent to shard_xor() had inconsistent '
                            + 'lengths.'), None))

                    if b != b'' and block_sizes[-1] > save_block_size \
                            and (len(block_sizes) != len(chunks_array)):
                        # The parity block at the end will be big due
                        # to tripple base64,
                        # but otherwise it is an error.
                        return((print_err(
                            30300,
                            'A chunk sent to shard_xor() had was bigger '
                            + 'than the first chunk'), None))

        result = bytearray()
        for j in range(save_block_size):
            # For each index into the block length,
            this_byte = 0
            for k in range(block_count):
                # #if block_sizes[k] == block_sizes[0]:
                if j < block_sizes[k]:
                    # Get the jth byte from each block and xor them together
                    # except if it is the final chunk that has a short length,
                    # in which case the logic is the same as counting it as
                    # a zero shard (this format is used to match what
                    # was used in the original Mac OS X client).
                    this_byte ^= chunks_array[k][j]

            result.append(this_byte)

    if recovered_shard_fname is not None:
        debug_msg(
            4,
            'Writing the recovered shard to: '
            + recovered_shard_fname)
        fd = open(recovered_shard_fname, 'wb')
        fd.write(bytes(result))
        os.fsync(fd.fileno())
        fd.close()

    # Return the parity thing as a regular
    # bytes object:
    return((0, bytes(result)))


###############################################################################
#               Slice the data into chunks
###############################################################################
def nm_slice(bytes_in, shard_count=3):
    """Slice a message (or data) into shards.

    Given some text and a shard count ('shards' = pieces),
    slice the text into 'shard count' number of pieces.
    This does not pad the last shard in the event that it
    is not divisible by the shard_count.
    The output is a tuple with the first part being
    the pad count and the second being an array
    of Python 'bytes objects' with similar byte
    counts (but the last one might be short to match
    what Chris did in the original Mac OS X client).

    If there is an error, the first element of the
    returned tuple will be less than zero.

    Positional arguments:
    bytes_in -- A bytes object with the message to slice.

    Keyword arguments:
    shard_count -- Integer. Default = 3.


    Return value:
    Tuple.  On success, (pad_count, list_object_with_slices)
    else (negative_number, msg)
    """
    if not isinstance(bytes_in, bytes):
        print("Error.  You sent something other than a bytes() "
              + "object to nm_slice().")
        return((-1, []))

    pad_count = len(bytes_in) % shard_count
    pad = []
    default_chunk_size = int(len(bytes_in) / shard_count)

    if pad_count != 0:
        for j in range(pad_count):
            # Add filler byte to the next thing in the array
            pad.append(b'x\00')
            pad_count += 1

        default_chunk_size += 1

    # I am no longer padding the last shard
    # with zeroes because the OS X client
    # does not do so (we store pad_count
    # in encrypted form in the shard_metadata
    # to allow for recovery).
    # # b = b''.join([bytes_in, b''.join(pad)])

    # New version without trailing pad zeroes:
    debug_msg(5, 'Pad count is ' + str(pad_count))
    debug_msg(
        6,
        'Length of bytes version of text: final is '
        + str(len(bytes_in)))
    debug_msg(6, 'chunk size is ' + str(default_chunk_size))
    # ----------------------------------------
    #    Split the original binary data into chunks

    # declare an array
    chunks = []

    for j in range(shard_count):
        # This calculates the start and end of each shard
        # and extracts the values into the 'chunks' array.
        # A loop for j = 0 to j = shard_count
        # Python uses zero-based arrays, and will not do the
        # final loop for j = shard_count.
        strt = j * default_chunk_size
        # The end index in python is the index value one greater than what
        # we want to grab:
        end = (j + 1) * default_chunk_size
        debug_msg(
            5,
            'Start and end indexes (in Python format) for getting shards: '
            + str(strt) + ', ' + str(end))

        chunks.append(bytes_in[strt: end])

    return((pad_count, chunks))


###############################################################################
def nm_reassemble_shards(
        shard_fname_array,
        output_fname,
        parity_version=1,
        delete_shard_for_testing=False):
    """Reassemble shards or use the parity block for recovery.

    This will reassemble shards that have already be staged on a local
    storage device.  The shard_fname_array should
    should contain an ordered list of the filenames that
    hold shards that need to be reassembled.  Any parity blocks
    should be last.    If any items are missing, include them
    as an empty string ''.

    Positional arguments:
    shard_fname_array -- a list of filenames for the shards to reassemble.
    output_fname -- name for the reassembled file.

    Keyword arguments:
    parity_version -- currently defautls to 1.
    delete_shard_for_testing -- For testing purposes, delete a shard
        before reassembling the shards.

    Return value:
    0 on success, else nonzero.
    """
    debug_msg(
        4,
        '** nm_reassemble_shards fname array ' + str(shard_fname_array))

    failure_count = 0  # More than one missing shard is fatal.
    parity_needed = False

    if delete_shard_for_testing is None:
        delete_shard_for_testing = False

    if delete_shard_for_testing:
        # See if parity block recovery works
        shard_fname_array[delete_shard_for_testing] = ''
        debug_msg(
            1,
            '*** Deleting shard for testing: '
            + str(delete_shard_for_testing)
            + '.  The fname array is now: ' + repr(shard_fname_array))

    j = 1
    missing_shard_idx = -1
    for j in range(len(shard_fname_array) - 1):
        if shard_fname_array[j] == '':
            missing_shard_idx = j
            failure_count += 1

        # to do: add a check for zero file size -- add to failure_count xxx

        if failure_count > 1:
            return(31000)  # can not reassemble
            break

    if failure_count == 1:
        # check for the parity block filename
        if shard_fname_array[-1] == '':
            return(31100)
        else:
            parity_needed = True

    if parity_needed:
        # If parity recovery is needed, recover the shard here,
        # then continue with regular processing below.
        # To do, add directory
        #
        # I can not say /tmp because that is not valid on all OS
        fname_recovered = tempfile.mktemp(prefix='natmsg-tmprcvd-')

        err_nbr,  recovered_block = shard_xor(
            action='r',
            chunks_fname_array=shard_fname_array,
            recovered_shard_fname=fname_recovered)

        # Put the recovered shard name into the list
        shard_fname_array[missing_shard_idx] = fname_recovered

    # Simple reassemble:
    try:
        # I will write several times to the output file,
        # but I don't think there is any need for 'wb+'.
        fd_out = open(output_fname, 'wb')
    except:
        try:
            if fd_out:
                fd_out.close()
        except:
            pass

        return(31200)

    for j in range(len(shard_fname_array) - 1):
        debug_msg(5, 'Reassembling ' + str(j) + ' ' + shard_fname_array[j])

        try:
            fd_in = open(shard_fname_array[j], 'rb')
        except:
            e = repr(sys.exc_info()[0:2])
            # xxxx i get this message when the file exists!!
            # xxxx i get this message when the file exists!!
            # xxxx i get this message when the file exists!!
            # xxxx i get this message when the file exists!!
            # xxxx i get this message when the file exists!!
            # xxxx i get this message when the file exists!!
            # xxxx i get this message when the file exists!!
            # xxxx i get this message when the file exists!!
            # xxxx i get this message when the file exists!!
            print('WARNING (this should be a fatal errror for '
                  + 'this message): failed to open shard for reading '
                  + shard_fname_array[j] + '. ' + e, file=sys.stderr)

        else:
            try:
                fd_out.write(fd_in.read())
            except:
                e = repr(sys.exc_info()[0:2])
                print('WARNING: failed to read shard from '
                      + shard_fname_array[j]
                      + ' and stream to ' + output_fname
                      + '. ' + e, file=sys.stderr)
                fd_in.close()
            else:
                os.fsync(fd_out.fileno())
                fd_in.close()

    # Don't close the output file until all the shards have been read.
    fd_out.close()

    return(0)


###############################################################################
def nm_inbox_read(
        host,
        port_nbr,
        private_box_id=None,
        smd_id=None,
        save_dir=None):
    """Read the inbox to check for messages.

    This will read an inbox and write each shard metadata file
    to a subdirectory under the save_dir.

    This needs to be modified so that once the server responds,
    I never terminate processing due to bad content -- just return
    shard_metadata of None and continue reading the inbox.

    I am in the process of revising this to facilitate restarts
    after a crash that occurs saving information. Save this stuff:
      * SMD DATA until the file has been successfully read.
      * THE FULL ARCHIVE OF THE MESSAGE,
      * subject, reply-to, destination box ID, archive sha1, maybe the
        first 200 chars, attachment sizes, stored either
        in a separate file with the same basename and a different extension
        or in a separate database (or build the db by scanning the files).
      * A message browser that can list subjectlines and allow the user
        to unarchive and read them.
      * filename {in/out}YYMMDDHHMMSS##.{json/meta.json}


    To Do: open files that are received, unless they are executable!
    Commands:
        mac os x = /usr/bin/open
      windows = start (os.startfile(); os.system(start notepad.exe); Popen...)
      linux = xdg-open
    returns error code or zero.

    Positional arguments:
    host -- Host name for the directory server, such as https://123.456.123
    port_nbr -- port number for the directory server.

    Keyword arguments:
    private_box_id -- The private box ID of the user.
    smd_id -- A shard meta ID to read (for the old-school email transport)
    save_dir -- The directory under which retrieved messages will go. Each
        message will go to a numbered subdirectory, starting with 001.


    Return value:
    Integer return value.  0 if good.
    """

    old_school = False

    if private_box_id is None and smd_id is None:
        return(print_err(
            10800,
            'Neither private box ID nor smd_id was '
            + 'sent to nm_inbox_read.'))

    if private_box_id is not None and smd_id is not None:
        return(print_err(
            10801,
            'Both private box ID and smd_id were '
            + 'sent to nm_inbox_read -- you mus send '
            + 'one or the other.'))

    if smd_id is not None:
        old_school = True

    dest_public_box_ids = []
    svr_json = None
    shard_metadata = None

    if host[0:8] != 'https://':
        return(print_err(
            10802,
            'The host should begin with https://, but it did not.'))

    try:
        cryptor = RNCrypt_bob()
    except:
        return(print_err(10803, 'Failed to initialize RNCryptor.'))

    # The client app might set the max_reads value to 100
    # so that the client reads no more than 100 message
    # per fetch. TO DO: setting a max might leave the
    # last read unburned.
    max_reads = 200
    EOF = False

    if save_dir is None:
        # All this error
        return(print_err(897, 'Save_dir was not specified in nm_inbox_read.'))

    if private_box_id is not None:
        url = host + ':' + str(port_nbr) \
            + '/inbox_read?dest_private_box_id=' \
            + private_box_id
    else:
        url = host + ':' + str(port_nbr) \
            + '/inbox_read?email_smd_id=' + smd_id

    # The counter is used to compare to max_reads:
    inbox_count = 0
    session_id = None
    previous_smd_id = None
    while not EOF and inbox_count < max_reads:
        # xxxx feb 24
        r = None
        shard_metadata = None
        svr_json = None
        if session_id is None:
            # On the first read or old-school read, I don't have a session ID
            debug_msg(5, 'In inbox_read, first read.')

            requests.packages.urllib3.disable_warnings()
            try:
                r = requests.get(url, headers={'User-Agent': ''}, verify=False)
            except:
                e = repr(sys.exc_info()[0:2])
                # Halt on server errors (but not not invalid SMD format).
                return(print_err(
                    31300,
                    'Could not get URL on first inbox read. The URL was '
                    + url + '. ' + repr(e)))
        else:
            # Subsequent reads include the 'previous_smd_id' and session_id.
            debug_msg(5, 'In inbox_read, subsequent read, prior smd is '
                      + repr(previous_smd_id))

            url = host + '/inbox_read?dest_private_box_id=' + private_box_id \
                + '&session_id=' + str(session_id) + '&previous_smd_id=' \
                + previous_smd_id

            try:
                r = requests.get(url, headers={'User-Agent': ''}, verify=False)
            except:
                e = repr(sys.exc_info()[0:2])
                # Halt on server errors (but not not invalid SMD format).
                return(print_err(
                    31300,
                    'I could not get subsequent inbox read. '
                    + 'The URL was ' + url + '. ' + repr(e)))

        if r is not None:
            # At this point, do not return an error message unless it
            # is a server error.  If the SMD is corrupt, send a
            # shard_metadata of None instead (so that a bad SMD does not
            # stick in the queue... we need to get past it and submit
            # it as a previous_smd_id to kill bad smds.

            # un-base64 it, but allow for nonbase64
            debug_msg(8, 'In inbox_read has a response from the server: ' + repr(r))

            try:
                # The SMD was wrapped in Base64 (CJ-style), so unwrap
                # it and put it
                # into a Python dictionary object
                svr_json = json.loads(base64.b64decode(r.text))
            except:
                pass

            if svr_json is None:
                # This should be the normal execution path...
                # The SMD was not wrapped in Base64 -- try reading it directly.
                # If somebody sends trash to the SMD, I need to ignore
                # it and get to the next iteration.
                try:
                    svr_json = r.json()
                except:
                    pass

        if svr_json is None:
            return(print_err(
                31500,
                'The server did not return JSON for a shard '
                + 'metadata (or B64-wrapped JSON). The URL was ' + url + '.'))
        else:
            # I now have svr_json, which might have come from a 'first read'
            # or a 'subsequent read.'

            err_msg = None
            if 'inbox_read' not in svr_json.keys():
                # bad error
                print_err(
                    31505,
                    'There was an error reading shard meta data. '
                    + 'The keys are ' + repr(svr_json))
                junk = input('press any key to continue...')

            debug_msg(8, 'In inbox_read I have JSON.')

            if 'Error' in svr_json['inbox_read'].keys():
                # The 'Error' key is case sensitive.
                err_msg = svr_json['inbox_read']['Error']

            if err_msg is not None:
                # There is an error message in the JSON,
                # record an error and log it.
                svr_json = None  # Cancel the SMD data and keep the loop going.
                print_err(31600,  'Inbox_read failed: <' + err_msg + '>.')
            else:
                # There was no error message, check for a misspelled error
                # (or all uppercase error message).
                # This is to find sloppy work on the server program.
                svr_response = None
                try:
                    svr_response = svr_json['inbox_read']
                except:
                    e = repr(sys.exc_info()[0:2])
                    svr_json = None
                    print_err(
                        31700,
                        'The response does not have '
                        + 'the JSON entry for inbox_read. ' + e)

                if svr_json is None:
                    return(print_err(
                        31800,
                        'The server did not respond.  URL was ' + url))
                else:
                    # Verify the available keys--ignore junk SMD.
                    # We absolutely need session_id and smd_id from the server.
                    # Without this nothing will allow us to burn entries from
                    # the inbox.
                    if 'status' not in svr_json['inbox_read'].keys():
                        EOF = False
                    else:
                        if svr_json['inbox_read']['status'] == 'EOF':
                            EOF = True

                    if not EOF:
                        # Stop processing when I receive EOF... there
                        # will be nothing else
                        # in the JSON if EOF is there.
                        if 'session_id' not in svr_json['inbox_read'].keys():
                            print('==WARNING: SESSION_ID NOT FOUND')
                        else:
                            session_id = svr_json['inbox_read']['session_id']

                        if 'smd_id' not in svr_json['inbox_read'].keys():
                            return(print_err(
                                32000,
                                'The server did not include an smd_id '
                                + 'in the JSON of a shard_metadaa record. '
                                + 'This is a server error: ' + url))
                        else:
                            # I do not write smd_id below, I hold it
                            # until I make the next request
                            smd_id = svr_json['inbox_read']['smd_id']
                            previous_smd_id = svr_json['inbox_read']['smd_id']

                        if 'dest_public_box_id' not in svr_json['inbox_read']:
                            dest_public_box_id = ''
                        else:
                            dest_public_box_id = \
                                svr_json['inbox_read']['dest_public_box_id']

                        if 'shard_metadata' \
                                not in svr_json['inbox_read'].keys():
                            shard_metadata = ''
                            subj_reply_to = ''
                        else:
                            # shard_metadata is wrapped in the event
                            # that a user sends binary garbage
                            shard_metadata = base64.b64decode(bytes(
                                svr_json['inbox_read']['shard_metadata'],
                                'utf-8')).decode('utf-8')

                            if 'meta' not in json.loads(shard_metadata).keys():
                                subj_reply_to = ''
                            else:
                                smd_dict = json.loads(shard_metadata)
                                # The subject and the reply to are encrypted
                                # with the first password,
                                # which is the one that was sharded.
                                #
                                # Leave it as a base64 string for now:
                                subj_reply_to = smd_dict['meta']

                        if 'status' not in svr_json['inbox_read'].keys():
                            EOF = False
                        else:
                            if svr_json['inbox_read']['status'] == 'EOF':
                                EOF = True
                        # - - - - - - - - - - - - - - - - - - -
                        # Save the smd here
                        this_dir = save_dir \
                            + os.sep + "%04d" % (inbox_count + 1)
                        try:
                            # Allow for recover rerun:
                            os.makedirs(this_dir, exist_ok=True)
                        except:
                            return(print_err(
                                32100,
                                'Could not create the directory '
                                + 'to save shard metadata.'
                                + this_dir))

                        if shard_metadata is not None:
                            with open(
                                    this_dir + os.sep
                                    + 'shard_metadata_staged',
                                    'wb') as fd:
                                debug_msg(
                                    3,
                                    'Writing shard metadata to ' + this_dir)

                                fd.write(bytes(shard_metadata, 'utf-8'))
                                os.fsync(fd.fileno())

                            # Write the dest public box ID to a file
                            # in the same place as the metadata
                            # so that I can decrypt it after I
                            # reassmble the password shards.
                            with open(this_dir + os.sep + 'meta2', 'wb') as fd:
                                fd.write(
                                    bytes(
                                        '{"dest":"' + dest_public_box_id
                                        + '","subj_reply_to_enc":"'
                                        + subj_reply_to + '"}', 'utf-8'))
                                os.fsync(fd.fileno())

                                inbox_count += 1

        if old_school:
            # break from the loop
            EOF = True
        # end of the while loop

    return(0)


###############################################################################
###############################################################################
###############################################################################
def nm_secure_remove(fname, passes=3):
    """Securely erase a file.

    This might help to securely erase a file that is stored on a hard disk.
    This technique might not work on SSD drives that remap disk sectors
    behind the scenes, but it couldn't hurt.
    Another approach is to ocassionally write giant files of random data
    to fill your disk, then erase them and repeat.  That way
    most of your freed space will be overwritten with random data.

    Positional arguments:
    fname -- file name to erase.

    Keyword arguments:
    passes -- number of times that the file is overwritten with junk data.

    Return value:
    0 on success, else nonzero.
    """

    print('temporarily not erasing files')
    return (0)

    blk_size = 1024
    fsize = os.path.getsize(fname)
    bytes_written = 0

    debug_msg(6, 'securely removing ' + fname)
    with open(fname, "wb+") as fd:
        for idx in range(passes):
            fd.seek(0)
            while bytes_written < fsize:
                if (bytes_written + blk_size) < fsize:
                    blk = RNCryptor.Random.new().read(blk_size)
                else:
                    blk = RNCryptor.Random.new().read(fsize - bytes_written)

                fd.write(blk)
                bytes_written += len(blk)
        # The 'with' statement will close the file.
        # for erasing, fsync is probably not needed
        # #os.fsync(fd.fileno())

    # overwrite the name with base64 characters
    fdir = os.path.dirname(fname)
    old_name = fname
    for j in range(passes):
        new_name = os.path.join(fdir, base64.b16encode(
            RNCryptor.Random.new().read(17)).decode('utf8').upper()[0:32])

        try:
            os.rename(old_name, new_name)
        except:
            e = repr(sys.exc_info()[0:2])
            # failed to rename file
            return(print_err(32200, 'Failed to rename a file '
                   + 'during deletion process: '
                   + fname + '. ' + e))
        old_name = new_name

    try:
        os.remove(new_name)
    except:
        e = repr(sys.exc_info()[0:2])
        # failed to remove file
        return(print_err(32300, 'Failed to remove a file during '
               + 'deletion process: ' + fname + '. ' + e))

    return(0)


###############################################################################
def nm_account_create(
        private_box_id=None,
        host=None,
        requested_expire_yyyymmdd=None,
        batch=False):
    """Create a new account (public/private ID pair or just public ID).

    The default behavior here is to create a new private box ID (Identity) and
    one public box ID. If the user sends a private box ID, then this will add
    one public box ID that is associated with that private box ID.

    If the expire date is specified, this will ask the server to create a new
    public box ID with that expiration date.  You should probably specify
    an expire date only if you also send an existing private box ID.

    This returns a tuple: (err_nbr, private_id, public_id)

    Keyword arguments:
    private_box_id -- Private box ID.
    host -- host name, such as https://naturalmessage.com, but preferably
        get the host name from the server farm list from a record of
        type='directory'.
    requested_expire_yyyymmdd -- Leave blank for the default, otherwise the
        year and day through which the account is valid.  The server
        will reject the request if the date is too far in the future.
    batch=False.

    Return value:
    tuple: (return_code, Private_Box_ID)

    """
    #
    # Note: The server has an option for "requested_expire_yyyymmdd"
    #
    # For the test period, all new accounts are on naturalmessage.com
    host = 'https://naturalmessage.com'

    if private_box_id is not None:
        rc = verify_id_format(private_box_id, expected_prefix='PRV')
        if rc != 0:
            return((print_err(32400, 'The private box id does not have the '
                   + 'right format: ' + private_box_id), None, None))

        url = host + '/account_create?private_box_id=%s' % (private_box_id)
    else:
        url = host + '/account_create'

    if requested_expire_yyyymmdd is not None:
        if len(requested_expire_yyyymmdd) != 8:
            return((print_err(
                32402,
                'The requested expire yyyymmdd is not 8 bytes long: '
                + requested_expire_yyyymmdd), None, None))

        url = url + '&requested_expire_yyyymmdd=' \
            + str(requested_expire_yyyymmdd)

    r = None
    requests.packages.urllib3.disable_warnings()
    try:
        # The verify=False option helps me to accept the
        # self-signed certificate. The user optionally authenticates
        # the server with the server verification programs.
        r = requests.get(url, headers={'User-Agent': ''}, verify=False)
    except:
        e = repr(sys.exc_info()[0:2])
        # Note: if the server is down, r will be None.
        if r is not None:
            return((print_err(
                32500,
                'No response from server.  Maybe it is down, maybe '
                + 'there is a firewall problem or network problem... ' + e
                + ' -- ' + repr(r.text)), None, None))
        else:
            # Note this error could mean that the the firewall is blocking
            # ('Connection aborted.', OSError(113, 'No route to host'))
            return((print_err(
                32600,
                'No response from server.  Maybe it is down, maybe '
                + 'there is a firewall problem or network '
                + 'problem... ' + e), None, None))

    PUB_ID_UT = None
    PRV_ID_UT = None
    if r is not None:
        if 'account_create' in r.json().keys():
            if 'Error' in r.json()['account_create'].keys():
                print('The server reported an error while '
                      + 'creating the box ID.')
                print(str(r.json()['account_create']['Error']))
                input('Press any key to continue.')
                return((35983, None, None))
            if 'private_box_id' in r.json()['account_create'].keys():
                PUB_ID_UT = r.json()['account_create']['public_box_id']
                PRV_ID_UT = r.json()['account_create']['private_box_id']
            else:
                print('the json from the server did not '
                      + 'contain the expected keys: '
                      + str(r.json()))
        else:
            print('the json from the server did not contain '
                  + 'the expected keys: '
                  + str(r.json()))

    return((0, PRV_ID_UT, PUB_ID_UT))


###############################################################################
def nm_remove_temp_dir(tmp_dir):
    """Remove a temporary directory (name must contain 'tmp' or 'temp').

    This will securely remove files and directories under
    (and including) the specified directory.

    For safety reasons, this will fail if the specified directory
    does not contain either "tmp" or "temp" in the directory name.

    Positional arguments:
    tmp_dir -- the temporary directory to remove.  Must have 'tmp' or
        'temp' in the basename.

    Return value:
    0 on success, else nonzero.
    """
    # CONSIDER REPLACING THIS WITH SHUTIL.RMTREE()
    # CONSIDER REPLACING THIS WITH SHUTIL.RMTREE()
    # CONSIDER REPLACING THIS WITH SHUTIL.RMTREE()
    # CONSIDER REPLACING THIS WITH SHUTIL.RMTREE()
    # CONSIDER REPLACING THIS WITH SHUTIL.RMTREE()
    # CONSIDER REPLACING THIS WITH SHUTIL.RMTREE()
    # CONSIDER REPLACING THIS WITH SHUTIL.RMTREE()
    if os.path.isdir(tmp_dir):
        if tmp_dir.find('tmp') > 0 or tmp_dir.find('temp') > 0:
            for root, dirs, files in os.walk(tmp_dir, topdown=False):
                # The outer loop contains the directory/subdirectory name
                # in 'root' and all the file names listed in the array 'files.'
                for f in files:
                    full_fname = root + os.sep + f
                    debug_msg(5, '  Securely removing file:' + full_fname)

                    nm_secure_remove(full_fname)

            for root, dirs, files in os.walk(tmp_dir, topdown=False):
                if len(dirs) == 0 and len(files) == 0:
                    debug_msg(5, '  removing ' + root)
                    tmp_name = base64.b64encode(
                        RNCryptor.Random.new().read(8)).decode('utf8')
                    # get rid of some symbols
                    tmp_name = \
                        tmp_name.translate(str.maketrans(
                            {'/': 'x', '+': 'Q', '=': 'e'}))
                    # I THINK I NEED TO KEEP THE PATH THAT
                    # LEADS TO ROOT WHNE i RENAME IT
                    newdname = os.path.dirname(root) + os.sep + tmp_name
                    debug_msg(6,
                              '  Renaming ' + root
                              + ' to tmp name ' + newdname)
                    os.renames(root, newdname)
                    os.removedirs(newdname)
        else:
            return(print_err(
                32700,
                'Refusing to kill a temp directory that '
                + 'does not contain tmp or temp in the name: ' + tmp_dir))

    return(0)


###############################################################################
def nm_archiver2(
        action='c',
        arch_fname=None,
        message_included=False,
        f_list=None,
        output_dir=None,
        ballast_included=False,
        batch=False,
        extract_attachments=False,
        skip_existing=True,
        clobber='Prompt'):
    '''A privacy-respecting archive that can (approximately) replace tar.

    nm_archiver2 will read one or more files and put them in
    an archive that mixes JSON with binary storage.  This approach is used
    for the following reasons:
      1) tar archives leak info about user name or number.
      2) JSON is easy and portable
      3) binary storage was needed because the ordinary JSON base64
         inflated the size substantially in a process that used 2 rounds
         of base 64.


    Arguments:
    Action 'c' = create and action 'x' = extract.

    arch_fname: This is the name of the archive file to either read or write.
    If action is c and arch_fname is supplied, the archive will be written
    to disk, otherwise if action is c and arch_fname is not supplied, the
    archive will be return as the third element of the return value.

    f_list: This is a list (Python list object []) of filenames to archive
    when action = 'c'.

    message_included: If message_included is set to True, then the
    first filename in the f_list should be plain text or RTF
    (do NOT use Mac OS RTFD because it is not portable).  The
    Natural Message system expects a message called __NM.txt
    or __NM.rtf as text or RTF respectively (do not use Mac OS X
    RTFD for __NM.rtf).

    ballast_included: If this is set to True during archive creation,
    then the last entry in f_list will be treated as a junk file
    and will not be extracted later. The ballast is filler to mask
    the size of the real contents when the file is sent over a network.

    Options for Extract only:

    1) Extract attachments: if this is set to True then both the main
       'message' and the message attachments are exracted, otherwise
       only the main 'message' is extracted (the message is determined
       internally by the JSON code for isMessage=true).  If this archiver
       is used outside of the Natural Message messaging system, the
       main 'message' can be used as a manifest for the main files inside.
       The main message in the messaging system is expected to have
       the name __NM.txt or __NM.rtf.

    2) If skip_existing is set to True, then existing files are not
       overwritten and no error message is presented.

    3) The options for clobber are True, False, or 'Prompt'.  The
       values for True and false maybe sent as text or booleans.

    This returns a tuple: (errcode, errmsg_or_bytes, arch_json).
    A nonzero errcode indicates an error. If no output directory
    was specifed for an extract, the message is returned as a
    BytesIO object in the second parameter.

    '''

    extracted_files = []
    if clobber is None:
        clobber = 'p'
    elif isinstance(clobber, bool):
        if clobber:
            clobber = 't'
        else:
            clobber = 'f'
    elif isinstance(clobber, str):
        if clobber.lower() in ['p', 'prompt']:
            clobber = 'p'
        elif clobber.lower() in ['y', 'yes']:
            clobber = 't'
        elif clobber.lower() in ['n', 'no']:
            clobber = 'f'
        else:
            return(print_err(
                3270,
                'Unexpected string value for clobber: '
                + str(clobber)))
    else:
        return(print_err(
            3275,
            'Unexpected data type for clobber: '
            + str(type(clobber))))

    # Note: that we do not put any whitespace in the JSON to
    # avoid an accidental fingerprint in the archiver format
    # (e.g., the Python archiver version 7.1.2.3 includes
    # an extra space before the file extension and then
    # the recipient knows that Ken is about the only person
    # still using that version).

    attachment_count = 0

    debug_msg(5, 'Starting nm_archive2.')

    action = action.lower()

    # For creating an archive without writing to disk:
    create_bytesio = False
    f = []
    tot_file_size = 0
    output_block_size = DEFAULT_TARGET_BLOCK_SIZE
    file_idx = 0

    # Check for consistency of input args:
    if action == 'c':
        if f_list is None:
            return((
                33000,
                'Error.  There were no input files to nm_archive.', None))

    elif action == 'x':
        #  Extract an existing archive file:
        if not os.path.isfile(arch_fname):
            return((
                33100,
                'Error. The input archive filename is missing.', None))

    else:
        return((33300, 'Error.  Invalid action code: ' + str(action), None))

    if action == 'c':
        debug_msg(3, 'Creating a new archive')

        attachment_count = len(f_list)  # Not including the main text message.

        file_idx = 0

        # A newly created archive can go to disk or an io.Bytes() object.
        # io.BytesIO() is a memory object that can be treated like a file.
        # We might need this to avoid writing passwords to disk.
        if arch_fname is None:
            create_bytesio = True
            fd_out = io.BytesIO()
        else:
            fd_out = open(arch_fname, "wb")

        # Write the header:
        fd_out.write(bytes(NATMSG_ARCH_HEADER, 'utf-8'))

        i_types = []
        if f_list is not None:
            debug_msg(3, 'Reading files from the file list...')
            for file_idx in range(len(f_list)):
                debug_msg(4, 'Reading ' + f_list[file_idx])

                if file_idx == 0 and message_included:
                    i_types.append('message')
                else:
                    tst_val = len(f_list) - 1
                    if file_idx == tst_val and ballast_included:
                        i_types.append('ballast')
                    else:
                        i_types.append('attachment')

        if create_bytesio:
            my_bytes = fd_out.getvalue()
        else:
            my_bytes = None

        rc = nm_archiver2_attach_files(
            f_list,
            fd_out,
            item_types=i_types)
        if rc != 0:
            return((33381, 'Could not properly archive the file(s).', None))

        if arch_fname is not None:
            # avoid syncing for BytesIO output
            os.fsync(fd_out.fileno())

        fd_out.close()

        debug_msg(3, str(file_idx) + ' files archived.')

    else:
        # ---------------------------------------------------------
        # ---------------------------------------------------------
        # ---------------------------------------------------------
        #                 'x' Extract files.
        msg = None
        data = None
        fname_base = None
        fname_ext = None

        if output_dir is None:
            create_bytesio = True

        debug_msg(3, 'Extracting from archive file: ' + repr(arch_fname))

        # The codecs.open() function supports an option for buffering mode.
        # buffering=1024 means to read 1024 bytes at a time.
        # I might need to read a reasonable block size to
        # avoid hogging all memory
        # or crashing the server.
        fd_in = open(arch_fname, "rb")
        # read the header
        hdr = fd_in.read(len(NATMSG_ARCH_HEADER))

        if hdr.decode('utf-8') != NATMSG_ARCH_HEADER:
            return((
                33400,
                'Bad header on the archive file ' + arch_fname, None))

        # read the length of the JSON
        try:
            jlen = int(fd_in.read(6))
        except:
            e = str(sys.exc_info()[0:2])

            return((
                33500,
                'Could not read the JSON length in the archive file '
                + arch_fname + ': ' + e, None))

        # check the json len
        if jlen < 10:
            return((33600, 'Error.  Invalid JSON length.', None))

        # read the JSON
        try:
            json_array = json.loads(fd_in.read(jlen).decode('utf-8'))
        except:
            e = str(sys.exc_info()[0:2])

            return((
                33700,
                'Bad JSON in the archive file ' + arch_fname + ': '
                + e, None))

        # The initial attachment count probably includes ballast and
        # the main msg that need to be deducted below
        # (after they are confirmed).
        attachment_count = len(json_array)
        for jjj in json_array:
            # Loop through each 'file entry' in the array.
            #
            if 'ballast' in jjj.keys():
                attachment_count -= 1

            if 'ballast' not in jjj.keys() \
                    and ('isMessage' in jjj.keys() or extract_attachments):
                # Do not process ballast records, but dot process
                # isMessage records,
                # and process attachments if the flag says to do so:
                debug_msg(7, 'Examining a file to see if it can be extracted.')

                extract_this_file = False
                fname_out = None
                if 'fileName' in jjj.keys() and 'fileExt' in jjj.keys():
                    a = jjj['fileName']
                    b = jjj['fileExt']
                    flen = int(jjj['size'])

                    if 'isMessage' in jjj.keys() or extract_attachments:
                        extract_this_file = True
                        # Do not count the main message as an attachment,
                        # and we already
                        # initialized counting this record as an attachment,
                        # so undo the calculation.
                        attachment_count -= 1
                    else:
                        if extract_attachments:
                            extract_this_file = True

                else:
                    return((
                        33800,
                        'Could not get filename from JSON. ' + e, None))

                if extract_this_file:
                    if not create_bytesio:
                        fname_out = os.path.join(output_dir, a + '.' + b)
                        extracted_files.append(fname_out)
                        # first check if the output directory exists
                        file_exists = os.path.isfile(fname_out)
                        if file_exists and skip_existing:
                            # Quietly refuse to overwrite an existing file.
                            extract_this_file = False
                        elif file_exists and \
                                os.path.abspath(
                                    os.path.expanduser(fname_out)) == \
                                os.path.abspath(
                                    os.path.expanduser(arch_fname)):
                            # This is intended to avoid overwriting the source
                            # archive file, but the test might not be perfect.
                            debug_msg(
                                3,
                                'Not overwriting existing file: ' + fname_out)
                            extract_this_file = False
                        elif file_exists and clobber == 'f':
                            return((
                                33900,
                                'Error. File exists, and you said no-clobber ('
                                + 'try the skip-existing option to ignore '
                                + 'this error).', None))
                        elif file_exists and clobber == 'p':
                            if nm_confirm(
                                    'Do you want to overwrite this file: '
                                    + fname_out + ': ', batch=batch):
                                extract_this_file = True
                            else:
                                extract_this_file = False

                        # Some tests above might have turned
                        # off 'extract_this_file'.
                        if extract_this_file:
                            out_subdir = os.path.dirname(fname_out)
                            if out_subdir != os.curdir and out_subdir != '':
                                if not os.path.isdir(out_subdir):
                                    # The output subdirectory does not exist,
                                    # so create it.
                                    os.makedirs(
                                        out_subdir,
                                        mode=0o700,
                                        exist_ok=True)
                            try:
                                fd_out = open(fname_out, 'wb')
                            except:
                                return((
                                    34000,
                                    'Error. Failed to open output filename '
                                    + fname_out, None))
                    else:
                        # bytesio output to RAM
                        fd_out = io.BytesIO()

                    # I now have fd_out defined either to a real file or to
                    # a BytesIO() object.  I am ready to extract the file
                    if extract_this_file:
                        # Extract the current file.
                        debug_msg(6, 'Writing now.')
                        try:
                            fd_out.write(fd_in.read(flen))
                        except:
                            e = repr(sys.exc_info()[0:2])
                            return((
                                34100,
                                'Failed to write to output filename '
                                + fname_out + '. ' + e, None))

                        if create_bytesio:
                            my_bytes = fd_out.getvalue()
                        else:
                            fd_out.close()
                            print('Extracted file: ' + fname_out)
                    else:
                        # I am not writing this file, but I need to either seek
                        # to the write spot in the input file or
                        # read junk to nowhere
                        junk = fd_in.read(flen)
                        junk = None
                else:
                    # the JSON did not define an output filename:
                    debug_msg(4, 'No filename in the JSON.')
                    return((
                        34200,
                        'the JSON did not supply an filename for '
                        + 'archived file.', None))

        fd_in.close()

    if create_bytesio:
        # This part typically runs when I extract just the message part,
        # not the attachments, and I do not provide an output_dir:
        return((
            0,
            '',
            {'attachment_count': attachment_count,
             'msg_txt': my_bytes.decode('utf-8'),
             'extracted_files': extracted_files}))

    else:
        return((
            0,
            '',
            {'attachment_count': attachment_count,
             'extracted_files': extracted_files}))


###############################################################################
def nm_archiver_json(fname_list, item_types, version=2):
    """Prepare JSON data that goes to the NM archiver.

    Given a list of file names and associated item_types,
    this will prepare the strings in JSON format
    that go into the archive version 2 file before
    the binary attachments.

    This returns a tuple (err_nbr, json_str, size of the specified file).
    Positional arguments:
    fname_list -- A list object with file names to archive.
    item_types -- One of message, attachment, ballast.  Chris's archiver
        uses ballast to mask the size of the message.

    Keyword arguments:
    version -- The current version number. VERIFY THAT CHRIS IS USING
        THIS AND THAT IT IS SET TO 2.

    Return value:
    0 on success, else nonzero.
    """
    jarray = ['[']

    for j in range(len(fname_list)):
        # fname_input is the input file name, possibly with path.
        # fname_clean is just the simple file name without the extension
        # fname_ext is just the file extension without the dot
        fname_tmp, fname_ext = os.path.splitext(fname_list[j])
        fname_clean = os.path.basename(fname_tmp)
        fsize = 0

        if item_types[j] not in ['message', 'attachment', 'ballast', '']:
            return(print_err(34300, 'Bad item type sent to nm_archiver_json: '
                             + item_types[j]
                             + ' for file: ' + fname_clean))

        if j > 0:
            # Add a comma between elements in the JSON array
            jarray.append(',')

        # Remove leading dot from file ext
        if len(fname_ext) > 0:
            fname_ext = fname_ext[1:]

        if not os.path.isfile(fname_list[j]):
            return((print_err(
                34450,
                'The requested file to archive is not a file: '
                + fname_list[j]), None, None))

        fsize += os.stat(fname_list[j]).st_size

        # To match Chris's version, I will convert item_type to a flag only
        # for item_type='message'
        if item_types[j] == 'message':
            # Chris uses lower case 'true' in Mac OS X. JSON understands
            # only lower case 'true' as a boolean (with no quotes around it).
            jflags = ',"isMessage":true'
        else:
            jflags = ''

        # ## To Do: Chris needs to add base64 to filenames to
        # ## prevent JSON errors
        # # json_str = '{"fileName":"' \
        # #     + base64.b64encode(
        # #         bytes(fname_clean, 'utf-8')).decode('utf8') + '",'
        # #     + '"fileExt":"'
        # #     + base64.b64encode(
        # #         bytes(fname_ext, 'utf-8')).decode('utf8') + '",'
        # #     + '"size":' + str(fsize) + jflags + '}'
        json_str = '{"fileName":"' \
            + fname_clean + '",' \
            + '"fileExt":"' \
            + fname_ext + '",' \
            + '"size":' + str(fsize) + jflags + '}'

        jarray.append(json_str)

    # End the JSON array and include ballast:
    # The ballast is added to ensure that the main file is big enough
    # to fill the fixed-sized preamble shards (127 bytes each) so that
    # tiny files are spread across more 'shard caretakers'.  It is difficult
    # to estimate the final, zipped size without first encrypting it, so
    # this techniqe might change in the future.
    #
    # bob made the ballast lower case to make the bzip table more
    # complex (to find some duplicates and thereby encode the
    # data rather than leaving uncompressible data in its original form.)
    ballast_data = base64.b16encode(
        RNCryptor.Random.new().read(250)).decode('utf8').lower()

    jarray.append(',{"ballast":"' + ballast_data + '"}]')

    return((0, ''.join(jarray), fsize))


###############################################################################
def nm_archiver2_attach_files(
        fname_list,
        fd_out,
        item_types):
    """Attach files to an NM archive file.

    Attach one or more files, named in fname_list, to the archive
    file handle described by fd_out.  You must have fd_out
    open for binary writing before calling this. The caller
    should close fd_out when done.

    item_types is an array that has the value 'message' (for the body of
    the email or the manifest for a regular archive) or 'attachment'
    for a file attachment or 'ballast' for random filler data to mask
    the file size.

    In theory, this step can be repeated, but for the Natural Message
    system, we will send all the files in one json block.

    Positional arguments:
    fname_list -- A list of file names to archive.
    fd_out -- A file handle to output the archive file.
    item_types -- One of message, attachment, ballast.  Chris's archiver
        uses ballast to mask the size of the message.

    Return value:
    0 on success, else nonzero.
    """
    if len(fname_list) != len(item_types):
        return(print_err(
            34500,
            'The length if fname_list is not equal to '
            + 'the length of item_types in nm_archiver2_attach_file'))

    # verify item types
    for j in range(len(fname_list)):
        if item_types[j] not in ['message', 'attachment', 'ballast', '']:
            return(print_err(
                34600,
                'Bad item type sent to nm_archiver2_attach_file: '
                + item_types[j]
                + ' for file: ' + fname_list[j]))

    # Get the JSON that describes all the attachments.
    err_nbr, json_str, tot_file_size = nm_archiver_json(fname_list, item_types)
    if err_nbr != 0:
        return(print_err(
            34700,
            'In nm_archiver2_attach_file, could not get '
            + 'basic info about file: ' + str(fname_list)))

    json_bytes = bytes(json_str, 'utf-8')

    # The length of the JSON is expessed as 6 ASCII integer characters
    # with leading zeroes.
    # #fd_out.write(struct.pack('<L', len(json_bytes)))
    if len(json_bytes) > 999999:
        return(print_err(
            34700,
            'In nm_archiver2_attach_file, the JSON is too long.'))

    fd_out.write(bytes("%06d" % len(json_bytes), 'utf-8'))
    # Now write the actual JSON
    fd_out.write(json_bytes)

    # attach all files to the output archive file.
    for j in range(len(fname_list)):
        try:
            fd_in = open(fname_list[j], "rb")
        except:
            return(print_err(
                34800,
                'Could not open the input message file: '
                + fname_list[j]))

        try:
            # Attach the binary files to the archive file:
            fd_out.write(fd_in.read())
        except:
            # I lumped several actions into one error trap--review this later.
            return(print_err(
                34900,
                'Error. Could not open the output files for writing'))

        fd_in.close()

    return(0)


###############################################################################
def nm_fetch_server_farm():
    """Fetch the server farm list (list of shard servers in JSON format).

    This will fetch a list of shard servers and directory servers
    from naturalmessage.com (using DNS) and return a tuple with
    (err_nbr, server_farm_dictionary_object).

    This will eventually be updated to grab data from several
    Internet and local sources.
    """
    global MAIN_CONFIG

    MAIL_DIR = None
    sfarm_fname = None
    try:
        MAIL_DIR = MAIN_CONFIG['SETTINGS']['mail_dir']
        sfarm_fname = MAIL_DIR + os.sep + 'settings' \
            + os.sep + 'serverFarm.json'
    except:
        e = repr(sys.exc_info()[0:2])
        debug_msg(
            1,
            'There was no sfarm_fname available. You might need '
            + 'to run natmsgclib.start().  ' + e)
        pass

    #  TEMPORARILY HARD-CODED
    url = 'https://naturalmessage.com/json/serverFarm.json'
    r = None
    requests.packages.urllib3.disable_warnings()
    try:
        # The verify=True option means that I am relying on
        # regular SSL/TLS and the server's certificate.
        r = requests.get(
            url,
            headers={'User-Agent': ''},
            verify=False)  # Not verifying !!!!!!!!!!!!!!!!!!!!!!!
    except:
        e = repr(sys.exc_info()[0:2])
        # Note: if the server is down, r will be None.
        # Note this error could mean that the the firewall is blocking
        # ('Connection aborted.', OSError(113, 'No route to host'))
        return((print_err(
            35000,
            'Failed to fetch server farm list. ' + e), None))

    if r is not None:
        try:
            server_dict = json.loads(r.text)
        except:
            e = repr(sys.exc_info()[0:2])
            return((print_err(
                35100,
                'Failed to convert serverFarm list to a dictionary. '
                + e), None))

        # I now have the server farm list in a Python dictionary object.
        # I will save a copy to disk and archive any existing file.
        if sfarm_fname is not None:
            roll_gdg(sfarm_fname)
            with open(sfarm_fname, 'w') as fd:
                fd.write(json.dumps(server_dict, indent=2))
                os.fsync(fd.fileno())

        else:
            debug_msg(
                3,
                'There was no sfarm_fname available, so there will '
                + 'be no disk copy of the current server farm list.')

        return((0, server_dict))
    else:
        e = repr(sys.exc_info()[0:2])
        return((print_err(
            35200,
            'Failed get a valid response from the server farm.'
            + e)))


def nm_fetch_directory_server_list(IPV4=False):
    """IS THIS USED --- THIS IS PART OF SERVER FARM LIST.

    This will return an array of addresses for directory servers
    or None if there is an error.

    This should also save a copy to disk along with backups.
    """
    server_list = []

    err_nbr, sfarm = nm_fetch_server_farm()

    conf = sfarm['serverConfiguration']
    try:
        for d in conf:
            if d['server_type'].lower() == 'directory':
                if IPV4:
                    server_list.append(d['IPV4'] + os.sep + str(d['port_nbr']))
                else:
                    server_list.append(
                        d['address'] + os.sep + str(d['port_nbr']))
    except:
        return(None)

    return(server_list)


###############################################################################
def nm_confirm(prompt='Do you want continue? (y/n): ', batch=False):
    """Asks if the user wants to continue.  Returns True if yes.

    If batch is set to True, this does not prompt the user and
    simply returns True.
    """

    if batch:
        return(True)

    good = False
    while not good:
        answ = input(prompt)

        if answ.lower() == 'y' or answ.lower() == 'yes':
            return(True)
        elif answ.lower() == 'n' or answ.lower() == 'no':
            return(False)
        else:
            answ = None  # Force another loop.

        if answ is not None:
            print('Enter y or n.')

    return(False)


###############################################################################
def input_and_confirm(prompt, int_answer=False, default_value=None):
    """Prompt user to enter data, then have user confirm it.

    This will present the specified prompt and wait for the
    user to enter a value.

    If int_answer is set to True, the answer must be
    an integer.

    This returns the entered value, which might be a str()
    or an int().  If no value was entered, this returns
    None.

    Positional arguments:
    prompt -- The text that is displayed to prompt the user.

    Keyword arguments:
    int_answer -- If True, the user should enter an integer.
    default_value -- The default value to use if the user does not enter
        anything.

    Return value:
    0 on success, else nonzero.
    """

    good = False
    while not good:
        # #    answ = input(prompt)
        # #
        # #    if answ == '':
        # #        conf = input('Do you want quit? (y/n): ')
        # #        if conf.lower() == 'y' or conf.lower() == 'yes':
        # #            return(None)
        # #        else:
        # #            answ = None # force another loop
        # #
        # #    if int_answer and answ is not None:
        # #        int_val = None
        # #        try:
        # #            int_val = int(answ)
        # #        except:
        # #            # Wrong input format, try again
        # #            print('Enter a numeric value.  Try again.')
        # #            answ = None # force another loop
        # #
        # #        if int_val is not None:
        # #            answ = int_val
        answ = input_no_confirm(
            prompt,
            int_answer=int_answer,
            default_value=default_value)

        if answ is not None:
            print('Your entered: ' + str(answ))

            conf = input('Do you want to keep this answer? (y/n): ')
            if conf.lower() == 'y' or conf.lower() == 'yes':
                good = True

    return(answ)


###############################################################################
def input_no_confirm(prompt, int_answer=False, default_value=None):
    """Prompt user to enter data, then accept it without confirmation.

    This will present the specified prompt and wait for the
    user to enter a value.  If int_answer is set to True, the answer must be
    an integer.

    This returns the entered value, which might be a str()
    or an int().  If no value was entered, this returns
    either the default value or None (if not default was supplied).

    Positional arguments:
    prompt -- The text that is displayed to prompt the user.

    Keyword arguments:
    int_answer -- If True, the user should enter an integer.
    default_value -- The default value to use if the user does not enter
        anything.

    Return value:
    0 on success, else nonzero.

    """
    good = False
    while not good:
        if default_value is not None:
            answ = input(prompt + ' [' + str(default_value) + ']: ')
        else:
            answ = input(prompt)

        if answ.lower() in ['q', 'quit']:
            conf = input('Do you want quit? (y/n): ')
            if conf.lower() == 'y' or conf.lower() == 'yes':
                # quit
                return(None)
            else:
                conf = input('Do you want to specify that your answer is '
                             + 'the text (in angle brackets): <'
                             + answ + '>? (y/n): ')
                if conf.lower() == 'y' or conf.lower() == 'yes':
                    return(answ)
                else:
                    print('Hey bro, make up your mind.  Try again')
                    continue

        if answ == '':
            # This might return an integer or string depending
            # on the default, so caller beware.
            return(default_value)

        if answ is not None:
            if int_answer and answ is not None:
                int_val = None
                try:
                    int_val = int(answ)
                except:
                    # Wrong input format, try again
                    print('Enter a numeric value.  Try again.')
                    answ = None  # Force another loop.

                if int_val is not None:
                    answ = int_val
                    good = True
            else:
                good = True  # String entry

    return(answ)


###############################################################################
def nm_display_menu_section(
        lst,
        start_idx,
        title='',
        add_numbers=True):
    """Display a text file as a menu (this adds numbers to each line).

    This will display some rows of text from the list.
    This uses basic text output, so I do not know the width of the screen
    or if the lines will take more than one screen line.

    This is called by nm_menu_choice() and should probably not be called
    otherwise.  Maybe move this to be a privat function or part of a menu
    class.

    Positional arguments:
    lst -- a list containg lines of text to display in a menu (this will add
        numbers to the menu items).
    start_idx -- start displaying the subset of lines of text using this
        index.

    Keyword arguments:
    title -- Title to use for the menu.
    add_numbers -- Add numbers to each line of text to represent the numbers
        that are entered to select the menu item.

    Return value:
    0 on success, else nonzero.
    """
    global MAIN_CONFIG
    print('\n\n\n')
    print(title)
    items_per_page = int(MAIN_CONFIG['SETTINGS']['screen_height']) - 3
    last_displayed_idx = start_idx - 1
    target_final_idx = start_idx + items_per_page - 1
    idx = 0

    for l in lst:
        if idx >= start_idx and idx <= target_final_idx:
            if add_numbers:
                print("%2d)ZZ %s" % (idx + 1, l))
            else:
                print(l)

            last_displayed_idx = idx

        idx += 1

    if last_displayed_idx < len(lst) - 1:
        print('Enter a number (ENTER=next pg; P=prior pg; Q=quit)')

    return(0)


###############################################################################
def nm_menu_choice(lst, prompt=': ', title='', trim_width=True):
    """Display text from a list object as an interactive menu.

    Given a list of text strings, add numbers to them
    and display them as a menu.  Get input from the user.

    This returns a tuple with the selected (zero-based) index and
    the text of the item that was selected. On error (or on quit)
    the index number will be less than zero.

    Without curses, I do not know the screen height,
    and curses license does not work under Windows
    from what I recall from a few years ago when
    I read the curses license (Bob, Feb 2015).

    This returns a tuple: (return_code, selected_item_text).
    A negative return code indicates an error, otherwise the
    return code is the index number (zero-based) of the
    selected item.


    Positional arguments:
    lst -- The list of text to form the menu.

    Keyword arguments:
    prompt -- The text used to prompt the user to enter something.
    title -- The title for the menu.
    trim_width -- cut the width of the text to fit the width of the screen
        as recorded in the config file.

    Return value:
    0 on success, else nonzero.

    """
    global MAIN_CONFIG

    if trim_width:
        display_width = int(MAIN_CONFIG['SETTINGS']['screen_width'])
    else:
        display_width = 100000

    display_height = int(MAIN_CONFIG['SETTINGS']['screen_height'])

    idx = 0
    # this controls page up/down movements, not the actual display.
    items_per_page = display_height - 2

    # The user might have sent embedded EOL in each line, so
    # create a new array object that puts each text line
    # as its own array entry (possibly expanding one input
    # text line into many).
    menu_entry_idx = 0
    menu_txt_clean = []
    for t in lst:
        # attempt to account for different EOL types
        # and split each line into an array item.
        tmp = t.replace('\r', '\n').replace('\n\n', '\n').split('\n')
        item_idx = 0
        for x in tmp:
            if item_idx == 0:
                menu_txt_clean.append(
                    str(menu_entry_idx + 1) + ') '
                    + x[0:display_width])
            else:
                menu_txt_clean.append(x[0:display_width])

            item_idx += 1

        menu_entry_idx += 1

    # ---------------------------------------------------------------------
    # Display height is determined by global settings as
    # intepreted by nm_display_menu_selection.
    nm_display_menu_section(
        menu_txt_clean,
        idx,
        title=title,
        add_numbers=False)

    good = False
    while not good:
        int_choice = None
        try:
            choice = input(prompt)
        except:
            pass

        if choice.lower() == 'q':
            return((-1, None))  # -1 means no choice
        elif choice.lower() == 'p':
            # Show prior page.
            idx -= items_per_page
            if idx < 0:
                idx = 0

            nm_display_menu_section(
                menu_txt_clean,
                idx,
                title=title,
                add_numbers=False)
        elif choice.lower() == 'n':
            # Show prior page.
            idx += items_per_page
            max_idx = len(menu_txt_clean) - items_per_page
            if idx > max_idx:
                idx = max_idx

            if idx < 0:
                idx = 0

            nm_display_menu_section(
                menu_txt_clean,
                idx,
                title=title,
                add_numbers=False)
        elif choice == '':
            # Show next screen.
            idx += items_per_page
            highest_start_idx = len(lst) - items_per_page
            if idx >= highest_start_idx:
                idx = highest_start_idx
            # highest idx can be negative, so fix it:
            if idx < 0:
                idx = 0

            nm_display_menu_section(
                menu_txt_clean,
                idx,
                title=title,
                add_numbers=False)

        else:
            try:
                int_choice = int(choice)
            except:
                print('Enter an INTEGER (or Q to quit): ', end='')

            if int_choice is not None:
                if int_choice > len(lst) or int_choice < 1:
                    print('Enter an integer FROM THE LIST '
                          + '(or Q to quit): ', end='')
                else:
                    good = True

    return((int_choice - 1, lst[int_choice - 1]))


###############################################################################
def nm_input_list_and_confirm(
        prompts,
        blanks_keep_default=False,
        trim_width=False):
    """Display a menu for multiple entry fields. User confirms entry.

    Given an array that contains one or more tuples
    (text prompt, is_integer, default), prompt user to
    enter values for each entry, then show the list
    and allow the user to select numbers to re-enter things.

    This returns a tuple: (err_nbr, answers_array)

    If trim_width is true, a displayed prompt is trimmed to the
    current setting for screen_width.

    Positional arguments:
    prompts -- A list of prompts, each of which is a request to enter a
        value.

    Keyword arguments:
    blanks_keep_default

    Return value:
    0 on success, else nonzero.
    """

    answers = []
    quit_now = False
    for t in prompts:
        # For each item in prompts, get input from the user
        # and append the answer to 'answers'.
        if len(t) != 3:
            return((print_err(
                36000,
                'Each array entry sent to nm_input_list_and_confirm '
                + 'should be a tuple with (a) the prompt text, (b) '
                + 'a boolean to indicate if the entry must be '
                + 'integer (True = integer required) '
                + 'and (c) a default value.'), None))
        tmp_answer = input_no_confirm(
            prompt=t[0],
            int_answer=t[1],
            default_value=t[2])
        if tmp_answer is None:
            # user wants to quit
            quit_now = True
            break
        else:
            answers.append(tmp_answer.strip())

    # Reformat the answers to show the original prompt plus the
    # answer that was entered... so the user can verify the input:
    if quit_now:
        # fill the array with None to indicate a normal Quit request:
        answers = []
        for x in range(len(prompts)):
            answers.append(None)
    else:
        # A regular results
        prompts_with_answers = [''] * len(prompts)
        for j in range(len(prompts)):
            prompts_with_answers[j] = prompts[j][0] + ': ' + str(answers[j])

        good = False
        while good is False:
            choice, val = nm_menu_choice(
                prompts_with_answers,
                prompt='Enter a number to modify an entry, '
                + 'or press Q to finish: ',
                trim_width=trim_width)

            if choice < 0:
                good = True
            else:
                answers[choice] = input_no_confirm(
                    prompts[choice][0]
                    + ': ',
                    prompts[choice][1])
                prompts_with_answers[choice] = prompts[choice][0] \
                    + ': ' + str(answers[choice])

    return((0, answers))


###############################################################################
def nm_encrypt_local_txt(txt_bytes, pw_bytes):
    """Encrypt text with the given password.

    Use a modified version of RNCryptor to encrypt or decrypt
    things without using the PBKDF2 key derivation step.  This also
    derives and returns the base64 version of the encrypted
    value as utf-8.

    Use this only for things that are kept locally, because if you
    send a file to somebody and give the person the password,
    that password will not work unless they also use a
    hacked version of RNCryptor.  This is used so that
    when I encrypt and decrypt individual settings on the
    fly, I do not have to wait for the key derivation step.

    I run something like this one time to prepare
    the password that is used many times:
        SHARD_PW_BYTES = pw_hash2()
        if SHARD_PW_BYTES is None:
          print('The s

    The pbkdf2_nm.py is part of the Natural Message system.

    The returns the encrypted text as a Python bytes()
    object or None (if there is a problem).

    Positional arguments:
    txt_bytes = A bytes objects, typically ASCII or unicode in Python bytes
        format.
    pw_bytes -- A password in Python bytes format.

    Return value:
    0 on success, else nonzero.

    """
    cryptorz = RNCrypt_zero()
    if not isinstance(pw_bytes, bytes):
        pw_bytes = bytes(pw_bytes, 'utf-8')

    if not isinstance(txt_bytes, bytes):
        txt_bytes = bytes(txt_bytes, 'utf-8')

    try:
        enc_txt = cryptorz.encrypt(txt_bytes, pw_bytes)
    except:
        e = str(sys.exc_info()[0:2])
        print_err(36100, 'Failed to encrypt local text.')
        return(None)

    return(base64.b64encode(enc_txt).decode('utf-8'))


###############################################################################
def nm_decrypt_local_txt(txt_bytes, pw_bytes):
    """Decrypt text that was encrypted with nm_encrypt_local_txt.

    Use a modified version of RNCryptor to encrypt or decrypt
    things without using the key derivation step.  This also
    derives and returns the base64 version of the encrypted
    value as utf-8.

    Use this only for things that are kept locally, because if you
    send a file to somebody and give the person the password,
    that password will not work unless they also use a
    hacked version of RNCryptor.  This is used so that
    when I encrypt and decrypt individual settings on the
    fly, I do not have to wait for the key derivation step.

    I run something like this one time to prepare
    the password that is used many times:
        SHARD_PW_BYTES = pw_hash2()
        if SHARD_PW_BYTES is None:
          print('The s

    The pbkdf2_nm.py is part of the Natural Message system.

    The returns the encrypted text as a Python bytes()
    objec or None (if there is a problem).

    Positional arguments:
    txt_bytes -- The message to decrypt in Python bytes format.
    pw_bytes -- The password in Python bytes format.

    Return value:
    0 on success, else nonzero.
    """

    cryptorz = RNCrypt_zero()
    if not isinstance(pw_bytes, bytes):
        pw_bytes = bytes(pw_bytes, 'utf-8')

    if not isinstance(txt_bytes, bytes):
        txt_bytes = bytes(txt_bytes, 'utf-8')

    unb64 = base64.b64decode(txt_bytes)
    try:
        decrypted_txt = cryptorz.decrypt(unb64, pw_bytes)
    except:
        e = str(sys.exc_info()[0:2])
        print_err(36200, 'Failed to decrypt local text. ' + e)
        return(None)

    # return as str
    return(decrypted_txt.decode('utf-8'))


###############################################################################
def nm_set_pgm_opt(opt_key, pgm_list, prompt1, prompt2):
    """Set a NatMsg option that points to a program name.

    If the user sets the opt_key to unrtf, and supplies several
    programs that can remove RTF markup (e.g., 'unrtf'), this function
    will check the usual paths to find the unrtf program and assign it
    to the option key if the exact path of the program is found.

    example:
    rc = nm_set_pgm_opt('rtf_reader_pgm',
                pgm_list=['libreoffice', 'openoffice', 'abiword', 'catdoc'],
                prompt1='The RTF viewer program is not installed or is '
                    + 'not in the expected location.  It is not essential '
                    + 'to have an RTF viewer if you have the unrtf '
                    + 'program (or textutil on Mac) '
                    + 'installed. ' + os.linesep
                    + 'On UNIX-like systems, you can search for the '
                    + 'exact path of a program by running something like:'
                    + os.linesep + '  whereis libreoffice' + os.linesep
                    + 'then take the first path in the result listing.',
                prompt2='Do you want to manually enter a path to point '
                    + 'to the RTF viewer program (such as MS Word, '
                    + 'OpenOffice...)? (y/n): ')


    Positional arguments:
    opt_key -- The key for an option.
    pgm_list --  A list of program names (just the base name) that
        would perform the function desribe by opt_key.  For example,
        the unrtf key points to a program that can remove RTF markup
        to display on a text screen.
    prompt1 -- the first prompt for entry.
    prompt2 -- the prompt for manual entry of the program name and path.

    Return value:
    0 on success, else nonzero.

    """
    global MAIN_CONFIG

    pgm_encrypted = None
    options_changed = False

    if opt_key not in MAIN_CONFIG['SETTINGS'].keys():
        options_changed = True
        MAIN_CONFIG['SETTINGS'][opt_key] = ''

    pgm_encrypted = MAIN_CONFIG['SETTINGS'][opt_key]

    debug_msg(
        6,
        'The existing, encrypted pgm path is: '
        + str(pgm_encrypted) + ' for key ' + opt_key)

    if pgm_encrypted != '':
        # The configuration option was not blank, so try
        # to decrypt it.
        pgm = None

        try:
            pgm = nm_decrypt_local_txt(pgm_encrypted, SESSION_PW)
        except:
            pass

        if pgm is None:
            options_changed = True
            # remove a bad option
            MAIN_CONFIG['SETTINGS'][opt_key] = ''
        else:
            if not os.path.isfile(pgm):
                options_changed = True
                # Remove a bad option--an existing option that does
                # not point to a real file.
                MAIN_CONFIG['SETTINGS'][opt_key] = ''

    if MAIN_CONFIG['SETTINGS'][opt_key] == '':
        # There is not a valid entry for unrtf, so make one
        paths = []
        for ppp in pgm_list:
            paths.append(os.path.join(os.path.sep, 'usr', 'bin', ppp))
            paths.append(
                os.path.join(os.path.sep, 'usr', 'local', 'bin', ppp))

        for p in paths:
            if os.path.isfile(p):
                # A program in the list is a real file, so use it.
                options_changed = True
                print('I found the program in ' + p)
                time.sleep(1)

                the_pgm = None
                try:
                    the_pgm = nm_encrypt_local_txt(p, SESSION_PW)
                except:
                    pass

                if the_pgm is not None:
                    # The setting for pgm is encrypted.
                    MAIN_CONFIG['SETTINGS'][opt_key] = the_pgm
                    break

        if MAIN_CONFIG['SETTINGS'][opt_key] == '':
            # The fixes above did not result in a valid config entry.
            # Prompt the user to enter the path to the program:
            print(prompt1)
            if nm_confirm(prompt2):
                path = input('Enter the full path to the program: ')
                try:
                    path = os.path.abspath(os.path.expanduser(path))
                except:
                    e = str(sys.exc_info()[0:2])
                    print_err(
                        37553,
                        'Could resolve the entry to a file name. ' + e)

                if os.path.isfile(path):
                    # The thing that was entered is a real file name
                    # (presumably a program)
                    options_changed = True
                    the_pgm = None
                    try:
                        the_pgm = nm_encrypt_local_txt(path, SESSION_PW)
                    except:
                        pass

                    if the_pgm is not None:
                        # The setting for pgm is encrypted.
                        MAIN_CONFIG['SETTINGS'][opt_key] = the_pgm
                else:
                    print('That is not a file: ' + path + '.  Try again.')

    if options_changed:
        # The options changed, so save to disk.
        rc = nm_write_config()
        if rc != 0:
            print('There was an error writing the changes to disk.')
            input('Press any key to continue...')

    return(0)


###############################################################################
def nm_set_rtf_reader_pgm():
    """Prompt user to select an RTF viewer.  Save the setting."""
    rc = nm_set_pgm_opt(
        'rtf_reader_pgm',
        pgm_list=['libreoffice', 'openoffice', 'abiword', 'catdoc'],
        prompt1='The RTF viewer program is not installed or is '
                + 'not in the expected location.  It is not essential '
                + 'to have an RTF viewer if you have the unrtf '
                + 'program (or textutil on Mac) '
                + 'installed. ' + os.linesep
                + 'On UNIX-like systems, you can search for the '
                + 'exact path of a program by running something like:'
                + os.linesep + '  whereis libreoffice' + os.linesep
                + 'then take the first path in the result listing.',
        prompt2='Do you want to manually enter a path to point '
                + 'to the RTF viewer program (such as MS Word, '
                + 'OpenOffice...)? (y/n): ')
    return(rc)


def nm_set_unrtf_pgm():
    rc = nm_set_pgm_opt(
        'unrtf_pgm',
        ['unrtf'],
        prompt1='The unrtf program is '
        + 'not installed or is not in the expected location.',
        prompt2='Do you want to manually enter '
        + 'a path to point to the unrtf program? (y/n): ')
    return(rc)


###############################################################################
def nm_find_default_config_fname():
    """Find the default location for the config file (OS dependent).

    This will look in two places for an existing configuration file,
    but if one is not found, it will test if the system can write
    to a UNIX-style filename, otherwise it will test Windows-style
    file name.

    This returns a tuple: (need_new_config_file, config_fname).
    If all attempts to find or create a valid config file name,
    the value of config_fname will be None.
    """

    unix_config_fname = os.path.expanduser(os.path.join('~', '.natmsgsc'))
    other_config_fname = os.path.expanduser(os.path.join('~', 'natmsgsc.ini'))
    config_fname = None
    need_new_config_file = False

    # Look in two places for an existing config file:
    fd = None
    if os.path.isfile(unix_config_fname):
        debug_msg(
            4,
            'Found a config file: ' + unix_config_fname)
        if (os.stat(unix_config_fname).st_size == 0):
            need_new_config_file = True
            debug_msg(
                4,
                'Config file is zero bytes: ' + unix_config_fname)
        else:
            config_fname = unix_config_fname
    else:
        # the unix-style file does not exist, try this one:
        if os.path.isfile(other_config_fname):
            debug_msg(
                4,
                'Found a config file: ' + other_config_fname)
            if (os.stat(other_config_fname).st_size == 0):
                debug_msg(
                    4,
                    'Config file is zero bytes: '
                    + other_config_fname)
                need_new_config_file = True
            else:
                config_fname = other_config_fname
        else:
            need_new_config_file = True

    if need_new_config_file:
        debug_msg(
            4,
            'Need to config file in nm_find_default_config_fname')
        config_fname = None
        fd = None
        if platform.system().lower() == 'windows':
            debug_msg(5, 'platform is windows')
            # Windows 8 can save a file that starts with a dot, but
            # it is not Windows-traditional and the file extension shows
            # unintended information in Windows Explorer.
            try:
                fd = open(other_config_fname, 'w')
                config_fname = other_config_fname
                debug_msg(2, 'saving config file to: ' + config_fname)
            except:
                e = repr(sys.exc_info()[0:2])
                print_err(
                    36300,
                    'Can not create the config file at '
                    + other_config_fname + ': ' + e)
            else:
                fd.close
        else:
            # non-Windows
            debug_msg(5, 'Platform is NOT windows')
            try:
                fd = open(unix_config_fname, 'w')
                config_fname = unix_config_fname
                debug_msg(2, 'Saving config file to: ' + config_fname)
            except:
                try:
                    fd = open(other_config_fname, 'r')
                    config_fname = other_config_fname
                    debug_msg(2, 'Saving config file to: ' + config_fname)
                except:
                    e = repr(sys.exc_info()[0:2])
                    print_err(
                        36400,
                        'Can not create the config file at '
                        + 'either location, including  '
                        + other_config_fname + ': ' + e)
                else:
                    fd.close
            else:
                fd.close()

    if config_fname is None:
        debug_msg(
            2,
            '=== config_fname is None at the end of '
            + 'nm_find_default_config_fname().')
    else:
        debug_msg(
            4,
            '=== returning from nm_find_default_config_fname(): '
            + config_fname)
    return((need_new_config_file, config_fname))


###############################################################################
def nm_create_config_file(homedir):
    """Create and initialize the NatMsg config file.

    This will create a Natural Message configuration file with some
    default settings and additional information entered by the user.

    Nothing in these files is ever sent to a server, and most of the
    values are encrypted using the Natural Message login password
    (SESSION_PW; which must be processed with pbkdf2_nm.py).

    Positional argument:
    homedir -- The path home directory.

    This returns a tuple: (err_nbr, config_fname).
    """

    global SESSION_PW
    global MAIN_CONFIG
    global CONIFG_FNAME

    debug_msg(
        1,
        'Can not find a configuration file.  Creating a new one now.')

    # This will set the global value for CONFIG_FNAME
    # if it is not set
    need_new_config_file, CONFIG_FNAME = nm_find_default_config_fname()

    if CONFIG_FNAME is None:
        # Strange error in trying to determing config file name.
        # Maybe it is due to a permissions problem??
        return((print_err(
            36500,
            'Could not resolve config file name.'),
            None))

    if CONFIG_FNAME == '':
        # should not execute unless programmer error.
        return((print_err(
            36600,
            'Could not resolve config file name (blank).'),
            None))

    MAIL_DIR = os.path.expanduser('~' + os.sep + 'nm_mail')
    RECEIPT_FILE = MAIL_DIR + os.sep + 'settings' + os.sep \
        + 'pbkdf2_receipt.save'

    # ####################################################################
    # ### move the creation of directories to a new directory that can
    # ### be called from receipt-save func.
    # Create the mail directory if it does not exist
    if not os.path.isdir(MAIL_DIR):
        try:
            os.makedirs(MAIL_DIR, mode=0o700)
            if platform.system().lower() != 'windows':

                debug_msg(
                    2,
                    '==== fixing owner for ' + MAIL_DIR)
                shutil.chown(
                    MAIL_DIR,
                    user=pwd.getpwnam(os.getlogin()).pw_uid,
                    group=pwd.getpwnam(os.getlogin()).pw_gid)

        except:
            e = str(sys.exc_info()[0:2])
            return((
                print_err(
                    36700,
                    'Can not create the mail directory: '
                    + MAIL_DIR + '.  ' + e),
                None))

    os.makedirs(MAIL_DIR + os.sep + 'settings', mode=0o700, exist_ok=True)
    if platform.system().lower() != 'windows':
        shutil.chown(
            MAIL_DIR + os.sep + 'settings',
            user=pwd.getpwnam(os.getlogin()).pw_uid,
            group=pwd.getpwnam(os.getlogin()).pw_gid)

    # ####################################################################
    #
    if SESSION_PW == '':
        # The pw_hash2() function normally looks for the name of the
        # receipt file in the config file, but the config file does
        # not exist.  Passing the suggested filename will help pw_hash2()
        # create the new receipt in the right place.
        #
        # Get the password from the user if it is not already available.
        # This will be used to encrypt the individual config entries.
        SESSION_PW = pw_hash2(receipt_fname=RECEIPT_FILE)
    #
    # catch programmer error:
    if SESSION_PW is None:
        return((print_err(
            36800,
            'Session password in nm_create_config_file '
            + 'is None.'), None))

    if SESSION_PW == '':
        return((print_err(
            36900,
            'Session password in nm_create_config_file '
            + 'is blank.'), None))
    #
    MAIN_CONFIG = configparser.ConfigParser()

    # Some default settings:
    # Note, and option for an executable program needs to be encrypted
    # (e.g., text editor, unrtf, and rtf viewer)
    MAIN_CONFIG['SETTINGS'] = {
        'update_interval': '5',
        'mail_dir': MAIL_DIR,
        'download_directory': os.path.expanduser('~/Downloads'),
        'verbosity': 2,
        'current_identity': 'Identity1',
        'screen_height': 20,
        'screen_width': 80,
        'max_msg_browse': 2000,
        'PBKDF2_receipt_file': RECEIPT_FILE,
        'unrtf_pgm': '',
        'rtf_reader_pgm': '',
        'listing_format': 'long',
        'allow_clear_screen': True,
        'archive_version': '1'}

    # ######################################################################
    print('Creating the default identity and box ID.  Please wait...')

    # To Do: allow the user to select the server from either the serverFarm
    # list of directory servers or from user input.  Then pass that server
    # to nm_account_create as the 'host.'

    # To Do: get the signature of the server, then save the online key,
    # offline pub key, and signed online key in the mail/keys directory.
    # Verify the expiration date of the keys each session. Save the
    # expiration date of the online key in MAIN_CONFIG, and check for
    # a new key if server verification fails.

    # Create a new box ID
    err_nbr, prv_id, pub_id = nm_account_create()
    if err_nbr != 0:
        return((print_err(
            err_nbr,
            'Failed to create a new box ID.  Try again in '
            + '10 minutes.'), None))

    # Save info about the box ID and identity after
    # encrypting the values.
    config_txt = nm_encrypt_local_txt(prv_id, SESSION_PW)  # returns type str()
    MAIN_CONFIG['Identity1'] = {}
    MAIN_CONFIG['Identity1']['prvid'] = config_txt

    # Self-test... decrypt and see if it matches:
    config_txt = nm_decrypt_local_txt(
        MAIN_CONFIG['Identity1']['prvid'],
        SESSION_PW)
    if config_txt != prv_id:
        return((
            print_err(
                37000,
                'Self-test on decryption of private ID failed.  This is '
                + 'probably a programmer error.'),
            None))

    config_txt = nm_encrypt_local_txt('My Main Box ID', SESSION_PW)
    MAIN_CONFIG['Identity1']['identity_nickname1'] = config_txt

    config_txt = nm_encrypt_local_txt(pub_id, SESSION_PW)
    MAIN_CONFIG['Identity1']['pubid1'] = config_txt

    # For the first box ID only, make it the default box ID (encrypted)
    MAIN_CONFIG['SETTINGS']['current_pub_box_id'] = config_txt

    config_txt = nm_encrypt_local_txt('main', SESSION_PW)
    MAIN_CONFIG['Identity1']['nickname1'] = config_txt

    debug_msg(1, 'OK, box ID created.')
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    if nm_confirm(
        prompt='Do you want to add another box ID under the '
               + 'default identity? (y/n): '):
        err_nbr, prv_id2, pub_id2 = nm_account_create(private_box_id=prv_id)
        if err_nbr != 0:
            print_err(
                err_nbr,
                'Failed to create the second box ID under the '
                + 'default identity. '
                + 'Try again in 10 minutes.')
        else:
            config_txt = nm_encrypt_local_txt(pub_id2, SESSION_PW)
            MAIN_CONFIG['Identity1']['pubid2'] = config_txt

            nickname = input_and_confirm(
                'Enter a nickname for the second box ID (this is '
                + 'never sent to any server)' + os.linesep + ': ')
            if nickname is not None:
                config_txt = nm_encrypt_local_txt(nickname, SESSION_PW)
                MAIN_CONFIG['Identity1']['nickname2'] = config_txt

    # Add Bob's ID as a contact

    config_txt = nm_encrypt_local_txt(
        'PUB002016013113CC95900BF7D64498E8A23D6D00E3862CF3B29E2B597DB'
        '492BC65CCADF11AF529AF8914B7B2B4290E6F86D54DC1E6C4C02EEFF12D6'
        '3675A802820BEAF7869BB',
        SESSION_PW)
    MAIN_CONFIG['Identity1']['contact_public_box_id1'] = config_txt

    config_txt = nm_encrypt_local_txt('Robert Hoot (pgm author)', SESSION_PW)
    MAIN_CONFIG['Identity1']['contact_nickname1'] = config_txt

    config_txt = nm_encrypt_local_txt(
        'Send questions, comments, bug reports, feature requests, etc. '
        + 'to Robert Hoot.',
        SESSION_PW)
    MAIN_CONFIG['Identity1']['contact_note1'] = config_txt

    # ######################################################################
    #                   Top Secret Identity
    print('Creating the Top Secret identity and box ID.  Please wait...')
    prv_id = None
    pub_id = None
    err_nbr, prv_id, pub_id = nm_account_create()
    if err_nbr != 0:
        return((
            print_err(
                err_nbr,
                'Failed to create a new box ID.  Try '
                + 'again in 10 minutes.'),
            None))

    MAIN_CONFIG['Identity2'] = {}

    config_txt = nm_encrypt_local_txt('Top Secret', SESSION_PW)
    MAIN_CONFIG['Identity2']['identity_nickname2'] = config_txt

    config_txt = nm_encrypt_local_txt(prv_id, SESSION_PW)
    MAIN_CONFIG['Identity2'] = {}
    MAIN_CONFIG['Identity2']['prvid'] = config_txt

    config_txt = nm_encrypt_local_txt(pub_id, SESSION_PW)
    MAIN_CONFIG['Identity2']['pubid1'] = config_txt

    config_txt = nm_encrypt_local_txt('default box ID', SESSION_PW)
    MAIN_CONFIG['Identity2']['nickname1'] = config_txt

    print('OK, box ID created.')
    if nm_confirm(
        prompt='Do you want to add another box ID under the '
               + 'Top Secret identity? (y/n): '):
        prv_id2 = None
        pub_id2 = None
        err_nbr = None
        err_nbr, prv_id2, pub_id2 = nm_account_create(private_box_id=prv_id)
        if err_nbr != 0:
            print_err(
                err_nbr,
                'Failed to create the second box ID under '
                + 'the Top Secret identity. Try again in 10 minutes.')
        else:

            config_txt = nm_encrypt_local_txt(pub_id2, SESSION_PW)
            MAIN_CONFIG['Identity2']['pubid2'] = config_txt

            nickname = input_and_confirm(
                'Enter a nickname for the '
                + 'second box ID under Top Secret '
                + ' (this is never sent to any server): ')
            if nickname is not None:
                config_txt = nm_encrypt_local_txt(nickname, SESSION_PW)
                MAIN_CONFIG['Identity2']['nickname2'] = config_txt
            else:
                print('nickname not saved')

    # ---------------------------------------------------------------------
    # set the default editor
    nm_select_editor()
    # ---------------------------------------------------------------------
    err_nbr = nm_write_config()
    if err_nbr != 0:
        return((print_err(
            37100,
            'Could not save the configuration file.  '
            + 'This is a serious error.  '
            + 'Check permissions to the home directory, and check '
            + 'free disk space.'), None))

    print('')
    print('==================================================================')
    print('WARNING: It is SUPER IMPORTANT that you make a backup copy of ')
    print('your configuration file: ')
    print('    ' + CONFIG_FNAME)
    print('That file contains encrypted information that is needed to '
          + 'access your inbox.')
    print('If your hard drive or computer fails and you do not have a backup ')
    print('copy, then you will not be able to access your inbox.')
    print('You could create a new box ID, but you will not be able to access ')
    print('the old one.')
    print('WARNING: If you forget your password, you will not be able '
          + 'to access your inbox.')
    print('==================================================================')
    input('Press any key to continue....')

    nm_set_unrtf_pgm()

    # Fix permissions
    root_owner_found = False
    # to do: confirm owner ID
    if platform.system().lower() != 'windows':
        # first see if anything is owned by root
        for root, dirs, files in os.walk(MAIL_DIR):
            for f in files:
                if f == '':
                    # check directory owner
                    if os.stat(root).st_uid == 'root':
                        root_owner_found = True
                        break
                else:
                    # regular file
                    fpath = os.path.join(root, f)
                    if os.stat(fpath).st_uid == 'root':
                        root_owner_found = True
                        break
            if root_owner_found:
                break

        if root_owner_found:
            if os.getlogin() == 'root':
                print('WARNING, your mail directory contains files that are '
                      + 'owned by the root user ID and might not be '
                      + 'accessible to your regular user ID.  '
                      + 'Your login ID is also set to root. ')

                owner_id_alpha = intput(
                    'Enter the user ID that you '
                    + 'want to be the owner of your mail directory: ')

                owner_numeric_id = pwd.getpwnam(owner_id_alpha).pw_uid
                owner_gid = pwd.getpwnam(owner_id_alpha).pw_gid
            else:
                owner_numeric_id = pwd.getpwnam(os.getlogin()).pw_uid
                owner_gid = pwd.getpwnam(os.getlogin()).pw_gid

            debug_msg(
                2,
                '==== fixing owner for '
                + CONFIG_FNAME)
            shutil.chown(CONFIG_FNAME, user=owner_numeric_id, group=owner_gid)

            for root, dirs, files in os.walk(MAIL_DIR):
                for f in files:
                    if f == '':
                        # Fix directory owner
                        shutil.chown(
                            root,
                            user=owner_numeric_id, group=owner_gid)
                    else:
                        # Fix regular file owner
                        fpath = os.path.join(root, f)
                        debug_msg(
                            2,
                            '==== fixing owner for ' + fpath)
                        shutil.chown(
                            fpath,
                            user=owner_numeric_id, group=owner_gid)

    return((0, CONFIG_FNAME))


###############################################################################
def nm_write_config():
    """Write the config file to disk.

    Make an archive copy of the existing config (settings) file and
    then write the MAIN_CONFIG settings to disk.

    This returns 0 on success.  If the global value for
    CONFIG_FNAME was not set, this will attempt to set
    it before saving.
    """
    global MAIN_CONFIG
    global CONFIG_FNAME

    options_written = False

    if CONFIG_FNAME is None:
        # call this routine to set the global CONFIG_FNAME:
        need_new_config_fname, CONFIG_FNAME = nm_find_default_config_fname()

    if CONFIG_FNAME is not None:
        try:
            roll_gdg(CONFIG_FNAME)
        except:
            print('Warning.  Could not save an archive copy of '
                  + 'the configuration file.')

        try:
            fd = codecs.open(CONFIG_FNAME, 'w', 'utf-8')
            MAIN_CONFIG.write(fd)
            fd.close()
        except:
            return(print_err(
                37500,
                'Could not save the configuration file.  '
                + 'This is a serious error.  '
                + 'Check permissions to the home directory, '
                + 'and check free disk '
                + 'space. The filename was ' + CONFIG_FNAME))
    else:
            return(print_err(
                37600,
                'Could not determine the filename for '
                + 'saving the MAIN_CONFIG file.'))

    return(0)


###############################################################################
def nm_create_contact_entry(
        public_box_id,
        nickname=None,
        name=None,
        business=None,
        notes=None):
    """Create a contact entry in the config file.

    This creates the encrypted 'value' of the key/value pair that will
    be added to the config file. The caller must put his in the configparser
    and save it to a permanent storage device.

    Positional arguments:
    public_box_id -- Public box ID.

    Keyword arguments:
    nickname -- A nickname for the contact (this is always kept local--never
        sent to any server).
    name = Name of the contact??,
    business -- Business name,
    notes -- Notes for this contact):

    Return value:
    0 for success, or nonzero for failure.
    """
    global SESSION_PW

    # I SHOULD BASE 64 THE individual VALUES to prevent invalid JSON chars,
    # THEN ENCRYPT AND BASE 64 THE ENTIRE JSON THING.
    err_nbr = verify_id_format(public_box_id, expected_prefix='PUB')
    if err_nbr != 0:
        return((err_nbr, None))

    ctc = '"public_box_id": "' \
        + base64.b64encode(bytes(public_box_id, 'utf-8')).decode('utf-8') + '"'

    if nickname is not None:
        ctc += ',"nickname":"' \
            + base64.b64encode(bytes(nickname, 'utf-8')).decode('utf-8') + '"'

    if name is not None:
        ctc += ',"name":"' + base64.b64encode(bytes(
            name, 'utf-8')).decode('utf-8') + '"'

    if business is not None:
        ctc += ',"business":"' \
            + base64.b64encode(bytes(business, 'utf-8')).decode('utf-8') + '"'

    if notes is not None:
        ctc += ',"notes":"' + base64.b64encode(bytes(
            notes, 'utf-8')).decode('utf-8') + '"'

    ctc = '{' + ctc + '}'

    # Encrypt and base64 it
    config_txt = nm_encrypt_local_txt(ctc, SESSION_PW)

    if config_txt is None:
        return((38000, None))
    else:
        return((0, config_txt))


###############################################################################
def nm_build_contact_dict(
        current_identity,
        include_anonymous=False,
        local_only=False):
    """Build a list of contacts in dictionary format.

    This will build a list of contacts for this identity. Each entry
    is a dictionary that will allow me to accessthe contact description
    and other things.

    The keys in the Python dictionary have THE FORM:
       contact_public_box_id#
       contact_nickname#
       contact_note#
    where '#' is replaced with a number (no leading zeroes).

    The odd format is an extension of how the keys exist in the config file
    (with the numbers used to avoid duplicates).

    Positional arguments:
    current_identity -- the name of the current identity as it exists in the
        config file.

    Keyword arguments:
    include_anonymous -- defaults to False.  If it is set to True, this will
        include a contact of 'Anonymous,' which allows the user to send
        a message from 'Anonymous' (meaning no sender ID).
    local_only -- defaults to False. If set to True, include only those
        contacts that represent the current user (for use as the
        From/Reply-to user ID).

    Return value:
    0 for success, or nonzero for failure.

    """
    global SESSION_PW
    global MAIN_CONFIG

    if current_identity not in MAIN_CONFIG.keys():
        # Silently return because this will be called for senders
        # or are not in the contact list, and I will just present
        # the formatted box ID rather than including a nickname.
        print_err(
            38170,
            'The identity passed to nm_build_contact_list was '
            + 'not found: ' + str(current_identity))
        return(None)

    contact_dict = {}
    if not local_only:
        for a in MAIN_CONFIG[current_identity].keys():
            # Loop through the contacts under this identity,
            # format some information,
            # then add a key/value pair for contact_description and
            # {id_nbr: THENBR, box_id=THE_BOX_ID}
            if a[0:21] == 'contact_public_box_id':
                id_nbr = int(a[21:])
                # Decrypt the nickname
                try:
                    nickname = ' ' \
                        + nm_decrypt_local_txt(
                            MAIN_CONFIG[current_identity][
                                'contact_nickname' + str(id_nbr)],
                            SESSION_PW)

                except:
                    pass

                # Decrypt the note
                try:
                    contact_note = ' ' \
                        + nm_decrypt_local_txt(
                            MAIN_CONFIG[current_identity][
                                'contact_note' + str(id_nbr)],
                            SESSION_PW)

                except:
                    contact_note = ''
                    pass

                # decrypt the box ID
                box_id = nm_decrypt_local_txt(
                    MAIN_CONFIG[current_identity][a],
                    SESSION_PW)

                if nickname is None:
                    # try to build unique keys using the last few chars
                    nickname = ' (no nickname-' + box_id[-6:] + ')'

                contact_description = nickname + ', ' \
                    + box_id[0:16] + '...' + box_id[-6:]
                # contact description and the full box ID:
                contact_dict.update(
                    {contact_description: {
                        'id_nbr': id_nbr,
                        'box_id': box_id,
                        'nickname': nickname,
                        'contact_note': contact_note}})

    # Add the user's own box ID to the contact list:
    for a in MAIN_CONFIG[current_identity].keys():
        if a[0:5] == 'pubid':
            id_nbr = int(a[5:])

            # decrypt the nickname
            nickname = None
            try:
                # The * in the first column indicates a local account
                nickname = '*' + nm_decrypt_local_txt(
                    MAIN_CONFIG[current_identity]['nickname' + str(id_nbr)],
                    SESSION_PW)

            except:
                pass

            if nickname is None:
                nickname = '*(no nickname)'

            #  Decrypt the box ID.
            box_id = nm_decrypt_local_txt(
                MAIN_CONFIG[current_identity][a],
                SESSION_PW)

            contact_description = nickname + ', ' \
                + box_id[0:16] + '...' + box_id[-6:]
            # Contact description and the full box ID:
            contact_dict.update(
                {contact_description: {'id_nbr': id_nbr, 'box_id': box_id}})

    if include_anonymous:
        contact_dict.update(
            {contact_description: {'id_nbr': 0, 'box_id': 'Anonymous'}})

    return(contact_dict)


###############################################################################
def nm_start(batch=False):
    """
    This is called early in the launch process to load or create
    the configuration file and prepare for actoin.
    """
    global MAIN_CONFIG
    global SESSION_PW
    global CONFIG_FNAME
    global VERBOSITY

    MAIL_DIR = ''  # Loaded from options or calculated.
    HOME_DIR = os.path.expanduser('~')

    #  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    need_new_config_file = False
    need_new_config_file, tmp_config_fname = nm_find_default_config_fname()

    if not need_new_config_file:
        if tmp_config_fname != '':
            CONFIG_FNAME = tmp_config_fname
        else:
            # there was an error
            return(print_err(
                38100,
                'There was an error trying to determine the config '
                + 'file name.'))
    else:
        pass
        # delete the old logic after testing
        # # There is no option file: set the default directory
        # # so that I can prepare the nm_mail directory tree...
        # # a new config file will be built later.

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    if need_new_config_file:
        err_nbr, CONFIG_FNAME = nm_create_config_file(homedir=HOME_DIR)
        if err_nbr != 0:
            return(print_err(
                38200,
                'Failed to save the initial configuration file.'))
        else:
            debug_msg(4, 'Config file appears to have been created.')

    else:
        debug_msg(4, 'There is no need for a new configuration file.')

    # We now have a (possibly empty?) config file on disk, either a new
    # one or an existing one.

    if CONFIG_FNAME is None:
        return(print_err(
            38300,
            'After the configuration file was supposed to '
            + 'be verified, there '
            + 'is no value for config_fname.  This is a programmer error.'))

    if CONFIG_FNAME == '':
        return(print_err(
            38400,
            'After the configuration file was supposed to be verified, '
            + 'config_fname is blank.  This is a programmer error.'))

    debug_msg(1, 'Loading configuration file: ' + CONFIG_FNAME)

    #  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # We have an existing configuration file, read it.
    MAIN_CONFIG = configparser.ConfigParser()
    MAIN_CONFIG.read(CONFIG_FNAME)

    # -#-#-#-#-#- Some verification needed for the startup process:
    if 'screen_width' not in MAIN_CONFIG['SETTINGS'].keys():
        print(
            'WARNING. Your options file does not contain an entry for '
            + 'screen_width. Defaulting to 80')
        # Screen width is a string -- all config opts are strings.
        MAIN_CONFIG['SETTINGS']['screen_width'] = '80'
        time.sleep(.3)

    if 'screen_height' not in MAIN_CONFIG['SETTINGS'].keys():
        print(
            'WARNING. Your options file does not contain an entry for '
            + 'screen_height. Defaulting to 20')
        MAIN_CONFIG['SETTINGS']['screen_height'] = '20'
        time.sleep(.3)

    if 'mail_dir' not in MAIN_CONFIG['SETTINGS'].keys():
        print('Error.  Your settings file is corrupt. There is no value for '
              + 'mail_dir.')
        print('Either restore ' + CONFIG_FNAME
              + ' or rename it to force this '
              + 'program to create a new file.  If you let this '
              + 'program generate a new settings file, '
              + 'will create a new box ID for you (you must recover your old '
              + 'settings file if you want to receive messages to '
              + 'your old box_id).')
        print('If you create a new settings file, use the same '
              + 'password so that you can copy your old contacts into '
              + 'the new file when you restore your real config file.')
        sys.exit(333)
    else:
        MAIL_DIR = MAIN_CONFIG['SETTINGS']['mail_dir']
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    if MAIL_DIR == '':
        # If there was an option file but for some reason
        # it was corrupted and MAIL_DIR was not set...
        MAIL_DIR = HOME_DIR + os.sep + 'nm_mail'
        if not os.path.isdir(
                os.path.expanduser(os.path.join('~', 'Downloads'))):
            # Do not alter the privileges.
            os.makedirs(os.path.expanduser(os.path.join('~', 'Downloads')))
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    dirs = [
        MAIL_DIR,
        MAIL_DIR + os.sep + 'settings',
        MAIL_DIR + os.sep + 'Identity1' + os.sep + 'received',
        MAIL_DIR + os.sep + 'Identity1' + os.sep + 'incoming',
        MAIL_DIR + os.sep + 'Identity1' + os.sep + 'sent',
        MAIL_DIR + os.sep + 'Identity1' + os.sep + 'outgoing',
        MAIL_DIR + os.sep + 'Identity2' + os.sep + 'received',
        MAIL_DIR + os.sep + 'Identity2' + os.sep + 'incoming',
        MAIL_DIR + os.sep + 'Identity2' + os.sep + 'sent',
        MAIL_DIR + os.sep + 'Identity2' + os.sep + 'outgoing']

    for d in dirs:
        if d != '':
            if not os.path.isdir(d):
                os.makedirs(
                    d,
                    mode=0o700)
                if platform.system().lower() != 'windows':
                    debug_msg(
                        2,
                        '==== fixing owner for ' + d)
                    # The ownership thing would test for problems if the user
                    # copied an old archive to a new computer or user ID.
                    # (it might fail, but at least you will know why)
                    shutil.chown(
                        d,
                        user=pwd.getpwnam(os.getlogin()).pw_uid,
                        group=pwd.getpwnam(os.getlogin()).pw_gid)

    # Some verification.
    if 'screen_width' not in MAIN_CONFIG['SETTINGS'].keys():
        print('WARNING. Your options file does not contain an entry '
              + 'for screen_width. Defaulting to 80')
        # All values are strings in the config file,
        # including screen width.
        MAIN_CONFIG['SETTINGS']['screen_width'] = '80'
        time.sleep(.3)

    if 'screen_height' not in MAIN_CONFIG['SETTINGS'].keys():
        print(
            'WARNING. Your options file does not contain an entry '
            + 'for screen_height. Defaulting to 20')
        MAIN_CONFIG['SETTINGS']['screen_height'] = '20'
        time.sleep(.3)

    if 'current_identity' not in MAIN_CONFIG['SETTINGS'].keys():
        print(
            'WARNING. Your options file does not contain an '
            + 'entry for your current identity.  Defaulting to Identity1.')
        MAIN_CONFIG['SETTINGS']['current_identity'] = 'Identity1'
        time.sleep(.7)

    if 'verbosity' not in MAIN_CONFIG['SETTINGS'].keys():
        print(
            'WARNING. Your options file does not contain an entry '
            + 'for verbosity.  Defaulting to 4 (which is higher than '
            + 'usual because you obviously have some problems).')
        MAIN_CONFIG['SETTINGS']['verbosity'] = '4'
        time.sleep(.7)

    if 'download_directory' not in MAIN_CONFIG['SETTINGS'].keys():
        ddd = os.path.abspath(os.path.expanduser('~/Downloads'))
        print(
            'WARNING. Your options file does not contain '
            + 'an entry for the download '
            + 'directory.  Defaulting to ' + ddd)
        MAIN_CONFIG['SETTINGS']['download_directory'] = ddd
        os.makedirs(ddd, exist_ok=True)
        time.sleep(.7)
    # ####################################################################
    try:
        VERBOSITY = int(MAIN_CONFIG['SETTINGS']['verbosity'])
    except:
        VERBOSITY = 4

    debug_msg(4, 'Your VERBOSITY setting is ' + str(VERBOSITY))
    # ####################################################################

    # Many items in the config file contain encrypted values,
    # but they are not decrypted until they are needed.
    # The SESSION_PW is used to decrypt config values.
    if not batch:
        if SESSION_PW == '':
            SESSION_PW = pw_hash2(
                receipt_fname=MAIN_CONFIG['SETTINGS']['PBKDF2_receipt_file'])
            if SESSION_PW is None:
                return(print_err(38500, 'Failed to get the session password.'))

    return (0)


###############################################################################
# def pw_hash2(iterations=111373, receipt_fname=None):
def pw_hash2(iterations=97831, receipt_fname=None):
    """Hash a password using PBKDF2 and verify against a receipt.

    This is a system for prompting the user to enter a
    password, then strengthening that password with
    PBKDF2.  The intent is to use the hashed password
    to encrypt local information, such as individual values
    in the configparser dictionary.

    This process allows me to generate a complex password (once)
    so that when I call the encryption routine many times, I just
    uses the pre-hashed password rather than having to wait
    for the hash during each encryption.

    If receipt_fname is specified, and if the file exists,
    it is used to double check that the password this time
    matches a hash of the prior password. If the file does not exist,
    it is assumed that receipt fname is the location where
    the new receipt should go. If receipt_fname is not passed,
    the filename is retrieved from the configuration table.

    Keyword arguments:
    iterations -- The number of PBKDF2 iterations to hash the password.
    receipt_fname -- The name of a file that holds a receipt that can
        be used to check that the hashed password matches a saved
        subset of that key.

    Return value:
    0 for success, or nonzero for failure.

    """
    global MAIN_CONFIG

    need_new_receipt = False

    static_receipt_txt = 'Do not edit this text in any way.  '\
        + 'If this decrypts correctly, then the password is good.'

    # The user is prompted to enter a password, then it is hashed

    receipt = None
    pw_hashed = None
    # receipt_fname holds a receipt that can be used to confirm
    # if the entered password matches what was previously entered
    # (with a modest degree of accuracy).
    if receipt_fname is None:
        try:
            receipt_fname = MAIN_CONFIG['SETTINGS']['PBKDF2_receipt_file']
        except:
            receipt_fname = os.path.expanduser('~') + os.sep + 'nm_mail' \
                + os.sep + 'pbkdf2_receipt.save'

            if not os.path.isfile(receipt_fname):
                need_new_receipt = True
                print('WARNING: Could not get the name of '
                      + 'the password receipt file from the '
                      + 'configuration table.  The file is usually '
                      + 'in your home directory and '
                      + 'called natmsgsc.ini or .natmsgsc. '
                      + 'I wil put the file in')
                print('You can try to continue or try to restore '
                      + 'the configuration file.')
                junk = input('Press any key to continue....')
    else:
        if os.path.isfile(receipt_fname):
            print('using password receipt file: ' + receipt_fname)
        else:
            need_new_receipt = True

    def main_loop():
        pw_hashed = None
        pw = ''
        while pw == '':
            try:
                pw = getpass.getpass(
                    'Enter the password for Natural '
                    + 'Message simple client: ')
            except KeyboardInterrupt:
                print()  # move to a new output line
                return(None)

        # The salt is set to zero so that I get the same
        # output every time that I run this because I will
        # use the output here as the password later.
        # This routine is based on the one in RNCryptor (with
        # the salt modified):
        print('Please wait while the password is being hashed.')
        pw_hashed = KDF.PBKDF2(
            pw,
            b'00',
            dkLen=32,
            count=iterations,
            prf=lambda p, s: hmac.new(p, s, hashlib.sha256).digest())

        return(pw_hashed)
        # end of main_loop

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # hash the password and compare against the receipt
    pw_hashed = None
    while pw_hashed is None:
        pw_hashed = main_loop()
        if pw_hashed is not None:
            if not need_new_receipt:
                # Verify that the receipt is the same as the saved copy
                with open(receipt_fname, 'r') as fd:
                    encrypted_receipt = fd.read()

                    # decrypt the saved msg
                    saved_receipt = nm_decrypt_local_txt(
                        encrypted_receipt,
                        pw_hashed)

                    if saved_receipt != static_receipt_txt:
                        print('BAD pw')
                        pw_hashed = None  # Force another iteration.
                    else:
                        debug_msg(5, 'GOOD pw')
            else:
                # A new receipt is needed.
                print()
                print('============ WARNING!!! ================')
                print('There was no prior verification file.')
                print('You can now create a verification file so that')
                print('this program can easily tell if you have the correct')
                print('password in the future.')
                print('')
                print('If you are starting the client application '
                      + 'for the first time,')
                print('then proceed, else enter "n" to quit.')
                print(' ')

                if nm_confirm:
                    if not os.path.isdir(os.path.dirname(receipt_fname)):
                        # create the directory if need be
                        try:
                            os.makedirs(
                                os.path.dirname(receipt_fname), mode=0o700)
                        except:
                            e = str(sys.exc_info()[0:2])
                            print_err(
                                39000,
                                'Failed to create a receipt for your login '
                                + 'password: receipt_fname.  Did you change '
                                + 'your option file or alter your home '
                                + 'directory? Check your mail_dir option '
                                + 'and pbkdf2_receipt_file '
                                + 'option in ' + CONFIG_FNAME
                                + '\nThe original error was: ' + e)
                            print_err(
                                39001,
                                'Another possibility is that the '
                                + 'path shown above came from a '
                                + 'config file that you copied from another '
                                + 'computer, and the directory names '
                                + 'in your .natmsg config file are wrong.')
                            return(None)

                    # FIX THIS. I DON'T HAVE A PASSWORD ON THE FIRST RUN
                    # FIX THIS. I DON'T HAVE A PASSWORD ON THE FIRST RUN
                    # FIX THIS. I DON'T HAVE A PASSWORD ON THE FIRST RUN
                    # FIX THIS. I DON'T HAVE A PASSWORD ON THE FIRST RUN
                    receipt = nm_encrypt_local_txt(
                        static_receipt_txt, pw_hashed)

                    with open(receipt_fname, 'w') as fd:
                        fd.write(receipt)
                        os.fsync(fd.fileno())

                    need_new_receipt = False
                    print('')
                    print(
                        'Press any key to enter the password '
                        + 'again to verify')
                    print('your initial password.')
                    junk = input('...')
                    pw_hashed_new = pw_hash2(
                        iterations=iterations,
                        receipt_fname=receipt_fname)
                    if pw_hashed_new != pw_hashed:
                        pw_hashed = None  # Force another loop.

        else:
            print('There might be a problem with the '
                  + 'pw_hash routine.  You can try again or kill the program.')
            input('Press any key to continue...')

    return(pw_hashed)


###############################################################################
def roll_gdg(file_path):
    """
    This will see if the specified file exists, and if it does,
    this function will rename the file by
    adding ".g####" to the end of the filename.

    GDG = "generation data group," which is used on IBM
    mainframes as a mechanism for keeping a history of files.

    Positional arguments:
    file_path -- Path of the file to delete.

    Return value:
    0 for success, or nonzero for failure.

    """
    # This function will help me to extract GDGs for the
    # current file:

    debug_msg(4, 'Running roll_gdg with fname ' + file_path)

    def gdg_filter(s):
        j = len(s) - 1
        while j >= 0:
            while s[j].isnumeric():
                j -= 1
            if s[j] == 'G':
                # Looks good so far, look for a dot
                if s[j - 1] == '.':
                    if (j + 5) == len(s):
                        return(True)
                else:
                    j = -1
            else:
                j = -1

        return(False)

    bname = os.path.basename(file_path)

    # Extract the list of GDG files associated
    # with the specified (root) filename.
    highest_gdg = ''
    current_dir = os.path.dirname(file_path)
    if current_dir == '':
        current_dir = '.'

    if os.path.isfile(file_path):
        # Find the highest numbered GDG for this file
        # in the current directory.
        dirs = os.listdir(current_dir)

        gdg_entries = filter(gdg_filter, dirs)
        for x in gdg_entries:
            debug_msg(
                6,
                'In roll_gdg, found existing GDG member: ' + str(x))
            if x > highest_gdg:
                highest_gdg = x

        debug_msg(5, 'Highest gdg found was: ' + highest_gdg)
        if highest_gdg != '':
            gnbr = int(highest_gdg[-4:]) + 1
        else:
            gnbr = 1
        new_basename = bname + '.G' + "%04d" % gnbr
        new_path = current_dir + os.sep + new_basename
        shutil.move(file_path, new_path)

    return(0)


###############################################################################
def nm_select_editor():
    """Prompt the user to select an editor for writing messages.

    During the initial installation, see which editors
    are available and prompt the user to select one.

    This should probably be used only for OS other than
    Windows and Mac.
    """
    global MAIN_CONFIG

    found_editors = []

    unix_prefixes = ['/usr/bin/', '/bin/', '/usr/local/bin/']
    unix_editors = [
        'nano',
        'pico',
        'leafpad',
        'gedit',
        'vim',
        'emacs',
        'vi',
        'mousepad',
        'kwrite',
        'kate']

    other_editors = ['notepad.exe', '/Applications/TextEdit.app']

    if 'editor_command' not in MAIN_CONFIG['SETTINGS'].keys():
        MAIN_CONFIG['SETTINGS']['editor_command'] = ''

    if platform.system().lower() in ['darwin', 'windows']:
        # mac and windows will use system defaults
        MAIN_CONFIG['SETTINGS']['editor_command'] = ''
        nm_write_config()
        return(0)
    else:
        # linux, bsd, other
        for p in unix_prefixes:
            for e in unix_editors:
                path = p + e
                try:
                    if os.path.isfile(path):
                        found_editors.append(path)
                except:
                    pass

        if len(found_editors) == 0:
            return(print_err(
                93459,
                'Failed to obtain a choice '
                + 'for the editor.'))
        else:
            # There was at least one 'found editor' in the list.
            idx, choice = nm_menu_choice(
                found_editors,
                title='Select the path and '
                + 'program name for a text editor that you want to use.')

            if idx < 0:
                return(print_err(
                    9345,
                    'Failed to obtain a choice for the editor.'))
            else:
                the_pgm = nm_encrypt_local_txt(choice, SESSION_PW)
                # The value for the editor is encrypted.
                MAIN_CONFIG['SETTINGS']['editor_command'] = the_pgm
                nm_write_config()

    return(0)


###############################################################################
def nm_clean_utf8_text(data_raw):
    """Standardize EOL and remove RTF if possible.

    Send a Python bytes object (that represents some kind of text
    or RTF) to this function and it will standardize the EOLs,
    remove RTF codes, and escape any non-UTF8 characters.
    This was originally created to facilitate displaying either
    text or RTF on a terminal screen. Do not send Mac OS X RTFD
    files to this function (they might display reasonably but the
    underlying protocol is proprietary and graphics will not be handled
    correctly).

    This returns a Python list object with one line of text
    in each element (with no EOL at the end of the lines). You might
    want to use the output like this:

        fd = open('myfile.rtf', 'rb')
        data_raw = fd.read()
        fd.close()
        my_str = os.linesep.join(nm_clean_utf8_text(data_raw))

    If you send garbage to this function, it will return
    something like this: '[The original message contained invalid data]'
    """
    global MAIN_CONFIG
    global SESSION_PW

    UNRTF_HDR = '###  Translation from RTF performed by UnRTF'

    show_warning = False
    data_array = []

    if not isinstance(data_raw, bytes):
        try:
            data_raw = bytes(data_raw, 'utf-8')
        except:
            # This should probably never happen unless
            # somebody sends a non-string.
            data_raw = bytes(
                '[The original message contained invalid data]',
                'utf-8')

    unrtf_out = None
    if data_raw[0:5] == bytes('{\\rtf', 'utf-8'):
        # The input file appears to be RTF, so remove RTF codes
        # so that I can display it in plain text.
        fd = io.BytesIO(data_raw)

        debug_msg(
            4,
            'Calling the unrtf program to strip RTF in the main message.')

        # Run the unrtf program to remove RTF codes:
        if 'unrtf_pgm' in MAIN_CONFIG['SETTINGS'].keys():
            # unrtf_pgm needs to be decrypted
            pgm_encrypted = MAIN_CONFIG['SETTINGS']['unrtf_pgm']
            if pgm_encrypted == '':
                show_warning = True
            else:
                unrtf_pgm = None
                try:
                    unrtf_pgm = nm_decrypt_local_txt(
                        MAIN_CONFIG['SETTINGS']['unrtf_pgm'],
                        SESSION_PW)
                except:
                    pass

                if unrtf_pgm is not None:
                    if os.path.isfile(unrtf_pgm):
                        try:
                            pid = subprocess.Popen(
                                [unrtf_pgm, '--text', '--quiet', '--nopict'],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

                            # 'unrtf_out' is a python bytes() object
                            # because input is binary.
                            unrtf_out, err_msg = pid.communicate(fd.read())
                            # Standardize newlines first!!
                            # (there could be side-effects if the text
                            # contains invalid binary data).
                        except:
                            e = str(sys.exc_info()[0:2])
                            show_warning = True
                            print_err(7787, e)
                else:
                    show_warning = True
        else:
            show_warning = True

    if show_warning:
        print('WARNING: Could not run the unrtf program to remove '
              + 'RTF codes.  RTF codes might appear in the output.')
        print('If you install the unrtf program, you can point to '
              + 'it using the settings option in the main menu.')
        print('If you already have the unrtf program, you can point to it '
              + 'using the settings menu that is shown on the main menu.')
        time.sleep(1)

    if unrtf_out is not None:
        # RTF text that was successfully processed by unrtf.

        # Split the data into lines so that I can kill the unRTF
        # header lines.
        data_array = unrtf_out.replace(
            bytes('\r\n', 'utf-8'),
            bytes('\n', 'utf-8')).replace(
                bytes('\r', 'utf-8'),
                bytes('\n', 'utf-8')).split(bytes('\n', 'utf-8'))

        if data_array[0][0:len(UNRTF_HDR)] == bytes(UNRTF_HDR, 'utf-8'):
            # There is an unRTF header.
            hdr_count = 0
            idx = 0
            while True:
                if data_array[idx][0:4] == bytes('### ', 'utf-8'):
                    hdr_count += 1
                else:
                    # I prevously deleted an extra blank line here, but
                    # in some cases there is no blank line and real
                    # information was deleted by mistake
                    hdr_count += 0
                    break
                idx += 1

            # Delete the unRTF header lines
            for l in range(hdr_count):
                del(data_array[0])

            # This decode is a test to see if there are any
            # non-UTF8 characters.
            try:
                b''.join(data_array).decode('utf-8')
            except:
                # ADDD VERBOSITY CHECK
                debug_msg(
                    3,
                    'The RTF data produced non-UTF-8 characters, so some '
                    + 'characters will be escaped.')
                for k in range(len(data_array)):
                    data_array[k] = repr(data_array[k])[2:-1]
            else:
                for k in range(len(data_array)):
                    data_array[k] = data_array[k].decode('utf-8')

    else:
        # Either non-RTF or something that was unsuccessfully processed
        # by the unrtf program.

        # Standardize EOL and split into lines.
        data_array = data_raw.replace(
            bytes('\r\n', 'utf-8'),
            bytes('\n', 'utf-8')).replace(
                bytes('\r', 'utf-8'),
                bytes('\n', 'utf-8')).split(bytes('\n', 'utf-8'))

        # This decode is a test to see if there are any non-UTF8 characters.
        try:
            b''.join(data_array).decode('utf-8')
        except:
            # Use Python's repr() function to get an escaped
            # version of the the text to deal with invalid characters.
            for k in range(len(data_array)):
                data_array[k] = repr(data_array[k])[2:-1]
        else:
            # Convert each line to UTF-8
            for k in range(len(data_array)):
                data_array[k] = data_array[k].decode('utf-8')

    # Return an array of strings (no EOL at the end)
    return(data_array)


###############################################################################
# Choose a File
def nm_file_chooser(
        top,
        prompt='Select a file or directory to read: ',
        mode='file',
        select_msg_files=False):
    """
    This uses a text interface to prompt the user to select a file.
    It returns the name and path of the selected file.

    Positional arguments:
    top -- The root directory where file-selection begins.

    Keyword arguments:
    prompt -- The text that prompts the user to select a file.
    mode -- 'file' or 'directory'
    select_msg_files -- defaults to False.  If set to true, select
        files that contain archived Natural Messages (ending with .json
        or .meta.json).

    Return value:
    0 for success, or nonzero for failure.

    """
    finished = False

    mode = mode.lower()
    if mode not in ['file', 'directory']:
        natmsgblib.print_err(
            3929,
            'Invalid mode for nm_file_chooser. Must be '
            + 'file or directory.')
        return(None)

    try:
        while not finished:
            for root, dirs, files in os.walk(top):
                if root == top:
                    title = root
                    choices = ['..']
                    dirs.sort()
                    choices.extend(dirs)
                    files.sort(reverse=True)
                    for f in files:
                        if select_msg_files:
                            if f[-10:].lower() == '.meta.json':
                                if f[0:5].lower() != 'trash':
                                    choices.append(f)
                        else:
                            choices.append(f)

                    # The 'answer' will be just the filename without
                    # the full path.
                    # # nm_clear_screen()  # Avoid circular ref.
                    print('\n\n\n')
                    idx, answer = nm_menu_choice(choices, prompt=prompt)
                    if answer in dirs:
                        if mode == 'file':
                            top = top + os.sep + answer
                        else:
                            # Directory mode
                            a = input_no_confirm(
                                'Enter S to select this directory or G '
                                + 'to go to it: ')
                            if a is not None:
                                if a.lower() == 's':
                                    return(top + os.sep + answer)
                                elif a.lower() == 'g':
                                    # go to that directory
                                    top = top + os.sep + answer
                    elif answer == '..':
                        top = os.path.dirname(top)
                    elif answer == 'q':
                        top = None
                        finished = False
                        break
                    elif os.path.isfile(top + os.sep + answer):
                        # A file was selected, break out of the loop
                        finished = True
                        top = top + os.sep + answer
                        break

            if top is None:
                break
            elif finished:
                break
    except:
        top = None

    # Return the selected file, or None if there was an error
    return(top)


###############################################################################
def nm_search_files(top_directory, search_string):
    """
    This is a case insensitive search of the message and
    metadata JSON to find files to list in the 'inbox search' screen.

    Positional arguments:
    top_directory -- The directory root where the search starts.
    search_string -- The text to find

    Return value:
    A list of filenames containing the search string.

    """
    max_read_size = 1024 * 1024 * 15

    if not os.path.isdir(top_directory):
        return(print_err(
            42000,
            'Error. The specified location is not a '
            + 'directory: ' + str(top_directory)))

    found_files = []
    for root, dirs, files in os.walk(top_directory):
        for f in files:
            full_fname = os.path.join(root, f)
            if f[-5:] == '.json' and f[0:5].lower() != 'trash':
                # Search both the archive and the meta file (which
                # contains the subject line), but igore the ones
                # that have file names that start with 'trash'.
                #
                # Search this file.
                with open(full_fname, 'rb') as fd:
                    blk = fd.read(max_read_size)

                    if blk.lower().find(search_string.lower()) > 0:
                        # found it
                        found_files.append(full_fname)

    return(found_files)
