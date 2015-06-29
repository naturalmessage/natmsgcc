# Natural Message Simple Client for Python 3


# to do: 
#  1) check if the shard burns if the client reads only 100 bytes of the shard.
#  2) when receiving a msg, verify that the password shards
#     are in the serverFarm list with a good trust rating.


# This will be the simple command line client.
# To adapt to Chris's client, this will put an hard-coded
# RTF note into the main "message" that says to see the
# attachments, and the attachments might be DOS text.
#
# Get chris to add a "file_type" code for "message"
# to accept text or RTF.
################################## 
# Bob TEMP NOTES:
# pyQT has a built-in rich text editor:
# https://en.wikipedia.org/wiki/Scintilla_%28editing_component%29
# pyqt:http://www.riverbankcomputing.com/software/pyqt/intro
################################## 
#
# get RNCryptor from https://github.com/RNCryptor/RNCryptor-python
#
import natmsgcc.RNCryptor as RNCryptor
import base64
import codecs
import gzip
import json
import natmsgcc.natmsgclib as natmsgclib
import os
import platform
import queue
import shutil
import sys
import tempfile
import time

PUB_ID1='PUB002016013113CC95900BF7D64498E8A23D6D00E3862CF3B29E2B597DB492B' \
        + 'C65CCADF11AF529AF8914B7B2B4290E6F86D54DC1E6C4BA0233C5BB3271449' \
        + '69FC71BD7AB48B0'
PRV_ID1='PRV004001010113CC95900BF7D64498E8A23D6D00E3862CF3B29E2B597DB492B' \
        + 'C65CCADF11AF529AF8914B7B2B4290E6F86D54DC1E6C4BE43CAE157A44F83D' \
        + '5D51A21A072733D'

max_preamble_shard_size = 127
shard_count = 3
# The metadata prefixes must match what the other clients
# are using, and to simplify programming, they should be unique
# and equal lengths.
# # metadata_prefixes = {'password': '_PW', 'preamble':'_PA', 'big': '_BG'} 
metadata_prefixes = {'password': '_P', 'preamble':'_SMALL', 'big': '_BIG'} 
max_send_attempts = 4 # nbr of attempts for each shard server before quitting

shard_metadata = {}
template_msg = '{\rtf1\ansi{\fonttbl\f0\fswiss Helvetica;}\f0\pard ' \
    + 'See the attached file(s).\par}'

shard_send_queue = queue.Queue()
shard_receive_queue = queue.Queue()

SMD_PREAMBLE = '{"creatorVersion":"nmx1","meta":"'

#
#
privacy_notice = 'This electronic message, and any content linked from it, ' \
    + 'is for the sole use of the intended recipient and contains ' \
    + 'confidential and privileged information. If you received this ' \
    + 'message by error, please delete it from your computer and inform ' \
    + 'the sender. Any unauthorized review, use, disclosure or ' \
    + 'distribution of this message, items linked from it, or metadata ' \
    + 'about its contents is prohibited.'

########################################################################
########################################################################
########################################################################
def nm_send_shards(wrk_dir, sargs_array):
    """
    This will read an array of ShardSendQueueArgs objects
    and send (push) the shards from disk to shard servers.
    If there is an error, this will will try to resend the shard
    (UPDATE THIS TO PICK A NEW SHARD SERVER BEFORE RESENDING).

    All shards must be staged in the same working directory (wrk_dir).

    This is called from shard_and_send(), which initiates the shard
    sending process.
    """

    global shard_send_queue

    natmsgclib.debug_msg(
        5,
        'Starting nm_send_shards() with data:' + repr(sargs_array))
    # start a thread an add to the queue to process the shards.
    for sa in sargs_array:
        if sa.wrk_dir != wrk_dir:
            # Error. A shard is staged outside the wrk_dir
            return(10500)

        # start a thread for this shard
        t = natmsgclib.ThreadShardSend(shard_send_queue)
        # Start ThreadShardSend, which listens to shard_send_queue
        t.start()
        # Put the shard arguments into the queue (the put action does
        # not have a return value)
        shard_send_queue.put(sa)

        # I could sleep here if there are too many thread running at a time

    # print a status message every few seconds until all shards are sent.
    natmsgclib.show_shard_status(
        wrk_dir=wrk_dir,
        shard_args=sargs_array)  # This will loop until shards are all sent.

    # Double check that the queue has been processed, then loop until all
    # shards have a status of 'sent' in the disk status files.
    send_attempts = 0
    message_sent = False
    completed = False
    while not completed:
        # wait till all is done
        natmsgclib.debug_msg(
            5,
            'The next command will wait until all thread post a *done* code.')
        shard_send_queue.join() # safety measure to block until threads are done
        success_count = 0
        failed_count = 0

        #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
        # Test thread status in status files.
        # Rethread if need be.
        for sa in sargs_array:
            # For each shard_ID, verify that the status is 'sent'. If
            # status is 'failed', then resend.  If it has been more than
            # 5 minutes, resend (allow time for slow uploads?).
            status_fname = os.path.join(wrk_dir, sa.shard_id + '.status')
            st = None
            status_json = None
            try:
                fd_status = open(status_fname, 'r')
                try:
                    status_json = json.loads(fd_status.read())
                except:
                    e = str(sys.exc_info()[0:2])
                    print(e)
                    return(10532)
                finally:
                    fd_status.close()
            except:
                e = str(sys.exc_info()[0:2])
                print('Error. Failed to open status file: '
                    + status_fname + ' msg: ' + e)
                return(10533)

            try:
                st = status_json['status']
            except:
                e = str(sys.exc_info()[0:2])
                print(e)

            if st is not None:
                if st == 'sent':
                    success_count += 1
                    natmsgclib.debug_msg(5, 'Shard sent status on disk indicates success.')
                elif st == 'failed':
                    failed_count += 1
                    # The previous shard-send failed.
                    # Update the status to 'sending' and try again.
                    natmsgclib.nm_write_shard_status(status_fname, 'resending')

                    print('++ once debug on status file: ' + repr(st))
                    natmsgclib.debug_msg(
                        2,
                        '=== Resending shard with status file: ' + status_fname)
                    t = natmsgclib.ThreadShardSend(shard_send_queue)
                    #t.setDaemon(True)
                    t.start()
                    shard_send_queue.put(sa) # this is wrong??, put the current arg object
                else:
                    natmsgclib.debug_msg(5, 'The shard status in the status file is not ' \
                     + '"sent" or "failed": ' + str(st))
            else:
                natmsgclib.debug_msg(5, 'Could not get the shard status from the status ' \
                 + 'file for: ' + sa.shard_id + '. This should probably raise and exception.')
                

        send_attempts += 1
        finalized_count = success_count + failed_count
        if finalized_count == len(sargs_array):
            # completed means that I attempted an action and it completed,
            # possibly with success and possibly not.
            completed = True
            if success_count ==  len(sargs_array):
                message_sent = True
        else:
            natmsgclib.debug_msg(5, 'Not all shards ready.  Success count: ' \
                + str(success_count))

        if send_attempts > 5:
            natmsgclib.print_err(
                10600,
                'There were too many send attempts.  Not sending message')
            # Too many retries -- failed send.
            return(10600) 

        if not message_sent:
            # wait before trying again
            time.sleep(10)            

    # to do: I need to distinguish between succes and failure 
    # rather than mere completion
    print('===== The *send* task is complete, '
          + 'but I have not verify success. fix this!!!!!!!!!!!!!!!!!!!!!!.')
    return(0)
########################################################################
########################################################################
########################################################################


def shard_and_send(input_fname, pw, kek,  outbound_staging_dir,
    dest_box_id, subject=None, reply_to=None, batch=False,
    host='https://naturalmessage.com', port_nbr=443,
    outbound_shard_count=3, delete_temp_files=True, old_school=False):
    """
    This will process the archived msg (input as a Python
    bytes() object), zip it, encrypt it,
    slice it, create the parity chunk,
    write to disk, and push it to shard servers.

    The outbound_staging_dir is a temporary directory (usuaually in
    the 'outgoing' directory) that contains 'tmp' in the path name.

    If reply to is None, it will be left blank (sent anonymously).

    If old_school is True, it means that this will return a specially
    formatted link that can be sent over regular email so that 
    the receiver can put it into a Natural Message client to
    fetch a message from the Natural Message network.

    This returns a tuple: (return code, old_school_link)
    The old_school_link will be None, when old_school is False.

    """
    ## To Do: split this into pices so that it is easier 
    ## to restart/recover after a crash that happens in the
    ## middle of sending.
    global SMD_PREAMBLE
    global metadata_prefixes

    old_school_link = None # return value when old_school = True
    preamble_chunks =[]
    pw_chunks = []
    big_chunks = []
    big_chunks_exist = False

    gzip_fname = input_fname + '.gz'

    if dest_box_id is None:
        return((natmsgclib.print_err(3890, 'Destination box ID is ' \
            + 'missing in shard_and_send.'), None))
        

    if not isinstance(pw, bytes):
        pw = bytes(pw, 'utf-8')

    natmsgclib.debug_msg(1, 'Zipping the input archive file...')

    # These 'with' blocks automatically close the file
    # on end or on error.
    with gzip.GzipFile(gzip_fname, mode='wb') as gf:
        with open(input_fname, 'rb') as fd_in:
            gf.write(fd_in.read())


    # Read the gzip file and encrypt it.
    natmsgclib.debug_msg(1, 'Encrypting the gzip file...')
    msg = None
    with open(gzip_fname, 'rb') as gf_in:
        msg = gf_in.read()

    if msg is None:
        return((natmsgclib.print_err(10700, 'I could not get the gzipped file'), None))

    # ---------------------------------------------------
    # to do: append bytes so that the encrypted version of the
    # gzip file is divisible by the shard_count! Trailing
    # garbage to gzip file is ignored.

    # Do NOT add ballast or add junk to the end of the
    # gzip file because it might cause all of the contents
    # of a small file to go into the first shard,
    # thereby weakening the protection that we get by
    # splitting the file across multiple servers.

    # Do not force small shards to be 127 bytes until
    # we implement a new file format: split the file, then wrap
    # in a format that says file len then the real
    # file bytes followed by garbage (garbage added to
    # standardize shard lengths).
    # ---------------------------------------------------
    try:
        cryptor = natmsgclib.RNCrypt_bob()
    except:
        return((natmsgclib.print_err(10800, 'Failed to initialize RNCryptor.'), None))

    # Encrypt the message
    
    try:
        msg_enc = cryptor.encrypt(msg, pw)
    except:
        return((natmsgclib.print_err(10900, 'Failed to execute ' \
            + 'RNCryptor for the main message.'), None))

    ##------------------------------------------------------
    #                                        encrypt the subject and reply-to
    ##------------------------------------------------------
    # CHRIS NOW FINDS THE BASE64 OF THE ENCRYPTED FILE,
    # SO DO THE SAME HERE UNTIL HE CHANGES HIS FORMAT.
    natmsgclib.debug_msg(1, 'Encrypting the subject and reply-to fields...')
    if subject is None:
        subject = ''

    if reply_to is None:
        reply_to = ''

    subject_reply_to = json.dumps({"subject": subject,
        "replyto": reply_to}, indent=None, separators=(',', ':'))
    try:
        subject_reply_to_enc_b64 = base64.b64encode(
            cryptor.encrypt(subject_reply_to, pw))
    except:
        e = str(sys.exc_info()[0:2])
        return((natmsgclib.print_err(
            11000,
            'Failed to execute RNCryptor for the subject '
            + 'line and reply-to fields. ' + e), None))

    natmsgclib.debug_msg(9, 'Msg contents: ' + repr(msg_enc))

    # ------------------------------------------------------
    # Slice the encrypted message into 3 (shard_count) pieces/shards:
    natmsgclib.debug_msg(1, 'Slicing the main message into shards...')
    preamble_chunks = None
    pad_count, preamble_chunks = natmsgclib.nm_slice( \
        msg_enc[0: (outbound_shard_count * max_preamble_shard_size)], 
        shard_count=outbound_shard_count)

    if pad_count < 0:
        return((natmsgclib.print_err(11100, 'I could not get the msg slices.'), None))

    if natmsgclib.VERBOSITY > 8:
        natmsgclib.debug_msg(6, 'Here are the contents of the slices:')
        for tmp in preamble_chunks:
            natmsgclib.debug_msg(6, '  ' + repr(tmp))

    #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
    # Calculate the parity block and write shards to disk.
    natmsgclib.xor_and_write(fname_prefix=metadata_prefixes['preamble'],
        msg_chunks=preamble_chunks, out_dir=outbound_staging_dir)
    
    preamble_chunks = None # get from disk now--include the parity block
    ##------------------------------------------------------
    ##         BIG SHARDS
    ## If the file size was bigger than the standard 
    ## preamble, then make a big shard here.
    big_shards_exist = False
    if len(msg_enc) > (max_preamble_shard_size * outbound_shard_count):
        big_shards_exist = True
        # create a big shard
        big_chunks = None
        pad_count, big_chunks = natmsgclib.nm_slice( \
            msg_enc[(outbound_shard_count * max_preamble_shard_size): ], 
            shard_count=outbound_shard_count)
        
        if pad_count < 0:
            return((natmsgclib.print_err(11200, 'I could not get the msg slices.'), None))
        
        big_chunks_exist = True

        natmsgclib.debug_msg( 3, 'Here are the sizes of the big shards:')
        for tmp in big_chunks:
            natmsgclib.debug_msg(2, '   ' + repr(len(tmp)))

        #msg_enc_b64 = None # free mem
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
        # Calculate the parity block and write shards to disk.
        natmsgclib.xor_and_write(fname_prefix=metadata_prefixes['big'],
            msg_chunks=big_chunks, out_dir=outbound_staging_dir)
    
        big_chunks = None # get from disk now--include the parity block

    ##------------------------------------------------------
    ##------------------------------------------------------
    ##------------------------------------------------------
    ## Encrypt the first password with the key-encryption-key:
    ##  (the key encryption key, kek, is the 'passpass' in Chris' terminology).
    ## Encrypt the password with the kek (both are used in base64 format)
    natmsgclib.debug_msg(
        1,
        'Encrypting the password with the key encryption key...')
    try:
        pw_enc = cryptor.encrypt(pw, kek)
    except:
        return((natmsgclib.print_err(11300, 'Failed to execute RNCryptor to encrypt ' \
            + 'the first password.'), None))

    ##------------------------------------------------------
    ##------------------------------------------------------
    ## base64 the encrypted password.  Chris will eventually
    ## remove the extra layer of base64, but for now
    ## add another layer of base 64 to the password, and yet
    ## another layer to the parity block for the password only.
    
    pw_enc_b64 = base64.b64encode(pw_enc)
    pw_enc = None # Avoid using the wrong thing.
    ##------------------------------------------------------
    # Slice the encrypted pw into 3 (shard_count) pieces/shards:
    pw_chunks = None
    pad_count = None
    pad_count, pw_chunks = natmsgclib.nm_slice(pw_enc_b64, outbound_shard_count)

    if pad_count < 0:
        return((natmsgclib.print_err(11400, 'I could not slice the ' \
            + 'password into pieces.'), None))

    # ---------------------------------------------------
    # Calculate the parity block for the password shards and write shards to disk:
    # This reads the encrypted data, so writing to disk should be OK.
    # I will attempt to securely erase, even though it might not work
    # on some SSD drives.
    natmsgclib.xor_and_write(fname_prefix=metadata_prefixes['password'],
        msg_chunks=pw_chunks, out_dir=outbound_staging_dir)

    pw_chunks = None # get from disk

    ## To Do: maybe split this functions here to facilitate
    ## restarting after a crash that happens in the middle of sending.
    ########################################################################
    ########################################################################
    ########################################################################
    #                                                Push Shards to Shard Servers and
    #                                            Prepare the (outbound) Metatdata List
    # 
    # I now have password shards on disk with short names that indicate which
    # shard they are.
    # I generate a shard ID for each shard and call a routine to push it to
    # a shard server.
    #
    # (I will need to add another loop 
    # around each of the following subparts of the 'j'
    # loop... to handle failed connections to shard servers)
    natmsgclib.debug_msg(
        1,
        'Preparing the metadata and pushing shards to shard servers...')
    sent = False
    # url_array is the list of URLs (and related data) for shards that have been 
    # successfully pushed to shard servers.
    #url_array = [] 
    sargs_array = []
    #
    for j in range(outbound_shard_count + 1):

        shard_id = natmsgclib.nm_gen_shard_id()
        if j == outbound_shard_count:
            shard_letter = 'X'
        else:
            ##shard_letter = chr(ord('a') + j)
            shard_letter = str(j + 1)

        #-  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  
        # Password shards (will eventually choose shard servers
        # with higher trust rating) and get the input shards from
        # an array in RAM... so leave the duplicated logic here.
        #
        # dtmp wil save some info that will go into url_array.
        # This will eventually select a web host from the serverFarm list.
        shard_id = natmsgclib.nm_gen_shard_id()
        if j == outbound_shard_count:
            shard_letter = 'X'
        else:
            ##shard_letter = chr(ord('a') + j)
            shard_letter = str(j + 1)

        ##############################################################
        # create three sets of sargs (ShardSendQueueArgs):
        # one for password shards,
        # one for small shards,
        # one for large shards.
        #
        # THIS PART NEEDS TO CHANGE TO USE SHARD SERVERS FROM
        # THE SERVER FARM LIST:
        # THIS PART NEEDS TO CHANGE TO USE SHARD SERVERS FROM
        # THE SERVER FARM LIST:
        sargs = natmsgclib.ShardSendQueueArgs(
            web_host='https://shard01.naturalmessage.com',
            shard_id=shard_id, 
            input_fpath=os.path.join(
                outbound_staging_dir, metadata_prefixes['password']
                + shard_letter),
            wrk_dir=outbound_staging_dir,
            add_proof_of_work=True)

        sargs_array.append(sargs)
        # - - - - 
        # This will eventually select a web host from the serverFarm list.
        shard_id = natmsgclib.nm_gen_shard_id()
        # use the same shard_letter as above.
        sargs = natmsgclib.ShardSendQueueArgs(web_host='https://shard01.naturalmessage.com',
            shard_id=shard_id, 
            input_fpath=os.path.join(outbound_staging_dir, metadata_prefixes['preamble'] \
                + shard_letter), wrk_dir=outbound_staging_dir, add_proof_of_work=True)

        sargs_array.append(sargs)

        # - - - - 
        if big_shards_exist:
            # This will eventually select a web host from the serverFarm list.
            shard_id = natmsgclib.nm_gen_shard_id()
            # use the same shard_letter as above.
            sargs = natmsgclib.ShardSendQueueArgs(web_host='https://shard01.naturalmessage.com',
                shard_id=shard_id, 
                input_fpath=os.path.join(outbound_staging_dir, metadata_prefixes['big'] \
                + shard_letter),
                wrk_dir=outbound_staging_dir, add_proof_of_work=True)

            sargs_array.append(sargs)

    # I have now added some dictionary objects to sargs_array to define
    # what I want to push to the Internet.

    # send arguments to threads to send the shards.
    rc = nm_send_shards(outbound_staging_dir, sargs_array)
    if rc != 0:
        return((natmsgclib.print_err(11500, 'The process to send the shards via ' \
        + 'threads failed.'), None))

    #----------------------------------------------------------------------
    # 
    #-----------------------------------------------------------------------
    #        Finish and Write the outgoing Shard Metadata (smd, shard_metadata)
    #
    # I already have the final list of shards in url_array, but I need to
    # add details, like the privacy notice, KEK, encrypted stuff (subject,
    # reply_to, dest box id).
    #
    # Chris built the first part of the smd metadata in a specific order
    # in the original Mac OS X client, so follow that order here:
    smd_str_array = [SMD_PREAMBLE]
    # Note that the SMD_PREAMBLE introduces the ['meta'] tag, then
    # subject_reply_to_enc_b64 contains just a base64 string that
    # represents encrypted JSON for the subject and reply to.
    smd_str_array.append( subject_reply_to_enc_b64.decode('utf-8') \
        + '","privacyNotice":"' + privacy_notice \
        + '","passpass":"' + kek.decode('utf-8') \
        + '","parameters":[')

    # The URLs might be in a specific order in the original client,
    # I haven't tested it yet.  The goal is for all client behavior
    # to be the same to avoid accidental client signatures.
    u_str = ''
    ##for u in url_array:
    for sa in sargs_array:
        u = {'path':os.path.basename(sa.input_fpath),
            'key': sa.shard_id,
            'resource':sa.web_host}
        if u_str != '':
            # commas between statements after the first one
            smd_str_array.append(',')

        u_str = json.dumps(u, sort_keys=True, indent=None, separators=(',', ':'))
        smd_str_array.append(u_str)

    smd_str_array.append(']}')

    # The pieces of the shard metadata are now in smd_str_array.
    # Chris puts the SMD in base64 for some reason, so do it here.
    cargo_bytes=base64.b64encode(bytes(''.join(smd_str_array), 'utf-8'))

    natmsgclib.debug_msg( 4, 'The shard metadata (with added formatting) is:\n' \
        + cargo_bytes.decode('utf-8'))
        #+ json.dumps(json.loads(''.join(smd_str_array)), indent=2))

    ########################################################################
    #                                    Send Shard Metadata (SMD) to the server

    natmsgclib.debug_msg(1, 'Pushing metadata to the directory server...')

    err_nbr, err_msgd = natmsgclib.nm_smd_create( \
        web_host=host + ':' + str(port_nbr),
        dest_box_id=dest_box_id,
        cargo_bytes=cargo_bytes,
        add_proof_of_work=True)
    if err_nbr != 0:
        print(err_msgd)
        if not batch:
            input('Press any key to continue')
        return((natmsgclib.print_err(11600, str(err_msgd)), None))

    else:
        status=None
        try:
            status = err_msgd['status']
        except:
            return((natmsgclib.print_err(11700, 'I did not find the status value in the ' \
                + 'JSON returned when created SMD.'), None))

        smd_id = err_msgd['smd_id']

        # To Do: use server info from the current identity
        if old_school:
            old_school_base = 'smd=' + smd_id + '&p=' + str(port_nbr) + '&s=' + host[8:]
            old_school_link = 'natmsg://' + base64.b64encode( \
                bytes(old_school_base , 'utf-8')).decode('utf-8')
            natmsgclib.debug_msg( 2, 'SUCCESS.  The server returned smd_id: ' + smd_id \
                + ' and old-school link ' + old_school_link)
        else:
            # non old-school
            natmsgclib.debug_msg( 2, 'SUCCESS.  The server returned smd_id: ' + smd_id)


    #---------------------------------------------------------------------
    # clean the outbound temp files (MOVE THIS UP HIGHER)
    # to do: move this to a higher level function
    # to do: MODIFY THIS TO SAVE TO THE 'SENT' FOLDER IF OPTIONS SAY TO DO SO    
    # to do: MODIFY THIS TO SAVE TO THE 'SENT' FOLDER IF OPTIONS SAY TO DO SO    
    # to do: MODIFY THIS TO SAVE TO THE 'SENT' FOLDER IF OPTIONS SAY TO DO SO    
    # to do: MODIFY THIS TO SAVE TO THE 'SENT' FOLDER IF OPTIONS SAY TO DO SO    
    # to do: MODIFY THIS TO SAVE TO THE 'SENT' FOLDER IF OPTIONS SAY TO DO SO    
    # to do: MODIFY THIS TO SAVE TO THE 'SENT' FOLDER IF OPTIONS SAY TO DO SO    
    # to do: MODIFY THIS TO SAVE TO THE 'SENT' FOLDER IF OPTIONS SAY TO DO SO    
    # xxx

    if delete_temp_files:
        natmsgclib.nm_remove_temp_dir(outbound_staging_dir)

    return((0, old_school_link))


########################################################################
########################################################################
########################################################################
########################################################################
########################################################################
########################################################################
########################################################################
def nm_receive_shards(out_dir, arg_array):
    """
    Given a list of queue_arg objects, start a thread and fetch the shard.
    This will also record status messages until all the messages
    have been read or until the process reached the maximum number
    of attempted downloads.
    """

    global shard_receive_queue

    # Put all the URLS for this message into the queue
    message_received = False
    for sa in arg_array:
        # start a thread
        t = natmsgclib.ThreadShardReceive(shard_receive_queue)
        #t.setDaemon(True)
        t.start()
        # Put the shard arguments into the queue.
        shard_receive_queue.put(sa)
        # I could sleep here if there are too many thread running at a time
        if shard_receive_queue.qsize() > 4:
            sleep(2)
        if shard_receive_queue.qsize() > 7:
            sleep(10)
        if shard_receive_queue.qsize() > 10:
            sleep(40)

    # show_shard_status will loop until shards are all received:
    natmsgclib.show_shard_status(wrk_dir=out_dir, shard_args=arg_array) 

    receive_attempts = 0
    while not message_received:
        # wait till all is done
        natmsgclib.debug_msg(4, 'Approximate queue size (not reliable): ' \
            + str(shard_receive_queue.qsize()))

        shard_receive_queue.join() # safety measure to block until threads are done
        success_count = 0
        failed_count = 0

        #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
        # Test thread status in status files.
        # Rethread if need be.
        for sa in arg_array:
            # For each shard_ID, verify that the status is 'received'. If
            # status is 'failed', then resend.  If it has been more than
            # 5 minutes, resend (allow time for slow uploads?).
            status_fname=os.path.join(out_dir, sa.shard_id + '.status')
            st = None
            status_json = None
            try:
                fd_status = open(status_fname, 'r')
                status_json = json.loads(fd_status.read())
            except:
                e = str(sys.exc_info()[0:2])
                print(e)
                try:
                    fd_status.close()
                except:
                    pass
            else:
                fd_status.close()

            try:
                st = status_json['status']
            except:
                e = str(sys.exc_info()[0:2])
                print(e)

            if st is not None:
                if st == 'received':
                    success_count += 1
                    natmsgclib.debug_msg(5, 'Shard receive status on disk indicates success.')
                elif st == 'failed':
                    failed_count += 1
                    # The previous shard-send failed.
                    # Update the status to 'sending' and try again.
                    natmsgclib.nm_write_shard_status(status_fname, 'refetching')

                    natmsgclib.debug_msg(2, '=== Refetching the shard (maybe the shard server ' \
                        + 'during the testing period is down temporarily for maintenance).')
                    t = natmsgclib.ThreadShardReceive(shard_receive_queue)
                    #t.setDaemon(True)
                    t.start()
                    shard_receive_queue.put(sa) # this is wrong??, put the current arg object
                else:
                    natmsgclib.debug_msg(5, 'The shard status in the status file is not ' \
                        + '"received" or "failed": ' + str(st))
            else:
                natmsgclib.debug_msg(5, 'Could not get the shard status from the status ' \
                    + 'file for: ' + sa.shard_id + '. This should probably raise and exception.')

        receive_attempts += 1
        finalized_count = success_count + failed_count
        if finalized_count == len(arg_array):
            message_received = True
        else:
            natmsgclib.debug_msg(
                4,
                'Not all shards ready.  Success count ' + str(success_count))

        if receive_attempts > 5:
            natmsgclib.print_err(
               11900,
                'There were too many receive attempts. Fetch failed.')
            break # change this to a return when I refactor ## To Do: change to return()

        if not message_received:
            # wait before trying again
            time.sleep(10)            

    print('===== everything has been received')
    return(0)
########################################################################
########################################################################
#                                                             Process the Inbox Data
#
# (the inbox_read routine saves shard metadata to the specified directory,
# then I process each of those files to grab the shards). 
#

def read_inbox(
        fetch_id,
        private_box_id=None,
        old_school_link=None,
        max_shard_count=3,
        host='https://naturalmessage.com',
        port_nbr=443,
        delete_shard_for_testing=False,
        delete_temp_files=False):
    """
    This will either read all the messages for a given private_box_id or
    it will fetch one message associated with a shard metadata ID (smd_id).

    You must supply either a private_box_id or a smd_id.  A normal
    inbox read is performed with a private_box_id.  The smd_id would
    be used only if you received a link over old-school email that
    can be used to fetch a message from the Natural Message network. 

`    For a regular inbox read, this will:
    1) Prepare to read the inbox that is associated with
    private_box_id, and then call nm_inbox_read()
    2) Download the metatdata files that describe how to fetch
    the actual messages.
    3) Call unpack_metadata_files() to download shards, reassemble
    them, and unpack the archive files so that the messages are readable.


    The fetch_id is required: it will be used to construct a
    directory name that will contain all of the messages that
    are received in this batch.

    max_shard_count is the maximum number of original shards that we will
    expect for inbound messages (not counting parity blocks). Do not change this.

    """

    natmsgclib.debug_msg(5, '** read_inbox starting')

    shard_dir = None


    if private_box_id is None and old_school_link is None:
        return(natmsgclib.print_err(11950, 'There was no private_box_id  and ' \
            + 'no old_school link sent to read_inbox.'))
    elif old_school_link is not None:
        if old_school_link[0:9] != 'natmsg://':
            return(natmsgclib.print_err(11951, 'The old_school link sent to ' \
                + 'read_inbox did not start with natmsg://: ' + old_school_link))

    MAIL_DIR = natmsgclib.MAIN_CONFIG['SETTINGS']['mail_dir'] 
    current_identity = natmsgclib.MAIN_CONFIG['SETTINGS']['current_identity'] 

    if fetch_id is None:
        return(natmsgclib.print_err(12000, 'There was no fetch_id ' \
            + 'sent to read_inbox.'))

    #    - - - - - - - - - - - - - - - 
    # verify that directories are available
    dirs = [MAIL_DIR, 
        MAIL_DIR + os.sep + current_identity + os.sep + 'received', 
        MAIL_DIR + os.sep + current_identity + os.sep + 'incoming',
        MAIL_DIR + os.sep + current_identity + os.sep + 'sent',
        MAIL_DIR + os.sep + current_identity + os.sep + 'outgoing']

    try:
        for d in dirs:
            if not os.path.isdir(d):
                os.makedirs(d, mode=0o700, exist_ok=True)
                if platform.system().lower() != 'windows':
                    shutil.chown(d, user=pwd.getpwnam(os.getlogin())[2])

    except:
        pass # To Do: I will catch specific errors later
    #    - - - - - - - - - - - - - - - 

    inbound_save_dir = MAIL_DIR + os.sep + current_identity + os.sep \
        + 'incoming' + os.sep + fetch_id

    if not os.path.isdir(inbound_save_dir):
        try:
            os.makedirs(inbound_save_dir, mode=0o700)
        except:
            natmsgclib.print_err(12200, 'Can not create a directory to write ' \
                + 'downloaded messages: ' + inbound_save_dir)
            sys.exit(456)


    if private_box_id is not None:
        # nm_inbox_read returns an err_nbr, error message, and an array of urls 
        # that point to shards.
        err_nbr = natmsgclib.nm_inbox_read(host, port_nbr = str(port_nbr), 
            private_box_id=private_box_id, save_dir=inbound_save_dir)
        if (err_nbr !=0):
            return(natmsgclib.print_err(12300, 'Failed to read inbox.' ))
        else:
            natmsgclib.debug_msg(  2, 'Inbox read (of shard metadata) looks good...')
            # get the list of temp files and remove them
    else:
        # old school link
        tmp = None
        try:
            tmp = base64.b64decode(bytes(old_school_link[9:], 'utf-8')).decode('utf-8')
        except:
            return(natmsgclib.print_err(12307, 'The link could not be decoded. ' \
                + 'Be sure that you copied the full link.'))

        decoded_opts = tmp.split('=')
        old_school_opts = []
        for t in decoded_opts:
            old_school_opts.extend(t.split('&'))

        smd_id = old_school_opts[1]
        port_nbr = old_school_opts[3]
        host = 'https://' + old_school_opts[5]
        err_nbr = natmsgclib.nm_inbox_read(host , port_nbr= str(port_nbr), 
            smd_id=smd_id, save_dir=inbound_save_dir)
        if (err_nbr !=0):
            return(natmsgclib.print_err(12300, 'Failed to read inbox.' ))
        else:
            natmsgclib.debug_msg(  2, 'Inbox read (of shard metadata) looks good...')
        
        

    # I now have the *shard_metadata* files (not the shards) downloaded to 
    # the inbound_save_dir.
    rc, old_school_link = unpack_metadata_files(inbound_save_dir, private_box_id, 
        fetch_id, max_shard_count=3, delete_shard_for_testing=False, 
        delete_temp_files=delete_temp_files)

    return(rc)
    ######################################################################
    ######################################################################
    ######################################################################
    ######################################################################
    ######################################################################
def unpack_metadata_files(inbound_save_dir, private_box_id, fetch_id, 
    max_shard_count=3, delete_shard_for_testing=False,
    delete_temp_files=False):
    """
    After inbox_read runs and the metadata files have been downloaded,
    This will scan the download directory and fetch the shards
    for each shard_metadata file, then reassemble them into archived
    messages.

    This function produces a status file for each shard metadata file to 
    indicate which ones have been started and finished or are pending.

    This will initially be called by  read_inbox() and then
    I will build something to run from the main menu to call this
    to get incomplete downloads.

    If this is called on an existing directory that remained on disk
    after a hardware failure, the fetch_id should be sent to this
    with the proper ID for whatever was on disk:
    
         fetch_id = os.path.basename(os.path.dirname(old_dir_with_numeric_001))

    The inbound_save_dir might look something like this (on UNIX):
            ~/nm_mail/Identity1/incoming/20150223_181756.95
    where the last part starting with 2015 (or maybe tmp_2015)  is 
    usually the fetch_id.

    This returns a tuple: (return_code, old_school_link).  The link
    will be none if this is not a message via the old_school transport.
    """
    global metadata_prefixes

    old_school_link = None 
    save_temp_dirs = [] # a list of temp directories that I will need to delete

    natmsgclib.debug_msg(5, '** unpack_metadata_files starting')

    # Parse the date from the fetch_id
    msg_date = fetch_id[0:4] + '/' + fetch_id[4:6] + '/' + fetch_id[6:8]  \
        + ' ' + fetch_id[9:11] + ':' + fetch_id[11:13]

    if inbound_save_dir is not None:
        inbound_save_dir = os.path.expanduser(inbound_save_dir)

    MAIL_DIR = natmsgclib.MAIN_CONFIG['SETTINGS']['mail_dir']
    current_identity = natmsgclib.MAIN_CONFIG['SETTINGS']['current_identity']

    try:
        cryptor = natmsgclib.RNCrypt_bob()
    except:
        return((natmsgclib.print_err(12400, 'Failed to initialize RNCryptor.'), None))

    # I now have the *shard_metadata* files (not the shards) downloaded to 
    # the inbound_save_dir.
    #---------------------------------------------------------------------
    #---------------------------------------------------------------------
    #---------------------------------------------------------------------
    # Initialize some names that will contain either filenames
    # of downloaded shards or '' for missing shards (order is important).
    #
    password_inbound_fnames = [''] * (max_shard_count + 1)
    preamble_inbound_fnames = [''] * (max_shard_count + 1)
    big_inbound_fnames = [''] * (max_shard_count + 1)

    # Create a reverse lookup dictionary
    # to use the old 'values' and new 'keys'
    # and vice versa. I can use this to look
    # an 'path' entries in the SMD or filename
    # prefixes and determine if the thing is
    # a password shard, preamble shard, or big shard.
    rev_prefixes = {}
    for k in metadata_prefixes.keys():
        rev_prefixes.update({metadata_prefixes[k]: k})

    # To Do: scan this section and do not exit the loop
    # for invalid download file -- skip the bad item and 'continue'
    # with the next iteration.

    # To Do: scan this section and do not exit the loop
    # for invalid download file -- skip the bad item and 'continue'
    # with the next iteration.

    # To Do: scan this section and do not exit the loop
    # for invalid download file -- skip the bad item and 'continue'
    # with the next iteration.

    # To Do: scan this section and do not exit the loop
    # for invalid download file -- skip the bad item and 'continue'
    # with the next iteration.

    # Scan all the inbound directories for this batch of *shard_metadata*
    # files.
    for root, dirs, files in os.walk(inbound_save_dir):
        # The outer loop contains the directory/subdirectory name
        # in 'root' and all the file names listed in the array 'files.'

        for ddd in dirs:
            # For each subdirectory (each SMD is put into its own subdirectory, but some
            # subdirectories might not contain an SMD)
            # Prepare to read the shard metadata into a JSON object.

            natmsgclib.debug_msg( 5, 'Starting scan of inbound save loop for: ' + ddd)

            if ddd == '':
                current_dir = inbound_save_dir
            else:
                current_dir = inbound_save_dir + os.sep + ddd

            # The shard_metadata_staged file is created by natmsgclib.nm_inbox_read
            smd_fname = current_dir + os.sep + 'shard_metadata_staged'

            smd_data = None
            if os.path.isfile(smd_fname):
                try:
                    fd = open(smd_fname, 'rb')
                except:
                    pass
                else:
                    smd_data = fd.read()
                    fd.close()

            if smd_data is None:
                #print('Warning. There were no metadata files in this directory: ' + smd_fname)
                pass
            else:
                # Read the JSON inside the downloaded shard metadata file.
                smd_json = None
                ###smd_json = json.loads(smd_data.decode('utf-8')) # feb23, 2014 for mac os
                try:
                    # unwrap the base64
                    smd_json = json.loads(base64.b64decode(smd_data).decode('utf-8'))
                except:    
                    try:
                        # not wrapped in base64
                        smd_json = json.loads(smd_data.decode('utf-8')) # not wrapped in base64
                    except:
                        # one time test for a double wrap base64
                        smd_json = json.loads(
                            base64.b64decode(
                                base64.b64decode(smd_data)).decode('utf-8'))
                        pass


            if smd_data is not None and smd_json is None:
                print('WARNING. Could not get the shard metadata JSON from the ' \
                    + 'downloaded metadata: ' + str(smd_data))
            elif smd_data is not None and smd_json is not None:
                # See if there is an smd.status file, else create one. 
                # These files facilitate restart after a power failure.
                new_smd = True
                smd_status = None
                smd_status_fname = os.path.join(current_dir, 'smd.status')
                fname_extract_dir = os.path.join(current_dir, 'extract')
                if not os.path.isdir(fname_extract_dir):
                    os.makedirs(fname_extract_dir)

                if os.path.isfile(smd_status_fname):
                    new_smd = False
                    with codecs.open(smd_status_fname, 'r', 'utf-8') as fd_smd_status:
                        smd_status = json.loads(fd_smd_status.read())
                        smd_state = smd_status['state']
                        shard_dir = smd_status['shard_dir']
                else:
                    # Create a new shard_metadata status file
                    shard_dir = tempfile.mktemp(prefix='shardtmp-', dir=current_dir)
                    smd_state = 'initializing'
                    smd_status = {'state':smd_state, 'shard_dir': shard_dir}
                    with codecs.open(smd_status_fname, 'w', 'utf-8') as fd_smd_status:
                        fd_smd_status.write(json.dumps(smd_status))

                # I now have a dictionary object called smd_status
                # ------------------------------------------------
                        
                # Note that this shard_dir is in the loop and can change many times!!
                # In need to know all of the temp locations so that I can delete them later.
                save_temp_dirs.append(shard_dir)
                natmsgclib.debug_msg(3, 'Shard dir is: ' + shard_dir)
    
                fname_pw_reassembled =  shard_dir + os.sep + 'password' 
                fname_preamble_reassembled =  shard_dir + os.sep + 'preamble' 
                fname_big_reassembled =  shard_dir + os.sep + 'big' 
                fname_msgarchive_reassembled =  shard_dir + os.sep + 'msg' 
    
                if os.path.isfile(fname_msgarchive_reassembled):
                    if os.stat(fname_msgarchive_reassembled).st_size > 0:
                        # The final archive has already been reassembled, so skip the
                        # remainder of this iteration (maybe this is recovery from
                        # a power failure).
                        natmsgclib.debug_msg(
                            5,
                            'Skipping reassembly of a message that '
                            + 'already exists: '
                            + fname_msgarchive_reassembled)
                        next
                    else:
                        # Rename a half-assed file.  
                        # It is possible that the file is being processed by another instance
                        # of the application?
                        ##roll_gdg(fname_msgarchive_reassembled)
                        os.remove(fname_msgarchive_reassembled)
    
                # Read the URL list from the shard_metadata
                url_array = smd_json['parameters']
                kek_from_smd = smd_json['passpass']
                try:
                    subject_reply_to_enc = smd_json['meta']
                except:
                    print('WARNING: there was an error getting the subject line and reply-to, ' \
                        + ' but I will keep processing.  The keys in the json are:')
                    for z in smd_json.keys():
                        print('    ' + z)
                    print('... and the smd_json was: ' + str(smd_json))
                    junk = input('press any key...')

    
                #---------------------------------------------------------------------
                #---------------------------------------------------------------------
                #---------------------------------------------------------------------
                # --------- I now have url_array with the urls for the shards
                # --------- for one message.
                # --------- Run three blocks of code to fetch shards:
                # --------- one for the password, one for preamble, one for big shards.
                # --------- but check the state for each shard to see if it has been 
                # --------- fetched.
                arg_array = []
                for u in url_array:
                    # Check the status of this shard.  If it is not completed,
                    # fetch it and update the status.
                    shard_id = u['key']  # from smd
                    shard_status_fname = os.path.join(shard_dir, shard_id + '.status')
                    err_nbr, shard_status = natmsgclib.get_status(shard_status_fname)
                    if shard_status is None:
                        # On first run, there will be no status file.  If this is recovery
                        # after a power failure, there might be a status file.
                        shard_status = {'status':'fetching'}
    
                    try:
                        ss = shard_status['status']
                    except:
                        # The JSON does not have the 'status' key, which is a server mistake,
                        # but I will try to keep processing and assume that I did not lose an EOF.
                        pass
                    else:
                        
                        if shard_status['status'] != 'received':
                            # Add this shard to the queue to be fetched.
                            shard_args = natmsgclib.ShardReceiveQueueArgs(web_host=u['resource'],
                                shard_id=u['key'], output_fname=u['path'],
                                out_dir=shard_dir)
    
                            arg_array.append(shard_args)
                        else:
                            natmsgclib.debug_msg(4,'This shard has already been received: ' \
                                + shard_id)
                            next
                # end of for-loop
    
                # Submit the threads and download the shards
                if len(arg_array) > 0:
                    rc = nm_receive_shards(out_dir=shard_dir, arg_array=arg_array)
                    if rc !=0:
                        # Maybe I should keep processing to avoid losing other SMD data
                        natmsgclib.print_err(3090, 'Warning: Fetch of shards failed.  See ' \
                        + shard_dir + '.  I will keep processing to see if I can get any other ' \
                        + 'messages (if there are any).')
    
    
                # Build an ordered array of shard filenames that puts the parity
                # block in a fixed location and leaves entries missing if the 
                # shard is not available--each array will be aligned with
                # the output filenames that they should have when reassembled.
                #
                # Use reverse lookup to know the category (password, preamble, big)
                # associated with a URL.
                for u in url_array:
                    # This section contains the hoakey variable length reverse 
                    # lookup to match OS X format.
                    natmsgclib.debug_msg( 5, 'Reading URL from the shard metdata file: ' \
                        + u['path'] + ', ' + u['key'])
    
                    if u['path'][0:2] in rev_prefixes.keys():
                        ##if rev_prefixes[u['path'][0:2]] == 'password':
                        ##tmp_idx = ord(u['path'][2:3]) - ord('a')
                        tmp_idx = ord(u['path'][2:3]) - ord('1')
                        if tmp_idx > max_shard_count:
                            # The parity block goes in the last array slot.
                            tmp_idx = max_shard_count
    
                        password_inbound_fnames[tmp_idx] = shard_dir + os.sep + u['path']
                    elif u['path'][0:6] in rev_prefixes.keys():
                        ##elif rev_prefixes[u['path'][0:6]] == 'preamble':
                        ##tmp_idx = ord(u['path'][6:7]) - ord('a')
                        tmp_idx = ord(u['path'][6:7]) - ord('1')
                        if tmp_idx > max_shard_count:
                            tmp_idx = max_shard_count
    
                        preamble_inbound_fnames[tmp_idx] = shard_dir + os.sep + u['path']
                    elif u['path'][0:4] in rev_prefixes.keys():
                        ##elif rev_prefixes[u['path'][0:4]] == 'big':
                        tmp_idx = ord(u['path'][4:5]) - ord('1')
                        if tmp_idx > max_shard_count:
                            tmp_idx = max_shard_count
    
                        big_inbound_fnames[tmp_idx] = shard_dir + os.sep + u['path']
                    else:
                        return((natmsgclib.print_err(3100, 'Unexpected type in smd file: ' \
                            + u['path']), None))
                
    
                #---------------------------------------------------------------------
                #---------------------------------------------------------------------
                # REASSEMBLE THE FILES HERE
                #---------------------------------------------------------------------
                # Pass all the password shard filenames to the joiner to reassemble 
                # and un-base64.
                # Pass all the preamble shard filenames to the joiner.
                # Pass all the big      shard filenames to the joiner.
                #
                natmsgclib.debug_msg( 2, 'Reassembling the shards (unpack_metadata_files)...')
    
    
                natmsgclib.debug_msg( 4, 'Password  fname array before reassembly ' \
                    + str(password_inbound_fnames))
                # Reassemble the password shards if needed
                # (maybe this is a rerun and the password was already reassembled)
                pw_reassemble_needed = False
                if not os.path.isfile(fname_pw_reassembled):
                    pw_reassemble_needed = True
                else:
                    if os.stat(fname_pw_reassembled).st_size == 0:
                        pw_reassemble_needed = True
                    
                if pw_reassemble_needed:
                    err_nbr = natmsgclib.nm_reassemble_shards(password_inbound_fnames, \
                        fname_pw_reassembled, parity_version=1,
                        delete_shard_for_testing=delete_shard_for_testing)
                    if err_nbr != 0:
                        natmsgclib.print_err(13100, 'Reassembly of password failed.' \
                            + str(err_nbr))
                        continue
    
                natmsgclib.debug_msg( 4, 'Preamble fname array before reassembly ' \
                    + str(preamble_inbound_fnames))

                # Reassemble the preamble shards:
                # (maybe this is a rerun and the preamble was already reassembled)
                preamble_reassemble_needed = False
                if not os.path.isfile(fname_preamble_reassembled):
                    preamble_reassemble_needed = True
                else:
                    if os.stat(fname_preamble_reassembled).st_size == 0:
                        preamble_reassemble_needed = True
    
                if preamble_reassemble_needed:
                    err_nbr = natmsgclib.nm_reassemble_shards(preamble_inbound_fnames,
                        fname_preamble_reassembled, 
                        delete_shard_for_testing=delete_shard_for_testing, parity_version=1)
                    if err_nbr != 0:
                        natmsgclib.print_err(13200, 'Reassembly of preamble failed.' \
                            + str(err_nbr))
                        continue
    
                # Reassemble the big shards (if there are any):
                # Reassemble the big shards:
                # (maybe this is a rerun and the big was already reassembled)
                natmsgclib.debug_msg( 4, 'BIG fname array  before reassembly ' \
                    + str(big_inbound_fnames))

                big_reassemble_needed = False
                if not os.path.isfile(fname_big_reassembled):
                    big_reassemble_needed = True
                else:
                    if os.stat(fname_big_reassembled).st_size == 0:
                        big_reassemble_needed = True
    
                if big_reassemble_needed:
                    if len(big_inbound_fnames[0]) > 0:
                        err_nbr = natmsgclib.nm_reassemble_shards(big_inbound_fnames,
                            fname_big_reassembled , 
                            delete_shard_for_testing=delete_shard_for_testing, parity_version=1)
                        if err_nbr != 0:
                            natmsgclib.print_err(13400, 'Reassembly of big shards failed.' \
                                + str(err_nbr))
    
                natmsgclib.debug_msg(
                    3,
                    'The temporary shard download directory is: ' + shard_dir)
    
                # # #---------------------------------------------------------------------
                # Glue the preamble and big shard if there is a big shard
                fd_preamble_in = open(fname_preamble_reassembled, 'rb')
                fd_msgarchive = open(fname_msgarchive_reassembled , 'wb+')
                fd_msgarchive.write(fd_preamble_in.read())
                fd_preamble_in.close()
                if len(big_inbound_fnames[0]) > 0:
                    fd_big_in = open(fname_big_reassembled, 'rb')
                    fd_msgarchive.write(fd_big_in.read())
                    fd_big_in.close()
    
                fd_msgarchive.close()
    
                #---------------------------------------------------------------------
                # Decrypt, and un-gzip the current archive/message.
                # The reassembled password needs to be unbase64 before it is decrypted, but
                # the KEK is stored unencrypted, in its original form (in the shard metadata).
                natmsgclib.debug_msg( 2, 'Decrypting the files...')
                fd_pw_in = open(fname_pw_reassembled, 'rb')
                fd_msgarchive = open(fname_msgarchive_reassembled, 'rb')
                fd_msgarchive_out = open(fname_msgarchive_reassembled + '.decrypted', 'wb')
    
                natmsgclib.debug_msg( 4, 'Testing pw and kek... pw inputfname ' \
                        + repr(fname_pw_reassembled) + ' kek value: ' + repr(kek_from_smd))

                # # old style before binary transfer
                # # (Chris should remove the extra base64 layer)
                pw = cryptor.decrypt(base64.b64decode(fd_pw_in.read()), kek_from_smd)
                # #pw = cryptor.decrypt(fd_pw_in.read(), kek_from_smd)
    
                try:
                    # #### old style before binary transfer
                    # ###fd_msgarchive_out.write(gzip.decompress(cryptor.decrypt( \ 
                    # ###    base64.b64decode(fd_msgarchive.read()), pw)))
                    fd_msgarchive_out.write(gzip.decompress(cryptor.decrypt( \
                        fd_msgarchive.read(), pw)))
                except:
                    e = str(sys.exc_info()[0:2])
                    try:
                        fd_pw_in.close()
                        fd_msgarchive.close()
                        fd_msgarchive_out.close()
                    except:
                        pass
    
                    natmsgclib.print_err(13500, 'There was error decrypting and unzipping ' \
                        + 'the message. It could be that the sender used a different ' \
                        + 'version of the file format. It could be a reassembly problem, ' \
                        + 'or maybe somebody sent you garbage. ' + e)
                    continue
    
                fd_pw_in.close()
                fd_msgarchive.close()
                fd_msgarchive_out.close()
    
                # Copy the archive file to the permanent 'received' box. pw
                received_fname = MAIL_DIR + os.sep + current_identity + os.sep \
                    + 'received' + os.sep + fetch_id + ddd + '.json'
                meta_fname_out = MAIL_DIR + os.sep + current_identity + os.sep \
                    + 'received' + os.sep + fetch_id + ddd + '.meta.json'
                natmsgclib.debug_msg(2, 'Saving received message: ' + received_fname)
                shutil.copyfile(fname_msgarchive_reassembled + '.decrypted', \
                    received_fname)
    
                #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
                #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
                meta_json_d = {}
                #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
                # Good so far.
                # Capture inbound metadata that came from the shard metadata file
                # (as opposed to coming from the reassembled archive file):
                try:
                    subject_reply_to = cryptor.decrypt(
                        base64.b64decode(
                            bytes(subject_reply_to_enc, 'utf-8')),
                        pw).decode('utf-8')
                    meta_json_d.update({'meta': json.loads(subject_reply_to)})
                    meta_json_d.update({'date': msg_date})
                except:
                    e = str(sys.exc_info()[0:2])
                    print('WARNING: I could not decrypt the subject and '
                        + 'reply-to metadata file into JSON. ' + e)
                else:
                    with open(meta_fname_out, 'w') as fd:
                        # Write json to a text file without extra whitespace.
                        fd.write(json.dumps(meta_json_d, separators=(',',':')))
    
                #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
                #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
                # Read the 'meta2' file for the inbound message -- it contains
                # some things that were not in the shard_metadata that the sender
                # uploads, but stuff that the server adds to the JSON.
                # The 'meta2' file is created by nm_inbox_read().
                meta_fname_in = current_dir + os.sep + 'meta2'
                try:
                    with open(meta_fname_in, 'r') as fd:
                        meta_tmp = fd.read()
    
                except:
                    print('WARNING. There was an error trying to get '
                        + 'metadata, but I will continue '
                        + 'processing to avoid losing messages. I was '
                        + 'trying to read: ' + meta_fname_in)
                try:
                     tmp_d = json.loads(meta_tmp)
                except:
                    tmp_d = {}
                    print('WARNING: I could convert the subject line to '
                        + 'JSON.  I will omit the subject line')
    
                if 'msg_snippet' in tmp_d.keys():
                    meta_json_d.update({'msg_snippet': tmp_d['msg_snippet']})

                if 'dest' in tmp_d.keys():
                    meta_json_d.update({'dest': tmp_d['dest']})
                else:
                    input('I did not find the destination box ID in keys.  '
                        + 'This is probably programmer error: '
                        + str(tmp_d) + os.linesep + 'Press any key to continue...')
                #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
                #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
                #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
                #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
                #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
                #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
                #
                natmsgclib.debug_msg( 2, 'Unarchiving the files to ' + fname_extract_dir)
    
                # Extract the archive files
                # return_data will be type bytes()

                # Extract just the main message (not the attachments) and the number of
                # attachments so that
                # I can capter some of the text for the msg_meta_browswer.
                # Note about nm_archiver2: During extract, data goes to disk
                # if an output_dir is specified,
                # or to the third recturn value if not output dir is specified.
                err_nbr, err_msg, return_dict = natmsgclib.nm_archiver2(action='x', 
                    arch_fname=fname_msgarchive_reassembled + '.decrypted',
                    extract_attachments=False,
                    skip_existing=True, clobber=False)

                if err_nbr !=0:
                    natmsgclib.print_err(13600, 'The archive extraction failed: ' + err_msg)
                    continue
                else:
                    if return_dict is not None:
                        try:
                            # Attachment count goes to the meta.json to simplify the
                            # display in the msg_meta_browser.
                            meta_json_d.update({'attachment_count': return_dict['attachment_count']})
                        except:
                            pass
                        if 'msg_txt' in return_dict.keys():
                            return_data = return_dict['msg_txt']
                        else:
                            input('Temporary notice: There was no message text to preview.  ' \
                                + 'Either this is a blank message or ' \
                                + 'bad programming somewhere.\nPress any key...' + str(return_dict))
                            return_data = ''

                        try:
                            # return_data is text in bytes() format from the
                            # message to show in the inbox listing later.
                            ###snippet = base64.b64encode( \
                            ###    bytes(' '.join(natmsgclib.nm_clean_utf8_text(return_data)), \
                            ###    'utf-8')[0:200]).decode('utf-8')
                            snippet = base64.b64encode( \
                                bytes(' '.join(natmsgclib.nm_clean_utf8_text(return_data)), \
                                'utf-8')[0:200]).decode('utf-8')
                            meta_json_d.update({'msg_snippet': snippet})
                        except:
                            e = str(sys.exc_info()[0:2])
                            natmsgclib.print_err(13697, 'Failed to get the msg snippet/preview of ' \
                                + 'the text: ' + e)
                            input('Press any key to continue....')
                            continue

                        try:
                            with open(meta_fname_out, 'w') as fd:
                                # Write json to the .meta.json text file without extra whitespace.
                                fd.write(json.dumps(meta_json_d, separators=(',',':')))
                        except:
                            e = str(sys.exc_info()[0:2])
                            # It is not a big deal if the snippet can not be saved, but
                            # if the meta.json file is corrupted, that would be a problem.
                            natmsgclib.print_err(13700, 'Failed to write the inbound ' \
                                + 'message snippet to the meta.json file. ' + e)
                            input('Press any key to continue....')
                            continue

    natmsgclib.debug_msg(3, 'check out ' + inbound_save_dir)
    
    # remove the shard_dir here
    # remove the shard_dir here
    # remove the shard_dir here
    # remove the shard_dir here
    # remove the shard_dir here
    # remove the shard_dir here
    #---------------------------------------------------------------------
    if delete_temp_files:
        # Clean the inbound temp files.
        # If there were no inbound message this time, then
        # there would be no shard_dir and no need to delete anything.
        for d in save_temp_dirs:
            natmsgclib.debug_msg( 3, 'Securely removing inbound temporary files in ' + d)

            natmsgclib.nm_remove_temp_dir(d)

    return((0, old_school_link))

########################################################################
########################################################################
########################################################################
########################################################################
########################################################################
########################################################################

def nm_send_message(outbound_staging_dir, pw, kek, msg_fname=None,
    body_txt=None, reply_to_box_id=None, dest_box_id=None,
    flist=None, subject=None, batch=False, confirmation=False):
    """
    Send a message over the Natural Message Transport.

    pw is the password used to encrypt the shards, the kek is the 
    key encryption key that is used to encrypt the first password.

    body_txt is a list object containing lines of text (this function
    will add os.linesep after each line). body_txt is intended
    for the body of a reply or forwarded message.

    This returns a tuple: (return_code, old_school_link). The link
    will be None if this is not a message via the old-school transport.

    The sending process...
    nm_actions.nm_send_message()
        prepare all the arguments and directories.
        archive the input file(s) with natmsgclib.nm_archiver2().
        nm_actions.shard_and_send()
            nm_actions.nm_send_shards()
                start natmsgclib.ThreadShardSend
                put data into a ShardSendQueueArgs, which will
                execute natmsgclib.ThreadShardSend.run()
                Resend if there is an error.

    """
    # add the text edit thing here

    if flist is None:
        flist = []
    else:
        # verify that the attached files exist
        for f in flist:
            if not os.path.isfile(f):
                return((natmsgclib.print_err(13475, 'Attached filename not found: ' \
                    + f), None))

    if dest_box_id is not None:
        if dest_box_id == '':
            dest_box_id = None

    if dest_box_id == natmsgclib.RESERVED_EMAIL_DEST_ID:
        old_school = True
    else:
        old_school = False

    if not batch:
        # not batch mode
        #### if 'editor_command' not in natmsgclib.MAIN_CONFIG['SETTINGS']:
        ####     # There is no key for 'editor_command' in the options file.
        ####     # Set the editor to None here to force a search for the editor.
        ####     editor_command = None
        #### else:
        ####     editor_command = natmsgclib.MAIN_CONFIG['SETTINGS']['editor_command']


        #### if editor_command is None:
        ####     # the selection command sets the global config settings.
        ####     natmsgclib.nm_select_editor()
        ####     editor_command = natmsgclib.MAIN_CONFIG['SETTINGS']['editor_command']
        #### elif editor_command == '':
        ####     natmsgclib.nm_select_editor()
        ####     editor_command = natmsgclib.MAIN_CONFIG['SETTINGS']['editor_command']

        #### # The editor command might be bad if the user copied options 
        #### # to a new computer.
        #### if not os.path.isfile(editor_command):
        ####     natmsgclib.nm_select_editor()
        ####     editor_command = natmsgclib.MAIN_CONFIG['SETTINGS']['editor_command']

        ##tmpfname = tempfile.mktemp(prefix='msgtmp-', dir=outbound_staging_dir)
        tmpfname = os.path.join(outbound_staging_dir, '__NM.txt')

        if body_txt is None:
            fd = open(tmpfname, 'w')
            fd.write('Edit this file to create the body of your message.\n' \
                + 'Remove this line of text, then save and quit to send.')
            fd.close()
        else:
            fd = open(tmpfname, 'w')
            for l in body_txt:
                # body_txt is a list of text lines
                fd.write(l + os.linesep)
            fd.close()
            

        # to do: GET THE EDITOR name FROM MAIN_CONFIG
        #### rc = os.system(editor_command + ' ' + tmpfname)
        rc = nm_edit_file(tmpfname)
        junk = input('After you have saved your message and exited the ' \
            + 'editor program, press any key to continue...')

        # See if the message file looks like RTF
        fd = open(tmpfname, 'rb')
        dat= fd.read(5)
        fd.close()
    else:
        # batch mode.... the input message file name is required
        confirmation = False
        if not os.path.isfile(msg_fname):
            return((natmsgclib.print_err(13475, 'The input message file was not found: ' \
                + msg_fname), None))

        tmpfname = msg_fname
        fd = open(msg_fname, 'rb')
        dat= fd.read(5)
        fd.close()
        # test if it is RTF or text
        try:
            shutil.copy(msg_fname, os.path.join(outbound_staging_dir, '__NM.txt'))
        except:
            e = str(sys.exc_info()[0:2])
            return((natmsgclib.print_err(13480, 'Could not copy the input message file ' \
                + 'to the staging area: ' + e), None))

    # --   --    --   --   --   --   -   
    archive_fname = tempfile.mktemp(prefix='archivetmp-', 
        dir=outbound_staging_dir, suffix='.json')

    # --   --    --   --   --   --   -   
    # Now tmpfname is the file to send for batch or interactive.
    if dat == bytes('{\\rtf', 'utf-8'):
        tmpfname_old = os.path.join(outbound_staging_dir, '__NM.txt')
        tmpfname = os.path.join(outbound_staging_dir, '__NM.rtf')
        shutil.move(tmpfname_old, tmpfname)

    if not batch:
        if dest_box_id is None:
            # add destination
            # to do: add an option for 'enter a new id'
            # TO DO: ALLOW ENTRY OF A NEW ID BY CALLING add_contact
            # an repeating this section.
            good = False
            while not good:
                print('Note: if you do not see the destination box ID, '
                    + 'add it to the contacts '
                    + 'list from the main menu.')
                err_nbr, box_dict , descr = nm_select_contact(
                    prompt='Select the destination '
                    + '(or Q to quit):')

                if err_nbr !=0:
                    return((err_nbr, None))

                dest_box_id = box_dict['box_id']
                ## id_nbr = box_dict['id_nbr']
                # Add confirmation of destination
                rc = natmsgclib.verify_id_format(id=dest_box_id, expected_prefix='PUB')
                if rc == 1:
                    reply_to_box_id = None # force input below
                    print('The destination box ID has expired.  Try again.')
                    input('Press any key to continue...')
                    good = False
                elif rc != 0:
                    reply_to_box_id = None # force input below
                    print('The destination box ID did not have the right format.  Try again.')
                    input('Press any key to continue...')
                    good = False
                else:
                    good = True

    else:
        # For batch mode, dest_box_id should be supplied as an argument.
        if dest_box_id is None:
            return((natmsgclib.print_err(4383949, 'There was no dest_box_id sent to ' \
            + 'nm_send_message() in batch mode.'), None))

    rc = natmsgclib.verify_id_format(dest_box_id, expected_prefix='PUB')
    if rc == 1:
        return((natmsgclib.print_err(4383954, 'The destination box ID has expired: ' \
                + dest_box_id + '.'), None))
    elif rc != 0:
        return((natmsgclib.print_err(4383955, 'The destination box ID did not have ' \
            + 'the right format: ' + dest_box_id + '.'), None))

    if not batch:
        # Add subject line
        if subject is None:
            # There was no subject passed as an argument to this function,
            # so prompt the user for one:
            subject = natmsgclib.input_no_confirm(
                "Enter a subject line (it will be encrypted): ")
        
    else:
        # For batch mode, subject should be supplied as an argument.
        if subject is None:
            return((natmsgclib.print_err(4383949, 'There was no subject sent to ' \
            + 'nm_send_message() in batch mode.'), None))

    if not batch:
        # Sender box ID/reply to box id
        if reply_to_box_id is not None:
            # verify that that argument for reply to has valid form
            rc = natmsgclib.verify_id_format(id=reply_to_box_id, expected_prefix='PUB')
            if rc == 1:
                reply_to_box_id = None # force input below
                print('The box ID has expired.  Try again.')
                input('Press any key to continue...')
            elif rc != 0:
                reply_to_box_id = None # force input below
                print('The box ID did not have the right format.  Try again.')
                input('Press any key to continue...')
    

        if reply_to_box_id is None:
            # The user did not supply a reply_to_box_id as an argument, so prompt
            # the user for one...
            good = False
            cnt = 0
            while not good:
                try:
                    current_pub_box_id = \
                        natmsgclib.nm_decrypt_local_txt( \
                        natmsgclib.MAIN_CONFIG['SETTINGS']['current_pub_box_id'],
                        natmsgclib.SESSION_PW)
                except:
                    current_pub_box_id = ''
                if current_pub_box_id[0:3].upper() == 'PRV':
                    natmsgclib.debug_msg(2, 'Error, your default box ID is a private ID and ' \
                        + 'should be a public ID.')

                    current_pub_box_id = ''

                choices=[current_pub_box_id, 'Other', 'Anonymous']
                idx, reply_to_box_id = natmsgclib.nm_menu_choice(choices,
                    prompt='Enter the sender (reply-to) box ID: ')

                if reply_to_box_id is None:
                    reply_to_box_id = ''
                elif reply_to_box_id.lower() == 'anonymous':
                    reply_to_box_id = ''
                elif reply_to_box_id.lower() == 'other':
                    # Allow the user to select from existing box_ids under this identity
                    err_nbr, box_dict , descr = nm_select_contact( \
                        prompt='Select the sender (reply-to) box ID: ',
                        local_only=True)
                    reply_to_box_id = box_dict['box_id']


                # to do: add an option for adding a new box ID to the contact list 
                # then redisplay the contact selection list.

                if reply_to_box_id != '':
                    rc = natmsgclib.verify_id_format(id=reply_to_box_id, expected_prefix='PUB')
                    if rc == 1:
                        reply_to_box_id = None # force input below
                        print('The reply-to box ID is expired.  Try again.')
                        input('Press any key to continue...')
                    elif rc != 0:
                        reply_to_box_id = None # force input below
                        print('The reply-to box ID did not have the right format.  Try again.')
                        input('Press any key to continue...')
                    else:
                        good = True # anonymous sender is OK
                else:
                    good = True # anonymous sender is OK

            cnt += 1
            if cnt > 4:
                return((natmsgclib.print_err(13490, 'Too many failures'), None))
        
    else:
        current_pub_box_id = reply_to_box_id # PUB box id
        ##reply_to_box_id = sender_public_box_id # PUB box id

    # ------------- Attach files
    if not batch:
        add_more = True
        while add_more:
            if len(flist) == 0:
                prompt = 'Do you want to attach a file? (y/n): '
            else:
                prompt = 'Do you want to attach another file? (y/n): '

            if (natmsgclib.nm_confirm(prompt)):
                #xxx file browswer and add to flist
                if os.path.isdir(os.path.expanduser('~/Documents')):
                    ddd = os.path.expanduser('~/Documents')
                else:
                    ddd = os.path.expanduser('~')

                print('ddd is ' + ddd)
                fname = natmsgclib.nm_file_chooser(top=ddd, select_msg_files=False)
                if fname is not None:
                    flist.append(fname)
                else:
                    print('=== No file was selected.')
                    input('Press any key to continue...')
            else:
                add_more = False

    # ------------- Confirm before sending 
    if confirmation:
        # to do: expand this confirmation and remove the other confirmations above
        if not natmsgclib.nm_confirm('Do you want to send this message? (y/n): '):
            # the user does not want to send this
            return((0, None))
                
    # Add review /loop here

    flist.insert(0, tmpfname) # put the message text first in the list of files

    # Archive the file(s) using the NatMsg archiver:
    err_nbr, err_msg, return_dict = natmsgclib.nm_archiver2(action='c', 
        arch_fname=archive_fname,
        f_list=flist, message_included=True,
        skip_existing=True, clobber=False)
    if err_nbr != 0:
        return((natmsgclib.print_err(13500, 'The archive-creation process failed. ' \
            + err_msg), None))

    # Now send it.
    err_nbr, old_school_link = shard_and_send(archive_fname, pw=pw,  
        kek=kek, dest_box_id=dest_box_id, 
        subject=subject, reply_to=reply_to_box_id, batch=batch,
        old_school=old_school,
        outbound_staging_dir=outbound_staging_dir)

    # to do, move the 'delete temp files' from shard_and_send to here
    # and save a copy to 'SENT' if the options say to do so xxx
    # to do, move the 'delete temp files' from shard_and_send to here
    # and save a copy to 'SENT' if the options say to do so xxx
    # to do, move the 'delete temp files' from shard_and_send to here
    # and save a copy to 'SENT' if the options say to do so xxx
    # to do, move the 'delete temp files' from shard_and_send to here
    # and save a copy to 'SENT' if the options say to do so xxx
    # to do, move the 'delete temp files' from shard_and_send to here
    # and save a copy to 'SENT' if the options say to do so xxx
    return((err_nbr, old_school_link))


########################################################################

def nm_add_contact(identity_nbr=None, box_id=None):
    """
    Add a contact (public box ID, name, and optional info).

    This is called by the user to get input values, format
    the data, and update the configparser settings.

    Contacts are added under an identity, so the user either
    passes the identity number or is prompted to select it
    """

    if box_id is None:
        box_id = '' # default value for the prompt

    if box_id != '':
        rc = natmsgclib.nm_verifiy_id(box_id, expected_prefix='PUB')
        if rc != 0:
            return(natmsgclib.print_err(
                6467,
                'The box_id sent to nm_add_contact is invalid: '
                + box_id))

    if identity_nbr is None:
        current_identity = natmsgclib.MAIN_CONFIG['SETTINGS']['current_identity']
    else:
        current_identity = 'Identity' + str(identity_nbr)

    if current_identity not in natmsgclib.MAIN_CONFIG.keys():
        return(natmsgclib.print_err(6468, 'Identity in nm_add_contact is invalid: ' \
            + current_identity))
        
    #------------------------------------------------------------------------
    # Find the maximum current contact nbr for this Identity:
    #
    max_contact_nbr = 0
    for a in natmsgclib.MAIN_CONFIG[current_identity].keys():
        if a[0:21] == 'contact_public_box_id':
            id_nbr = int(a[21:])
            if id_nbr > max_contact_nbr:
                # Save the highest contact number so I know where
                # to add the next one
                max_contact_nbr = id_nbr

    # The row order of prompts and contact_keys must match.
    # Each prompt contains the prompt; 0=noninteger entry; default value
    prompts = [ \
    ('Enter the public box ID (141 bytes starting with PUB): ', 0, box_id),
    ('                Enter the nickname of the new contact: ', 0, 'NA'),
    ('                       Enter a note about the contact: ', 0, 'NA')]

    # The order of prompts and contact_keys must match
    contact_keys = ['contact_public_box_id', 'contact_nickname', 'contact_note']

    quit_now = False
    good = False
    while not good:
        answers = [''] * len(prompts)
        err_nbr, answers = natmsgclib.nm_input_list_and_confirm(prompts)
        if err_nbr != 0:
            return(err_nbr)
        elif answers[0] is None:
            # user wants to quit
            quit_now = True
            return(0) # quitting is still a nonerror
        elif answers[0] in ['', 'q', 'Q', 'quit']:
            # user wants to quit
            quit_now = True
            return(0)# quitting is still a nonerror

        # validate the box ID to see if it has a reasonable format:
        rc = natmsgclib.verify_id_format(id=answers[0], expected_prefix='PUB')
        if rc == 1:
            print('The box ID did is expired.  Try again.')
            input('Press any key to continue...')
        elif rc != 0:
            print('The box ID did not have the right format.  Try again.')
            input('Press any key to continue...')
        else:
            good = True

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
        # # ADD A CHECK FOR DUPLICATE ID
        #
        contact_dict = natmsgclib.nm_build_contact_dict(current_identity, 
            local_only=False, include_anonymous=False)
        if contact_dict is None:
            ## Unable to build the contact list.
            return(natmsgclib.print_err(6473, 'Unable to build a list of contacts ' \
                + 'to verify the new entry:. ' + e))
        else:
            for k in contact_dict.keys():
                if 'box_id' in contact_dict[k]:
                    bid = contact_dict[k]['box_id']
                    if bid == answers[0].strip():
                        input('Error.  You entered a box ID that is already in the database.' \
                            + 'You can quit this menu and use the Edit Contact menue to chagne it.' \
                            + os.linesep + 'Press any key to continue')
                        return(91992)
        #- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
    
    new_contact_nbr = max_contact_nbr + 1
    try:
        # Add it to config 
        for j in range(len(contact_keys)):
            # encrypt the value and add to the config dictionary
            config_txt = natmsgclib.nm_encrypt_local_txt(answers[j].strip(), 
                    natmsgclib.SESSION_PW) # returns type str()

            natmsgclib.MAIN_CONFIG[current_identity][contact_keys[j] \
                + str(new_contact_nbr)] = config_txt 
    except:
        e = str(sys.exc_info()[0:2])
        return(natmsgclib.print_err(6483, 'Failed to update the configuration ' \
            + 'settings with the new contact info. ' + e))

    junk, config_fname = natmsgclib.nm_find_default_config_fname()
    # Save config to disk -- To Do: maybe make a backup of config
    fd = open(config_fname, 'w')
    natmsgclib.MAIN_CONFIG.write(fd)
    fd.close()

    return(0)
########################################################################
########################################################################
########################################################################

def nm_edit_contacts(identity_nbr=None):
    """
    Edit contacts (public box ID, name, and optional info).

    This is called by the user to get input values, format
    the data, and update the configparser settings.

    Contacts are added under an identity, so the user either
    passes the identity number or is prompted to select it
    """

    junk, config_fname = natmsgclib.nm_find_default_config_fname()

    if identity_nbr is None:
        current_identity = natmsgclib.MAIN_CONFIG['SETTINGS']['current_identity']
    else:
        current_identity = identity_nbr

    # Prompt the user to select an ID to edit:
    err_nbr, box_dict, orig_prompt = nm_select_contact(prompt='Select ' \
        + 'a box ID to edit: ')

    if err_nbr !=0:
        return(err_nbr)


    selected_box_id = box_dict['box_id']
    # The id_nbr is usually a small number like 1, 2, 3 ...
    # that is appended to the key names listed in contact_keys[] below
    # when the entries are in the MAIN_CONFIG dictionary as contact info.
    orig_contact_nbr = box_dict['id_nbr'] 
    ### #------------------------------------------------------------------------
    ### # find the maximum current contact nbr for this Identity:
    ### #
    ### max_contact_nbr = 0
    ### for a in natmsgclib.MAIN_CONFIG[current_identity].keys():
    ###     if a[0:21] == 'contact_public_box_id':
    ###         id_nbr = int(a[21:])
    ###         if id_nbr > max_contact_nbr:
    ###             # Save the highest contact number so I know where
    ###             # to add the next one
    ###             max_contact_nbr = id_nbr

    # The order of prompts and contact_keys must match
    bid = ''
    nickname = ''
    contact_note = ''
    try:
        bid = box_dict['box_id']
    except:
        pass

    try:
        nickname = box_dict['nickname'].strip()
    except:
        pass

    try:
        contact_note = box_dict['contact_note'].strip()
    except:
        pass

    prompts = [ \
    ('Public box ID (141 bytes starting with PUB): ', 0, bid),
    ('                Nickname of the new contact: ', 0, nickname),
    ('                                      Notes: ', 0, contact_note)]

    # The order of prompts and contact_keys must match
    contact_keys = ['contact_public_box_id', 'contact_nickname', 'contact_note']

    good = False
    while not good:
        # Get the new entry from the user, then do some error checking,
        # and repeat the loop if there are errors:
        answers = [''] * len(prompts)
        err_nbr, answers = natmsgclib.nm_input_list_and_confirm(prompts)
        if err_nbr != 0:
            return(err_nbr)

        # validate the box ID to see if it has a reasonable format:
        rc = natmsgclib.verify_id_format(id=answers[0], expected_prefix='PUB')
        if rc == 1:
            print('The box ID has expired.  Try again')
            input('Press any key to continue...')
        elif rc != 0:
            print('The box ID did not have the right format.  Try again.')
            input('Press any key to continue...')
        else:
            good = True
    
    if answers[0] == selected_box_id:
        contact_nbr = orig_contact_nbr 
    else:
        # We are adding a contact entry, so get a new contact nbr
        # (which is appended to the end of the key values).
        max_contact_nbr = 0
        for a in natmsgclib.MAIN_CONFIG[current_identity].keys():
            if a[0:21] == 'contact_public_box_id':
                id_nbr = int(a[21:])
                if id_nbr > max_contact_nbr:
                    # Save the highest contact number so I know where
                    # to add the next one
                    max_contact_nbr = id_nbr

        ##new_contact_nbr = max_contact_nbr + 1
        contact_nbr = max_contact_nbr + 1

    try:
        # This will add a record if the box ID changed or update
        # a record if the box ID matches one already in the dictionary.
        # The user could potentially change one ID and overwrite another
        # if they enter an existing box ID, but either way they are putting
        # info in the database.
        for j in range(len(contact_keys)):
            # encrypt the value and add to the config dictionary
            config_txt = natmsgclib.nm_encrypt_local_txt(answers[j], 
                    natmsgclib.SESSION_PW) # returns type str()
    
            natmsgclib.MAIN_CONFIG[current_identity][contact_keys[j] \
                + str(contact_nbr)] = config_txt 
    except:
        e = str(sys.exc_info()[0:2])
        return(natmsgclib.print_err(6484, 'Failed to update the configuration ' \
            + 'settings with the new contact info. ' + e))

    if answers[0] != selected_box_id:
        # we already added a new record because the user changed the box ID,
        # now kill the old one.
        del(natmsgclib.MAIN_CONFIG[current_identity][contact_keys[j] \
                + str(orig_contact_nbr)])

    # Save config to disk -- To Do: maybe make a backup of config
    fd = open(config_fname, 'w')
    natmsgclib.MAIN_CONFIG.write(fd)
    fd.close()

    return(0)
########################################################################
########################################################################
########################################################################

def nm_delete_contact(identity_nbr=None):
    """
    Delete a contact (public box ID, name, and optional info).

    Contacts are stored under an identity, so the user either
    passes the identity number or is prompted to select it
    """

    if identity_nbr is None:
        current_identity = natmsgclib.MAIN_CONFIG['SETTINGS']['current_identity']
    else:
        current_identity = identity_nbr

    err_nbr, box_dict, orig_prompt = nm_select_contact(prompt='Select ' \
        + 'a box ID to DELETE: ')

    if err_nbr !=0:
        return(err_nbr)

    selected_box_id = box_dict['box_id']
    orig_contact_nbr = box_dict['id_nbr'] 
    ### #------------------------------------------------------------------------

    print('')
    print('')
    print('')

    bid = natmsgclib.nm_decrypt_local_txt( \
        natmsgclib.MAIN_CONFIG[current_identity]['contact_public_box_id' \
            + str(orig_contact_nbr)],

        natmsgclib.SESSION_PW)

    nick = natmsgclib.nm_decrypt_local_txt( \
        natmsgclib.MAIN_CONFIG[current_identity][
            'contact_nickname' + str(orig_contact_nbr)],
        natmsgclib.SESSION_PW)

    note = natmsgclib.nm_decrypt_local_txt( \
        natmsgclib.MAIN_CONFIG[current_identity][
            'contact_note' + str(orig_contact_nbr)],
        natmsgclib.SESSION_PW)

    print('  Box ID: ' + bid)
    print('Nickname: ' + nick)
    print('   Notes: ' + note)
    yn = input('Do you want to delete this contact? (y/n): ')
    if yn.lower() in ['y', 'yes']:
        del(natmsgclib.MAIN_CONFIG[current_identity]['contact_public_box_id' \
            + str(orig_contact_nbr)])

        del(natmsgclib.MAIN_CONFIG[current_identity]['contact_nickname' \
            + str(orig_contact_nbr)])

        del(natmsgclib.MAIN_CONFIG[current_identity][
            'contact_note' + str(orig_contact_nbr)])

    junk, config_fname = natmsgclib.nm_find_default_config_fname()
    # Save config to disk -- To Do: maybe make a backup of config
    fd = open(config_fname, 'w')
    natmsgclib.MAIN_CONFIG.write(fd)
    fd.close()

    return(0)
########################################################################
########################################################################
########################################################################

def nm_select_contact(prompt='Select a destination box ID (enter a number): ', 
    include_anonymous=False,
    identity_nbr=None, local_only=False):
    """
    Show a list of contacts (with box IDs) for the current identity and
    allow the user to select one (originally to select the recipient
    for a message).  This returns a tuple with:
      a) return code,
      b) a dictionary object with keys for id_nbr and box_id, and
      c) the prompt used to describe the selected item.

    Also show the user's own box ID to facilitate mailing messages
    to self.
    """

    if identity_nbr is None:
        current_identity = natmsgclib.MAIN_CONFIG['SETTINGS']['current_identity']
    else:
        current_identity = 'Identity' + str(identity_nbr)

    # Note: The contact dict has entries like this:
    #   {'*my main box id PUB123123.....123312': {'id_nbr': 7, 'box_id': PUB....}}
    contact_dict = natmsgclib.nm_build_contact_dict(current_identity, 
        local_only=local_only, include_anonymous=include_anonymous)
    if contact_dict is None:
        # Unable to build the contact list.
        #
        # to not issue an error to the screen because this will
        # fail when I try to get a nickname for people who are not
        # in the database or for anonymous--I will simply omit
        # the nickname later if need be.
        return((natmsgclib.print_err(13604, 'Could not build the contact list.'),
            None, None))

    # Build the menu prompts as an array of strings.  
    prompts = []
    for s in contact_dict.keys():
        # This grabs just the formatted contact descriptions that
        # exist as the keys to contact_dict
        prompts.append(s)

    prompts = sorted(prompts)

    idx, answer = natmsgclib.nm_menu_choice(prompts, 
        prompt=prompt)

    if idx < 0:
        return((13605,'User refused to select a destination.', None))
    else:
        # Use the selected 'contact description' as a key into contact_dict 
        # to find the public box ID, and then return the public box ID along
        # with an error code of zero.  The last item in the tuple
        # is the box description from prompts[] so that I can show
        # that to the user for a confirmation step.
        # the second item is a dictionary object with keys for id_nbr and box_id.
        return((0, contact_dict[answer], prompts[idx]))

########################################################################

def nm_select_identity(title=''):
    """
    Show a list of identities and allow the user to select one.
    """
    
    max_identity_nbr = 0
    ident_lst = []
    for a in natmsgclib.MAIN_CONFIG.keys():
        if a[0:8] == 'Identity':
            id_nbr = int(a[8:])
            if id_nbr > max_identity_nbr:
                # Save the highest Identity number so I know where
                # to add the next one
                max_identity_nbr = id_nbr
    
            id_nickname = ''
            tmp = ''
            try:
                tmp = natmsgclib.MAIN_CONFIG[a]['identity_nickname' + str(id_nbr)]
            except:
                pass
    
            if tmp != '':
                id_nickname = natmsgclib.nm_decrypt_local_txt(bytes(tmp, 'utf-8'),
                    natmsgclib.SESSION_PW)
    
            ident_lst.append(a + ' ' + id_nickname)
    
    idx = -1
    while idx < 0:
        idx, identity_with_nickname = natmsgclib.nm_menu_choice(ident_lst,
            title='Select an Identity to become the active identity.')

    
    # Use the numeric idx to get the identity without possible
    # nicknames ruining it.
    identity = ident_lst[idx]
    ## UPDATE OPTIONS HERE
    natmsgclib.MAIN_CONFIG['SETTINGS']['current_identity'] = identity
    natmsgclib.nm_write_config()
    return(0)

########################################################################
def nm_edit_settings():
    """
    Under constructions to provide a command-line interface
    to edit the SETTINGS portion of MAIN_CONFIG.
    """

    menu_txt = ['Change the active IDENTITY',
        'Select the default BOX ID (from within the current identity)',
        'Set screen WIDTH (in characters)',
        'Set screen HEIGHT (in characters)',
        'Set VERBOSITY (how many warning or status messages '
        + 'appear when you send or receive)',
        'Set the EDITOR command (allows you to run you favorite '
        + 'text editor for composing messages)',
        'Show LONG summaries in the message listing.',
        'Show SHORT summaries in the message listing.',
        'Change the DOWNLOAD directory.',
        'Specify the path to the UNRTF program',
        'Specify the path to an RTF viewer program',
        'Enable/Disable the clear screen (or cls) command (disable only for ' \
            + 'debugging purposes)',
        'Quit this menu.']
        
    # the config_fname here is only for the title
    junk, config_fname = natmsgclib.nm_find_default_config_fname()

    choice = -1
    while choice < 0:
        choice, selected_txt = natmsgclib.nm_menu_choice(menu_txt,
            title='Select the option to view or change (your '
            + 'settings file is: ' + config_fname + ')')

        if choice == 0:
            # Change identity:
            nm_select_identity()
            natmsgclib.nm_write_config()
        elif choice == 1:
            # Select a public box_id
            err_nbr, box_dict, junk = nm_select_contact(prompt='Select a box ID: ')
            if err_nbr != 0 or box_dict is None:
                input('Error. I could not get the results of the menu selection.')
            else:
                if 'box_id' not in box_dict.keys():
                    natmsgclib.print_err(58388, 'I could not get the box ID from the ' \
                        + 'menu selection. Programmer error.')
                    print('The contact dictionary returned was: ' + str(box_dict))
                    time.sleep(2)
                else:
                    box_id = box_dict['box_id']
                    ## id_nbr = box_dict['id_nbr']
                    # This value is encrypted before going to the config file...
                    # (nm_encrypt... returns type str()):
                    config_txt = natmsgclib.nm_encrypt_local_txt(box_id, natmsgclib.SESSION_PW) 
                    if err_nbr == 0:
                        natmsgclib.MAIN_CONFIG['SETTINGS']['current_pub_box_id'] = config_txt
                        natmsgclib.nm_write_config()
                    else:
                        print('Not updating the box ID.')
        elif choice == 2:
            # screen width
            print('\n\n\n\n')
            print('Note that you can adjust the screen width while '
                + 'viewing messages by pressing '
                + 'the W key followed by ENTER.  You can press '
                + 'lower case w to decrease the width. '
                + 'To increase the width by 20 characters while '
                + 'viewing a message, enter 20W '
                + 'and then ENTER.\n\n')
            w_str = natmsgclib.MAIN_CONFIG['SETTINGS']['screen_width']
            answer = natmsgclib.input_no_confirm('Enter an integer '
                + 'value for the screen width '
                + 'in characters (reasonable values are 0-200'
                + '... current value is ' + w_str + ') ', 
                int_answer=True    )
            if answer is not None:
                if isinstance(answer, int):
                    try:
                        natmsgclib.MAIN_CONFIG['SETTINGS']['screen_width'] = str(answer)
                        natmsgclib.nm_write_config()
                    except:
                        e = str(sys.exc_info()[0:2])
                        print('\n')
                        print(natmsgclib.print_err(39245, 'Could not set the screen width. ' + e))
                else:
                    print('Error. I did not receive an integer... programmer error.')

        elif choice == 3:
            # screen height
            print('\n\n\nNote that you can adjust the screen height while viewing ' \
                + 'messages by pressing ' \
                + 'the H key followed by ENTER.  You can press lower case h to ' \
                + 'decrease the height. ' \
                + 'To increase the width by 20 characters while viewing a message, ' \
                + 'enter 20H and then ENTER.\n\n')
            h_str = natmsgclib.MAIN_CONFIG['SETTINGS']['screen_height']
            answer = natmsgclib.input_no_confirm('Enter an integer value for the  ' \
                + 'screen width in characters (reasonable values are 0-200... ' \
                + 'current value is ' + h_str + ') ',
                int_answer=True    )

            if answer is not None:
                if isinstance(answer, int):
                    try:
                        natmsgclib.MAIN_CONFIG['SETTINGS']['screen_height'] = str(answer)
                        natmsgclib.nm_write_config()
                    except:
                        e = str(sys.exc_info()[0:2])
                        print('\n')
                        print(natmsgclib.print_err(39245, 'Could not set the screen ' \
                            + 'width. ' + e))
                else:
                    print('Error. I did not receive an integer... programmer error.')
        elif choice == 4:
            # verbosity
            v_str = natmsgclib.MAIN_CONFIG['SETTINGS']['verbosity']
            answer = natmsgclib.input_no_confirm('Enter an integer value from 0-10 ' \
                + 'for verbosity ' \
                + '(0=no feedback, 10=excessive feedback, default=2) [' + v_str + '] ',
                int_answer=True    )
            if answer is not None:
                if isinstance(answer, int):
                    try:
                        natmsgclib.MAIN_CONFIG['SETTINGS']['verbosity'] = str(answer)
                        natmsgclib.nm_write_config()
                    except:
                        e = str(sys.exc_info()[0:2])
                        print('\n')
                        print(natmsgclib.print_err(39245, 'Could not set the screen ' \
                            + 'width. ' + e))

                    # I still have old code that reads the variable in natmsgclib,
                    # so set that too...
                    natmsgclib.VERBOSITY = answer
        elif choice == 5:
            # select editor
            natmsgclib.nm_select_editor()
            natmsgclib.nm_write_config()
        elif choice == 6:
            # long listing format
            try:
                natmsgclib.MAIN_CONFIG['SETTINGS']['listing_format'] = 'long'
                natmsgclib.nm_write_config()
            except:
                e = str(sys.exc_info()[0:2])
                print('\n')
                print(natmsgclib.print_err(39245, 'Could not set the screen width. ' \
                    + e))
        elif choice == 7:
            # long listing format
            try:
                natmsgclib.MAIN_CONFIG['SETTINGS']['listing_format'] = 'short'
                natmsgclib.nm_write_config()
            except:
                e = str(sys.exc_info()[0:2])
                print('\n')
                print(natmsgclib.print_err(39245, 'Could not set the screen width. ' \
                    + e))
        elif choice == 8:
            # Download directory
            if 'download_directory' in natmsgclib.MAIN_CONFIG['SETTINGS'].keys():
                dn_dir = os.path.expanduser( \
                        natmsgclib.MAIN_CONFIG['SETTINGS']['download_directory'])
            else:
                dn_dir = ''
            answer = natmsgclib.input_no_confirm('Enter the full path to ' \
                + 'the download ' \
                + 'directory [' + dn_dir + ']:  ' , int_answer=False    )

            if answer is None:
                print('The directory did not change.')
            elif answer == '':
                print('The directory did not change.')
            else:
                answer = os.path.expanduser(answer)
                if not os.path.isdir(answer):
                    print('The directory was not found.  The setting will not change.')
                elif answer == dn_dir:
                    print('The directory did not change.')
                else:
                    try:
                        natmsgclib.MAIN_CONFIG['SETTINGS']['download_directory'] = \
                            str(answer)

                        natmsgclib.nm_write_config()
                    except:
                        e = str(sys.exc_info()[0:2])
                        print('\n')
                        print(natmsgclib.print_err(39243, 'Could not set the download ' \
                            + 'directory. ' + e))
        elif choice == 9:
            # set unrtf path
            natmsgclib.nm_set_unrtf_pgm()
        elif choice == 10:
            # RTF viewer
            if platform.system().lower() in ['windows', 'darwin']:
                print('This setting is for Linux and BSD only')
            else:
                # I might run the 'open' command on mac to open RTF,
                # but on minmal Linux or BSD, the xdg-open command
                # might not be installed.
                natmsgclib.nm_set_rtf_reader_pgm()

        elif choice == 11:
            if 'enable_clear_screen' in natmsgclib.MAIN_CONFIG['SETTINGS'].keys():
                current = natmsgclib.MAIN_CONFIG['SETTINGS']['enable_clear_screen']
            else:
                current = True
                natmsgclib.debug_msg(2, 'The current setting is missing... ' \
                    + 'setting default first...')

                try:
                    natmsgclib.MAIN_CONFIG['SETTINGS']['enable_clear_screen'] = 'True'
                    natmsgclib.nm_write_config()
                except:
                    e = str(sys.exc_info()[0:2])
                    print('\n')
                    print(natmsgclib.print_err(39240, 'Could not intialize the ' \
                        + 'setting for enable_clear_screen. ' + e))
                    break

            print('enable_clear_screen is currently set to: ' + str(current))
            if natmsgclib.nm_confirm('Do you want to change this? (y/n): '):
                if current:
                    new_setting = 'False' # must be string for the config file
                else:
                    new_setting = 'True'

                try:
                    natmsgclib.MAIN_CONFIG['SETTINGS']['enable_clear_screen'] = \
                        str(new_setting)

                    natmsgclib.nm_write_config()
                except:
                    e = str(sys.exc_info()[0:2])
                    print('\n')
                    print(natmsgclib.print_err(39240, 'Could not initialize the ' \
                        + 'setting for enable_clear_screen. '  + e))
        elif choice == 12:
            # disable deletion of temp files
            natmsgclib.nm_set_rtf_reader_pgm()
        elif choice == 13:
            break

    return(0)
########################################################################
def nm_clear_screen():
    """
    This will clear the screen if the user settings allow it.

    On some systems, including FreeBSD, the clear command kills error
    messages that might be needed for debugging purposes.
    """

    # In case clear fails, add some space to the screen:
    print(os.linesep + os.linesep + os.linesep + os.linesep \
        + os.linesep + os.linesep + os.linesep + os.linesep)

    # Before options load, the settings will not be available, so
    # set a default that facilitates debugging on platforms where
    # stderr is entirely lost on clear screen (you can not scroll up
    # in the terminal to see old stderr error msgs in PC-BSD).
    enable_clear_screen = 'False'

    try:
        enable_clear_screen = natmsgclib.MAIN_CONFIG['SETTINGS']['enable_clear_screen']
    except:
        pass

    # The settings return data type string instead of boolean:
    if enable_clear_screen.lower() in ['t', 'true']:
        if platform.system().lower() == 'windows':
            try:
                os.system('cls')
            except:
                pass
        else:
            try:
                ## temp removed for testing
                os.system('clear')
                pass
            except:
                pass
    return(0)
########################################################################
                
def nm_edit_file(fname):
    """
    This will determin the correct text editor to open
    and then use it to open the specified filed.

    For Mac and Windows, this will open defaults (TextEdit
    or Notepad).

    If the user doesn't like text editors, 
    the user always has the choice of creating a file
    using any other format or program and attaching it
    as an attachment.
    """
    if platform.system().lower() == 'darwin':
        os.system('open "' + fname + '"')
    elif platform.system().lower() == 'windows':
        os.startfile('"' + fname + '"')
    else:
        # linux, bsd, etc.
        if 'editor_command' not in natmsgclib.MAIN_CONFIG['SETTINGS'].keys():
            # There is no key for 'editor_command' in the options file.
            # Set the editor to blank here to force a search for the editor.
            editor_command = None
            natmsgclib.MAIN_CONFIG['SETTINGS']['editor_command'] = ''
            natmsgclib.nm_write_config()

        ed_enc = natmsgclib.MAIN_CONFIG['SETTINGS']['editor_command']
        if ed_enc == '':
            # The edit command is blank, 
            # so prompt the user to fetch the edit command.
            natmsgclib.nm_select_editor()
            ed_enc = natmsgclib.MAIN_CONFIG['SETTINGS']['editor_command']

        if ed_enc is not None:
            if ed_enc is not '':
                editor_command = natmsgclib.nm_decrypt_local_txt( \
                    ed_enc, natmsgclib.SESSION_PW)
    
        # The editor command might be bad if the user copied options 
        # to a new computer.
        if ed_enc is not None:
            if not os.path.isfile(editor_command):
                # The existing editor command does not point
                # to a valid file.
                natmsgclib.nm_select_editor()
                ed_enc = natmsgclib.MAIN_CONFIG['SETTINGS']['editor_command']
                if ed_enc is not None:
                    if ed_enc is not '':
                        editor_command = natmsgclib.nm_decrypt_local_txt( \
                            ed_enc, natmsgclib.SESSION_PW)
        
        # I probably have a good editor command now,
        # so try opening the file:
        if editor_command is not None:
            try:
                os.system(editor_command + ' "' + fname + '"')
            except:
                e = str(sys.exc_info()[0:2])
                return(natmsgclib.print_err(84584, 'Failed to edit the file. ' + e))

    return(0)

######################################################################
######################################################################
######################################################################
######################################################################


def nm_file_open(fname):

    fname = os.path.abspath(os.path.expanduser(fname))

    open_regular = False
    is_root = False
    uid = None
    try:
        uid = os.geteuid()
    except:
        pass

    if uid is not None:
        if uid == 0:
            print('Do not run this as root')
            return(93833)

    # the fname_ext value here includes the dot:
    fname_base, fname_ext = os.path.splitext(fname)
    ##fname_clean = os.path.basename(fname_tmp)

    # There is a python library that is built on libmagic
    # that might identify executables, but it requires another installation.
    if fname_ext.lower() in ['.sh', '.exe', '.com', '.app', '.bat']:
        print('Refusing to open a possible executable: ' + fname)
        print('Note that this script will not block all executables.')
        print('It is up to you and your launch program to execute ')
        print('programs programs only when you really want to do so.')
        input('Press any key to continue...')
        return(1)

    if fname_ext.lower() == '.rtf':
        nm_view_rtf(fname)
    #### if 'rtf_reader_pgm' in natmsgclib.MAIN_CONFIG['SETTINGS'].keys():
    ####     pgm_encrypted = natmsgclib.MAIN_CONFIG['SETTINGS']['rtf_reader_pgm']
    ####     if pgm_encrypted == '':
    ####         # The user has no special RTF reader
    ####         open_regular = True
    ####     else:
    ####         pgm = natmsgclib.nm_decrypt_local_txt( \
    ####                 pgm_encrypted, natmsgclib.SESSION_PW)
    ####         if pgm is None:
    ####             # There is an entry for the RTF reader in the config file,
    ####             # but I can not decrypt it.
    ####             natmsgclib.print_err(484736, 'Could not decrypt the program name '
    ####                 + 'for your selected RTF viewer.')
    ####             open_regular = True
    ####         else:
    ####             if pgm != '':
    ####                 # Use the special program name in the config list
    ####                 # to open RTF.
    ####                 if os.path.isfile(pgm):
    ####                     try:
    ###                        nm_view_rtf(fname)
    ###                    except:
    ###                        open_regular = True
    ###                        pass    
    ###            else:
    ###                # The program name was properly encrypted, and contained nothing
    ###                open_regular = True

    elif fname_ext.lower() == '.txt':
        # use the default editor
        if 'editor_command' in natmsgclib.MAIN_CONFIG['SETTINGS'].keys():
            pgm_encrypted = natmsgclib.MAIN_CONFIG['SETTINGS']['editor_command']
            pgm = natmsgclib.nm_decrypt_local_txt( \
                    pgm_encrypted, natmsgclib.SESSION_PW)
            if pgm is not None:
                if pgm != '':
                    # Use the special program name in the config list
                    # to open RTF.
                    try:
                        os.system(pgm + ' "' + fname + '"')
                    except:
                        open_regular = True
                        pass    
                else:
                    open_regular = True
            else:
                open_regular = True

    else:
        natmsgclib.print_err(484736, 'Could not decrypt the program name '
                + 'for your selected text editor.')
        open_regular = True

    if open_regular:
        if platform.system().lower() == 'windows':
            # allow for embedded spaces?? add quotes??
            try:
                os.startfile(fname)
            except:
                e = str(sys.exc_info()[0:2])
                print(e)
                input('Could not open this file.  You can try to open it from your ' \
                    + 'usual file browswer or from the command line: ' + fname)
        if platform.system().lower() == 'darwin':
            # Mac OS X
            # The quotes might help interpretation of embedded spaces.
            try:
                os.system('/usr/bin/open "' + fname + '"') 
            except:
                e = str(sys.exc_info()[0:2])
                print(e)
                input('Could not open this file.  You can try to open it from your ' \
                    + 'usual file browswer or from the command line: ' + fname)
        else:
            # linux/bsd
            # TO DO: modify this to use the specified RTF reader or text editor
            # for .txt and .rtf.

            # The quotes might help interpretation of embedded spaces.
            if os.path.isfile('/usr/bin/xdg-open'):
                pgm = '/usr/bin/xdg-open'
            elif os.path.isfile('/usr/local/bin/xdg-open'):
                pgm = '/usr/local/bin/xdg-open'

            try:
                os.system(pgm + ' "' + fname + '"') 
            except:
                e = str(sys.exc_info()[0:2])
                print(e)
                print('Could not use xdg-open to open this file.  Try updating ' \
                    + 'the file associations using xdg-mime.')
                input('Could not open this file.  You can try to open it from your ' \
                    + 'usual file browswer or from the command line: ' + fname)

    return(0)
############################################################
########################################################################

                
def nm_view_rtf(fname):
    """
    This will attempt to open an RTF file usign a program
    that was specified by the user (e.g., OpenOffice, Word...).
    """
    if platform.system().lower() == 'darwin':
        os.system('open "' + fname + '"')
    elif platform.system().lower() == 'windows':
        os.startfile('"' + fname + '"')
    else:
        if 'rtf_reader_pgm' not in natmsgclib.MAIN_CONFIG['SETTINGS'].keys():
            # There is no key for 'rtf_reader_pgm' in the options file.
            # Set the editor to blank here to force a search for the editor.
            rtf_reader_pgm = None
            natmsgclib.MAIN_CONFIG['SETTINGS']['rtf_reader_pgm'] = ''
            natmsgclib.nm_write_config()
        
        rtf_pgm_enc = natmsgclib.MAIN_CONFIG['SETTINGS']['rtf_reader_pgm']
        if rtf_pgm_enc == '':
            # The rtf command is blank, 
            # so prompt the user to fetch the edit command.
            natmsgclib.nm_select_rtf_reader_pgm()
            rtf_pgm_enc = natmsgclib.MAIN_CONFIG['SETTINGS']['rtf_reader_pgm']
        
        if rtf_pgm_enc is not None:
            if rtf_pgm_enc is not '':
                rtf_reader_pgm = natmsgclib.nm_decrypt_local_txt( \
                    rtf_pgm_enc, natmsgclib.SESSION_PW)
        
        # The editor command might be bad if the user copied options 
        # to a new computer.
        if rtf_pgm_enc is not None:
            if not os.path.isfile(rtf_reader_pgm):
                # The existing editor command does not point
                # to a valid file.
                natmsgclib.nm_select_editor()
                rtf_pgm_enc = natmsgclib.MAIN_CONFIG['SETTINGS']['rtf_reader_pgm']
                if rtf_pgm_enc is not None:
                    if rtf_pgm_enc is not '':
                        rtf_reader_pgm = natmsgclib.nm_decrypt_local_txt( \
                            rtf_pgm_enc, natmsgclib.SESSION_PW)
        
        # I probably have a good editor command now,
        # so try opening the file:
        if rtf_reader_pgm is not None:
            try:
                os.system(rtf_reader_pgm + ' "' + fname + '"')
            except:
                e = str(sys.exc_info()[0:2])
                return(natmsgclib.print_err(84584, 'Failed to edit the file. ' + e))

    return(0)

######################################################################
def nm_add_public_box_id(current_identity, expire_yyyymmdd=None, batch=False):
    """
    This will be used to prompt the user to add a public box 
    ID (similar to an email ID) to an existing identity.
    There will be an option to accept the default expiration 
    date or a custom expiration date, but the custom date
    must be within the legal date range (usually January 31 within
    about 16 months of the current date).

    The value for 'current_identity' looks something like this:

      Identity1

    This returns zero on success or nonzero on error.
    """

    prv_id = None # the private box ID associated with the current identity.
    expire_yyyymmdd = None
    id_nbr = current_identity[8:]

    if not id_nbr[8:].isdigit or current_identity[0:8] != 'Identity':
        return(natmsgclib.print_err(3945, 'The format of the Identity '\
            + 'passed to nm_add_public_box_id is invalid: ' + current_identity))

    if current_identity not in natmsgclib.MAIN_CONFIG.keys():
        return(natmsgclib.print_err(3946, 'The Identity '\
            + 'passed to nm_add_public_box_id is not registered: ' + current_identity))

    # Find the 'box id index number ' for the new box ID:
    pub_id_nbr = 1
    while 'pubid' + str(pub_id_nbr) \
            in natmsgclib.MAIN_CONFIG[current_identity].keys():
        # If the key exists, increment this number until there
        # is no entry for that public id...
        pub_id_nbr += 1

    nickname = ''
    name_key = 'identity_nickname' + str(id_nbr)
    if name_key in natmsgclib.MAIN_CONFIG[current_identity].keys():
        nickname =  natmsgclib.MAIN_CONFIG[current_identity][name_key]

    if 'prvid' in natmsgclib.MAIN_CONFIG[current_identity].keys():
        prv_id_enc =  natmsgclib.MAIN_CONFIG[current_identity]['prvid']
        prv_id = natmsgclib.nm_decrypt_local_txt(prv_id_enc, natmsgclib.SESSION_PW)
    else:
        return(natmsgclib.print_err(3947, 'Could not get the '\
            + 'private box ID associated with ' + current_identity \
            + '.  This is either a programmer error or your settings are corrupt.'))

    if natmsgclib.nm_confirm(prompt='Do you want to add another box ID under ' \
        + current_identity + ' ' + nickname + '? (y/n): ', batch=batch):
        
        if expire_yyyymmdd is None and not batch:
            if natmsgclib.nm_confirm(
                prompt='Do you want to set a custom expiration date? '
                + 'For example, if you are going to post this ID online, you might '
                + 'want to set the expiration date for next month to reduce Spam. '
                + 'Messages will not be forwarded to the new ID after the expiration '
                + 'date.\nUse a custom expiration date for the new box ID? (y/n): ',
                batch=batch):

                expire_yyyymmdd = input('Enter the YYYYMMDD expiration date: ')

        err_nbr, prv_id2, pub_id2 = natmsgclib.nm_account_create(private_box_id=prv_id,
            requested_expire_yyyymmdd=expire_yyyymmdd)

        if err_nbr != 0:
            
            print( 'Failed to create the box ID.  Try again in 10 minutes. Error: '
                + str(err_nbr))
            input('Press any key to continue...')
            return(34954)
            
        else:
            config_txt = natmsgclib.nm_encrypt_local_txt(pub_id2, natmsgclib.SESSION_PW)
            natmsgclib.MAIN_CONFIG[current_identity][
                'pubid' + str(pub_id_nbr)] = config_txt
    
            nickname = natmsgclib.input_and_confirm(
                'Enter a nickname for the new box ID (this is '
                + 'never sent to any server)' + os.linesep + ': ')
            if nickname is not None:
                config_txt = natmsgclib.nm_encrypt_local_txt(nickname, natmsgclib.SESSION_PW)
                natmsgclib.MAIN_CONFIG[current_identity][
                    'nickname' + str(pub_id_nbr)] = config_txt

            # Save config to disk -- To Do: maybe make a backup of config
            natmsgclib.nm_write_config()

    return(0)
