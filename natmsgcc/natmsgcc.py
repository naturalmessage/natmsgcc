# Natural Message Simple Client 0_1 for Python 3
from __future__ import print_function

# to do: 
#  1) when receiving a msg, verify that the password shards
#     are in the serverFarm list with a good trust rating.

#
## Example batch  command (the --message-file must be named __NM.txt or __NM.rtf
## and you can add extra attachments at the end.
# python3 natmsg_0_1.py --batch --send \
#   --sender-public-box-id=PUB002016013113CC95900BF7D64498E8A23D6D00E3862CF3B29E2B597DB492BC65CCADF11AF529AF8914B7B2B4290E6F86D54DC1E6C438D11B759D178705F7F1B64F724930E4 \
#   --dest-public-box-id=PUB002016013113CC95900BF7D64498E8A23D6D00E3862CF3B29E2B597DB492BC65CCADF11AF529AF8914B7B2B4290E6F86D54DC1E6C438D11B759D178705F7F1B64F724930E4 \
#  --message-file __NM.txt --subject='my batch test' mypicture.jpg
import sys
if sys.version < '3':
	print('This requires python 3')
	sys.exit()

VERBOSITY=2 # this is a default, the real setting is in MAIN_CONFIG

import natmsgcc.RNCryptor as RNCryptor
import base64
import datetime
import getopt
import natmsgcc.natmsg_offline_reader as natmsg_offline_reader
import natmsgcc.natmsgactions as natmsgactions
import natmsgcc.natmsgclib as natmsgclib
import os
import subprocess
import sys
import tempfile

################################## 
# Bob TEMP NOTES:
# which gui should I use : https://stackoverflow.com/questions/3191373/what-is-the-best-python-gui-ide-toolkit-for-windows
# wxPythonG
# wxPython has a 'rich text control' http://wxpython.org/Phoenix/docs/html/richtextctrl_overview.html "Despite its name, it cannot currently read or write RTF (rich text format) files. Instead, it uses its own XML format, and can also read and write plain text. In future we expect to provide RTF or OpenDocument file capabilities."
# pyQT has a built-in rich text editor: https://en.wikipedia.org/wiki/Scintilla_%28editing_component%29
# pyqt:http://www.riverbankcomputing.com/software/pyqt/intro
################################## 
#

def usage():
	print ('usage: python3 natmsgcc.py [OPTIONS...] ACTION  MSG_FNAME [FILE_LIST]')
	print ('')
	print ('OPTIONS (all options are for batch mode only, and batch mode is send only):')
	print ('    [--batch]')
	print ('    [--sender-public-box-id=BOXID]')
	print ('    [--dest-public-box-id=BOXID]')
	print ('    [--subject=SUBJECT]')
	print ('    [-v] [--verbose]')
	print ('    ')
	print ('    For interactive use, you would normally use no command line options')
	print ('    and would instead use the menue to alter your options.')
	print ('    Batch mode is for sending only--you do not need to enter a password')
	print ('    because batch mode will use the sener box ID that is specified')
	print ('    on the command line.')
	print ('    ')
	print ('    You can specify -v multiple times to increase verbosity.')
	print ('    ')
	print ('    ')
	print ('')
	print ('ACTION:')
	print ('    { [-s] | [--send] }')
	print ('    Choose one action: send (currently there is only one action, but')
	print ('    enter the -s any way for future compatibility).')
	print ('')
	print ('MSG_FNAME:')
	print ('    [-m MSGFILE]  |  [--message-file=MSGFILE]}')
	print ('    Point to exactly one main message file that is either')
	print ('    plain text or RTF (do NOT use Mac OS RTFD).')
	print ('')
	print ('FILE_LIST:')
	print ('   [FILE_SPEC...]')
	print ('   Attach any type of file as an attachment.')
	print ('   Wildcards are allowed in the filespec.')
	sys.exit(1)


def main():
	natmsgactions.nm_clear_screen()

	action = None
	argv_idx = 1
	batch = False
	dest_public_box_id = None
	msg_rtf_fname = None
	sender_public_box_id = None
	subject = None
	verbosity = 0

	try:
		optlist, args = getopt.getopt(sys.argv[1:] \
			,'srhvm:*', ['send', 'receive', 'help', 'verbose', 'batch',
			'subject=',
 			'message-file=', 'dest-public-box-id=', 'sender-public-box-id='])
	except:
		e = str(sys.exc_info()[0:2])
		# except (getopt.GetoptError):
		print('Error.  Bad option list. ' + e)
		usage()
		sys.exit(12)

	#
	for o, a in optlist:
		# In this loop, I keep track of the number of things
		# that I pop off the list by incrementing argv_idx.
		# I then use argv_idx to get the optional file list at the end.
		if (o in ('-h', '--help')):
			usage()
			sys.exit()
		elif o in ('--batch'):
			argv_idx += 1
			batch = True
		elif o in ('-v', '--verbose'):
			argv_idx += 1
			verbosity += 1
		elif o in ('-s', '--send'):
			argv_idx += 1
			action = 's'
		elif o in ('--subject'):
			argv_idx += 1
			subject = a
			# add a verification step here
		elif o in ('--dest-public-box-id'):
			argv_idx += 1
			dest_public_box_id = a
			# add a verification step here
		elif o in ('--sender-public-box-id'):
			argv_idx += 1
			sender_public_box_id = a
			# add a verification step here
		elif o in ('-m', '--message-file'):
			# NOTE: increment my argv_idx so I know where
			# to look for random file specifications at the end
			# of the arg list.
			argv_idx += 1
			msg_rtf_fname = a
		else:
			print('unexpected option: ' + o)
			return(393980)


	f_list = sys.argv[argv_idx: ]
	for f in f_list:
		if not os.path.isfile(f):
			natmsgclib.print_err(12345678, 'Error.  A file that was listed as ' \
				+ 'an attachment was not found: '  + f)

			sys.exit(15)


	if natmsgclib.VERBOSITY > 3 :
		print('opts are: ' \
			+ 'fname  ' +str(msg_rtf_fname ) + ', ' \
			+ 'argvidx' +str(argv_idx) + ', ' \
			+ 'batch  ' +str(batch) + ', ' \
			+ 'verb   ' +str(verbosity ) + ', ' \
			+ 'action ' +str(action ) + ', ' \
			+ 'sender ' +str(sender_public_box_id) + ', ' \
			+ 'sender ' +str(dest_public_box_id) + ', ' \
			+ 'flist ')
		for f in f_list:
			print(f, end=', ')
		print('')


	if batch:
		#- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
		# Batch mode -- send one message and quit
	
		# VERIFY ALL THE OPTIONS HERE
		# VERIFY ALL THE OPTIONS HERE
		# VERIFY ALL THE OPTIONS HERE
		# VERIFY ALL THE OPTIONS HERE
		if action is None or dest_public_box_id is None \
			or msg_rtf_fname is None:
			natmsgclib.print_err(393982, 'Missing options in batch mode.  ' \
				+ 'Be sure to include --sent and a --dest-public-box-id.')
			usage()
			return(393982)

		if sender_public_box_id is None:
			sender_public_box_id = ''

		if subject is None:
			subject = ''

		if natmsgclib.nm_start(batch=True) !=0:
			sys.exit(9834) 
		
		TIME_STAMP_F=datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S.%f")[0:18]
		MAIL_DIR = natmsgclib.MAIN_CONFIG['SETTINGS']['mail_dir']
		# The outbound_staging_dir is a temporary directory, and my 
		# routine to erase temp directories requries that the name
		# contains the strings 'tmp' or 'temp':
		outbound_staging_dir = os.path.join(MAIL_DIR, current_identity, 'outgoing' ,
			'tmp_' + TIME_STAMP_F)

		##outbound_staging_dir = tempfile.mktemp(prefix='nm_tmp-',
		##	dir=os.path.join(MAIL_DIR, current_identity, 'outgoing' ,
		##	TIME_STAMP)

		try:
			os.makedirs(outbound_staging_dir, mode=0o700)
		except:
			e = sys.exc_info()[0]
			natmsgclib.print_err(3700, 'Failed to create outbound staging dir: ' \
				+ outbound_staging_dir)

			sys.exit(543)
		# ------------------------------------------------------
		#											Generate Two, 504-bit Passwords
		# (Chris used 504s bits so that the base 64 would divide 
		# equally across three shards)
		#
		# bytes() object in base64 format
		pw = base64.b64encode(RNCryptor.Random.new().read(63)) 
		kek = base64.b64encode(RNCryptor.Random.new().read(63))
		# note: f_list is a list object with filenames to attach.
		if action is not None:
			rc, old_school_link = natmsgactions.nm_send_message( \
				outbound_staging_dir, pw, 
				kek, msg_fname=msg_rtf_fname,
				reply_to_box_id=sender_public_box_id, dest_box_id=dest_public_box_id,
				flist=f_list,
				subject=subject, batch=True)
			if rc != 0:
				print('There was an error sending.  Check for error messages ' \
					+ 'above and try again.')
				input('Press any key to continue...')
			if old_school_link is not None:
				print(str(old_school_link))
	else:
		#- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
		# Interactive mode
		# load or create the configuration data:
		if natmsgclib.nm_start() !=0:
			sys.exit(9834) 

		try:
			VERBOSITY=int(natmsgclib.MAIN_CONFIG['SETTINGS']['verbosity'])
		except:
			pass

		# ------------------------------------------------------


		# ------------------------------------------------------
		# This should run for every outbound refresh.
		MAIL_DIR = natmsgclib.MAIN_CONFIG['SETTINGS']['mail_dir']
		# 

		# ------------------------------------------------------
		# ------------------------------------------------------
		# ------------------------------------------------------
		# prompt for actions: read, send, add a contact, show contacts, view
		# settings, view your contact info
		action_list = [ \
		'Check for new messages',
		'Read a message using a link from old-school email',
		'Send a message using the Natural Message transport',
		'Send a message using using old-school email',
		'Read messages',
		'Add a contact',
		'Edit contacts',
		'Delete a contact',
		'Add a public box ID (a new "address" for you)',
		'Edit settings',
		'Quit']

		natmsgactions.nm_clear_screen()
		good = False
		while not good:
			natmsgactions.nm_clear_screen()

			# The current identity might have changed if the user
			# editted the settings in the previous looop:
			current_identity = natmsgclib.MAIN_CONFIG['SETTINGS']['current_identity']

			choice, val = natmsgclib.nm_menu_choice(action_list)
			if choice < 0:
				#quit
				good = True
				break
			elif choice == 0:
				# Check for new messages
				TIME_STAMP_F=datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S.%f")[0:18]
				##DAY_STAMP = datetime.datetime.utcnow().strftime('%Y%m%d') # for inbox directory
				# For inbox subdirectory:
				TIME_STAMP_SHORT = datetime.datetime.utcnow().strftime('%H%M%S') 

				enc_prv_id = bytes(natmsgclib.MAIN_CONFIG[current_identity]['prvid'], 'utf-8')
				prv_id = natmsgclib.nm_decrypt_local_txt(enc_prv_id, natmsgclib.SESSION_PW)
				if prv_id is not None:
					rc = natmsgactions.read_inbox(private_box_id=prv_id, fetch_id=TIME_STAMP_F)
				else:
					rc = natmsgclib.print_err(8473, 'Could not decrypt the private box ID ' \
						+ 'to fetch the inbox contents.')

				if rc != 0:
					# There was a problem reading mail, pause and return to the main menue.
					junk = input('Check your Internet connection and try again later.\n' \
						+ 'Press any key to continue.')

				# Now read messages from the inbox
				natmsg_offline_reader.main('received')

			elif choice == 1:
				# Receive a message that was sent over old-school email
				TIME_STAMP_F=datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S.%f")[0:18]
				##DAY_STAMP = datetime.datetime.utcnow().strftime('%Y%m%d') # for inbox directory
				# For inbox subdirectory:
				TIME_STAMP_SHORT = datetime.datetime.utcnow().strftime('%H%M%S') 
				good = True

				old_school = input('Past the old school link inncluding the ' \
					+ 'natmsg:// part and the long string of odd characters (base64), ' \
					+ 'sometimes ending with an equals sign: ').strip()

				if old_school.lower() in ['', 'q', 'quit', 'exit']:
					good = False
				elif old_school[0:9] != 'natmsg://':
					good = False
				elif old_school.find(' ') > 0:
					good = False
				elif len(old_school) > 150:
					print('Error. The link is too long')
					time.sleep(1)
				else:
					rc = natmsgactions.read_inbox(old_school_link=old_school, fetch_id=TIME_STAMP_F)
					if rc != 0:
						# There was a problem reading mail, pause and return to the main menue.
						natmsgclib.print_err(8473, 'Could read the message.')
						junk = input('Check your Internet connection and try again later.' \
							+ os.linesep + 'Press any key to continue.')

				# Now read messages from the inbox
				natmsg_offline_reader.main('received')

			elif choice == 2:
				# Send a message via NatMsg transport.
				# Note: the 'choice' is a zero-based index.
				TIME_STAMP=datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S.%f")[0:18]

				# The outbound_staging_dir is a temporary directory, and my 
				# routine to erase temp directories requries that the name
				# contains the strings 'tmp' or 'temp':
				outbound_staging_dir = os.path.join(MAIL_DIR, current_identity, 'outgoing' ,
					'tmp_' + TIME_STAMP)

				##outbound_staging_dir = tempfile.mktemp(prefix='nm_tmp-', dir=MAIL_DIR \
				##	+ os.sep + 'tmp')
				try:
					os.makedirs(outbound_staging_dir, mode=0o700)
				except:
					e = sys.exc_info()[0]
					natmsgclib.print_err(3700, 'Failed to create outbound staging dir: ' \
						+ outbound_staging_dir)
					sys.exit(543)

				# bytes() object in base64 format
				pw = base64.b64encode(RNCryptor.Random.new().read(63)) 
				kek = base64.b64encode(RNCryptor.Random.new().read(63))
				rc, old_school_link = natmsgactions.nm_send_message( \
					outbound_staging_dir, pw, kek, confirmation=True)

			elif choice == 3:
				# Send a msg using old-school email
				# Note: the 'choice' is a zero-based index.
				TIME_STAMP=datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S.%f")[0:18]

				# The outbound_staging_dir is a temporary directory, and my 
				# routine to erase temp directories requries that the name
				# contains the strings 'tmp' or 'temp':
				outbound_staging_dir = os.path.join(MAIL_DIR, current_identity, 'outgoing' ,
					'tmp_' + TIME_STAMP)

				##outbound_staging_dir = tempfile.mktemp(prefix='nm_tmp-', dir=MAIL_DIR \
				##	+ os.sep + 'tmp')
				try:
					os.makedirs(outbound_staging_dir, mode=0o700)
				except:
					e = sys.exc_info()[0]
					natmsgclib.print_err(3700, 'Failed to create outbound staging dir: ' \
						+ outbound_staging_dir)
					sys.exit(543)

				# bytes() object in base64 format
				pw = base64.b64encode(RNCryptor.Random.new().read(63)) 
				kek = base64.b64encode(RNCryptor.Random.new().read(63))
				
				rc, old_school_link = natmsgactions.nm_send_message( \
					outbound_staging_dir, pw=pw, kek=kek, 
					dest_box_id=natmsgclib.RESERVED_EMAIL_DEST_ID,  confirmation=True)

				if old_school_link is not None:
					print(os.linesep + os.linesep + os.linesep)
					print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -')
					print('             Copy the text an the link between the lines')
					print('             and send them in an email to whomever you like.')
					print('====================================================================')
					input(str(old_school_link))
					print('====================================================================')

			elif choice == 4:
				natmsg_offline_reader.main()
			elif choice == 5:
				natmsgactions.nm_add_contact()
			elif choice == 6:
				natmsgactions.nm_edit_contacts()
			elif choice == 7:
				natmsgactions.nm_delete_contact()
			elif choice == 8:
				test = natmsgactions.nm_add_public_box_id(current_identity)
			elif choice == 9:
				test = natmsgactions.nm_edit_settings()
			elif choice == 10:
				print('bye')
				break

				### # practice editing
				### subprocess.Popen(['/usr/local/bin/nano', '/tmp/fart'])
				### print('finished with popen')
				### fd = open('/tmp/fart', 'r')
				### test = fd.read()
				### fd.close()
				### print('editted file is ' + test)
	
# ------------------------------------------------------
# ------------------------------------------------------
# ------------------------------------------------------
# ------------------------------------------------------

########################################################################
# I need to put my message in RTF format.
# *) Python can convert unicode to RTF with this:
# https://pypi.python.org/pypi/rtfunicode/1.0 = py2 and py3
# *) one note here: https://stackoverflow.com/questions/1337446/is-there-a-python-module-for-converting-rtf-to-plain-text
# *) example of pyrtf from 2008: http://tareqalam.com/2008/05/03/pyrtf-create-rtf-file-using-python/
# *) open office has python 2 interface that might help.
# *) GNU unrtf undoes rtf https://www.gnu.org/software/unrtf/unrtf.html == long time support and devel
# *) pyth does rtf but is python 2
# *) python text editors https://wiki.python.org/moin/PythonEditors

if __name__ == '__main__':
	main()
