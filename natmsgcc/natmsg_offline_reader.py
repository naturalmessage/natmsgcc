
# to do: 'a' to add the contact in the reply-to while reading a message.
import base64
import codecs
import json
import natmsgcc.natmsgactions as natmsgactions
import natmsgcc.natmsgclib as natmsgclib
import os
import platform
import natmsgcc.RNCryptor as RNCryptor
import shutil
import sys
import tempfile
import textwrap

ARCHIVE_HEADER = 'nmf1'
########################################################################


########################################################################
########################################################################
########################################################################
########################################################################
# I now have the name of a file to read.
# read both the original and meta files regardless of which
# file was selected

def nm_display_message(fpath, formatted_reply_to=None, formatted_dest=None,
	batch=False):
	"""nm_display_message(file_path)
	Given a filename that ends with either .json or .meta.json,
	and assuming that the files are either a Natural Message Archive
	Version 1 file or the associated meta file,
	read the files and display something that looks similar to a
	text display of old-school email.

	The user can enter commands to adjust the display.  Press ENTER
	after each of these commands:
	  q = Quit.
	  ENTER = next page.
	  h = Decrease display height (optionally add a prefix, so 12h
	      would decrease height by 12 lines).
	  H = Increase display height (optionally add a prefix, so 12H
	      would increase height by 12 lines).
	  n = Next page.
	  p = Previous page.
	  j = Next line -- actually 2 lines at a time (optionally add a prefix, 
	      so 8j means go down 8 lines).
	  k = Previous line -- actually 2 lines at a time.
	  r = reply
	  w = Decrease screen width (add a numeric prefix like 12w to decrease
	      width by 12 characters).
	  W = Increase screen width (add a numeric prefix like 12w to increase
	      width by 12 characters).
	  gg = Go to top of document.
	  GG = Go to bottom of document.
	"""
	global ARCHIVE_HEADER

	fpath_orig = fpath

	verbosity=int(natmsgclib.MAIN_CONFIG['SETTINGS']['verbosity'])

	#----------------------------------------------------------------------
	# Get screen dimensions from options file if they are available

	# This does not use curses, so I don't know the screen dimensions.
	# Use config settings for screen dimensions.
	try:
		screen_height = int(natmsgclib.MAIN_CONFIG['SETTINGS']['screen_height'])
		screen_width = int(natmsgclib.MAIN_CONFIG['SETTINGS']['screen_width'])
	except:
		screen_width = 80
		screen_height = 20

	#------------------------------------------------------------------------

	if fpath_orig[-10:] == '.meta.json':
		fpath_meta = fpath_orig
		fpath_base = fpath_orig[0:-10]
	else:
		fbase, fext = os.path.splitext(os.path.basename(fpath_orig))
		fpath_base = os.path.dirname(fpath_orig) + os.sep + fbase
		fpath_meta = fpath_base + '.meta.json'

	fpath_data = fpath_base + '.json'

	#------------------------------------------------------------------------
	natmsgclib.debug_msg(5, 'Reading mail metadata file from archive: ' + str(fpath_meta))
	try:
		with open(fpath_meta, 'r') as fd:
			meta_d = json.loads(fd.read())
	except:
		natmsgclib.print_err(4343, 'This file might have been deleted (renamed to ' \
			+ 'begin with the letters Trash).')
		return(4343)
		
	junk, fname = os.path.split(fpath_data)
	dt = fname[0:4] + '/' + fname[4:6] + '/' + fname[6:8]  + ' ' + fname[9:11] \
		+ ':' + fname[11:13]
	subject = ''
	destination_box_id = ''
	try:
		destination_box_id = meta_d['dest']
	except:
		pass

	if 'meta' in meta_d.keys():
		if 'subject' in meta_d['meta'].keys():
			subject = meta_d['meta']['subject']

		if 'replyto' in meta_d['meta'].keys():
			reply_to_box_id = meta_d['meta']['replyto']

	if formatted_reply_to is None:
		formatted_reply_to = reply_to_box_id[0:16] + '...' + reply_to_box_id[-6:]

	if formatted_dest is None:
		formatted_dest = destination_box_id[0:16] + '...' + destination_box_id[-6:]
	elif formatted_dest == '':
		formatted_dest = destination_box_id[0:16] + '...' + destination_box_id[-6:]
		
	header_source = []
	header_source.append('To: ' + formatted_dest)
	header_source.append('Reply To: ' + formatted_reply_to)
	header_source.append('Date YYYY/MM/DD UTC: ' + dt)
	header_source.append('Subject: ' + subject)
	##header_source.append('Date UTC: ' + dt + ' Subject: ' + subject)

	# There might be another record appended here for attachment info

	footer_source = ['--------------------- ' ]
	footer_source.append('q=quit, n=next page, p=prev page, w=less width, ' \
		+ 'W=more width, h=less height, H=more height')

	display_lines = None
	display_width = screen_width

	message = []
	start_idx = 0

	natmsgclib.debug_msg( 5, 'Reading mail data file from archive: ' \
		+ str(fpath_data))

	if not os.path.isfile(fpath_data):
		input('Error. The JSON archive file associated with this message was ' \
			+ 'not found: ' + fpath_data)
		return(3841)
	with open(fpath_data, 'rb') as fd:
		# Process one input message to format the information and display it.
		# to do: add a max file size
		msg_data = ''
		hdr = None 
		try:
			hdr = fd.read(len(ARCHIVE_HEADER))
		except:
			# Ignore corrupt archive file
			e = str(sys.exc_info()[0:2])
			natmsgclib.debug_msg(6, 'Ignoring corrupt archive at the start of ' \
				+ fpath_data + '. ' + e)
			pass
		else:
			# The few bytes have been read
			if hdr != bytes(ARCHIVE_HEADER, 'utf-8'):
				return(natmsgclib.print_err(3840, 'The input archive does not have ' \
					+ 'the correct header: ' + hdr.decode('utf-8')))
			try:
				jlen = int(fd.read(6).decode('utf-8'))
			except:
				# not correct format
				natmsgclib.print_err(3847, 'This archive does not appear to be ' \
					+ 'in the correct format (bad JSON len). header was  ' \
					+ hdr.decode('utf-8') )
				junk = input('Press any key to continue...')
				return(3847)
	
			# Read json metadata that describes the enclosed files
			try:
				tmp = fd.read(jlen).decode('utf-8')
				jmeta_array = json.loads(tmp)
			except:
				e = str(sys.exc_info()[0:2])
				# not correct format
				natmsgclib.print_err(3848, 'This archive does not appear to be in ' \
					+ 'the correct format (bad JSON content). ' + e )
				try:
					natmsgclib.print_err(3848, str(tmp.decode('utf-8')))
				except:
					pass
				return(3848)
	
			attachment_info = []
			archive_idx = 0
			for d in jmeta_array:
				# See if the JSON for this file is marked as the main message:
				if 'isMessage' in d.keys():
					# this should be a boolean type:
					if d['isMessage'] == True:
						# call nm_clean_utf8_text to remove RTF codes, escape invalid chars.
						# standardize EOL, and return an array of strings that have 
						# no EOL at the end.
						msg_data = natmsgclib.nm_clean_utf8_text(fd.read(d['size']))
					else:
						natmsgclib.debug_msg(5, 'I found isMessage but is was not true.  ' \
							+ 'This a problem with the sender application. The value of ' \
							+ 'isMessage was ' + str(d['isMessage']))
				else:
					# For now, I am 'reading past' file attachments 	
					# that are in the archive file until I find
					# the 'main message'...
					#
					# To D0: create a packet of info about the attachements
					# so that an attachment summary can be presented in
					# the message while viewing.
					if 'size' in d.keys():
						# Chris's old 'ballast' entry has no file attachment,
						# and no 'size' entry, so check for 'size' for file
						# existence in the archive.
						# UNDER CONSTRUCTION TO PROMPT TO EXPORT THE ATTACHEMENTS?
						
						# To do: this must change: filenames must be base64 to 
						# avoid utf errors
						attachment_info.append({'idx_nbr': archive_idx, 
							'file_name': d['fileName'] + '.' + d['fileExt'],
							'file_size': d['size']})
						
						# so read past other files only if they have a 'size' key.
						fd.read(d['size'])
				# increment the index that points to the files in the archive
				archive_idx += 1

	# If there are attachments, format the info for the header:
	if len(attachment_info) > 0:
		tmp_l = []
		for a in attachment_info:
			if len(tmp_l) > 0:
				tmp_l.append(', ')
			tmp_l.append(a['file_name'] + ' (' + str(a['file_size']) + ')')

		header_source.append('Attachments: ' + ''.join(tmp_l))
		header_source.append('\n')
	else:
		# no attachments... complete the header
		header_source.append('\n')

	# I now have the main message in msg_data; the formatted header text
	# in header_source[]; footer in footer_source[]; attachment_info[]
	rebuild_needed = True
	cmd = ''
	send_reply = False
	send_forward = False
	while True:
		# This loop display the message initially and 
		# after the user scrolls up or down or alters
		# the screen dimensions.
		if rebuild_needed:
			# 'rebuild' refers to the need to recalculate the set
			# of characters that should be displayed on this screen.
			#
			# Adjust the display lines for the current screen width.
			rebuild_needed = False

			header = []
			for h in header_source:
				# textwrap will convert embedded EOL to spaces.
				wrapped = textwrap.wrap(str(h), width=display_width, tabsize=2)
				for w in wrapped:
					header.append(w)
			header.append('') # the textwrap thing deleted my blank line.


			footer = []
			for h in footer_source:
				wrapped = textwrap.wrap(str(h), width=display_width, tabsize=2)
				for w in wrapped:
					footer.append(w)

			if display_lines is None:
				# For the first display only, set the number of lines
				# of the message to display based on screen settings.
				#
				# 'display_lines' is the number of lines of the message
				# to display on the screen, leaving room for the header
				# and footer.
				# After these are set the first time, the user's commands
				# set them.
				display_lines = screen_height - len(header) - len(footer) - 1


			end_idx = start_idx + display_lines

			# Format the message data to the current screen dimensions
			# and put the newly sliced lines into message[].
			#
			# Note that msg_data is an array of strings that represent
			# one line (paragraph) of text.
			message = []
			for t in msg_data:
				# textwrap produces an array with the text split across elements
				# of the array:
				#
				# textwrap will convert embedded EOL to spaces, but I
				# should have already broken lines on EOL.
				wrapped = textwrap.wrap(str(t), width=display_width, tabsize=2)
				if len(wrapped) == 0:
					# add a blank line to the output if the input line was blank
					message.append('')
				else:
					for w in wrapped:
						message.append(w)
				
		#- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
		# The formated (or re-formatted) header, message, and footer
		# can now be displayed for one screen...
		natmsgactions.nm_clear_screen()
		for h in header:
			print(h)

		for idx in range(start_idx, end_idx):
			if idx < len(message) and idx >= 0:
				print(message[idx])

		for f in footer:
			print(f)

		#- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
		# Prompt the user to enter a command:
		multiplier = 2
		cmd = input('(' + str(start_idx + 1) + '-'  + str(idx + 1) + ') /' \
			+ str(len(message)) + '): ')

		# See if there was a numeric prefix to the command
		i = []
		for c in cmd:
			if c.isnumeric():
				i.append(c)
			else:
				break

		if len(i) > 0:
			cmd = cmd[len(i): ]
			multiplier = int(''.join(i))

		if cmd in ('', 'n', 'N'):
			# Put the default action first to account for a side effect
			# of how an empty string is processed here.
			#
			# Next screen
			start_idx += display_lines 
			max_start_idx = len(message) - display_lines
			if start_idx > max_start_idx:
				start_idx = max_start_idx
			if start_idx < 0:
				start_idx = 0
			end_idx = start_idx + display_lines
		elif cmd in ('x', 'X'):
			# Export all attachments
			if 'download_directory' not in natmsgclib.MAIN_CONFIG['SETTINGS']:
				if not os.path.isdir(os.path.expanduser('~/Downloads')):
					os.makedirs(os.path.expanduser('~/Downloads'), mode=0o655)

			print('Exporting attached files to ' + os.path.expanduser('~/Downloads') )
			err_nbr, err_msg, arch_json = natmsgclib.nm_archiver2(action='x', 
				arch_fname=fpath_data,
				clobber='Prompt', skip_existing=False,
				output_dir=os.path.expanduser('~/Downloads'), extract_attachments=True)

			if err_nbr == 0:
				if 'extracted_files' in arch_json.keys():
					menu_file_open = arch_json['extracted_files']
					menu_file_open.append('Quit')

					while True:
						if platform.system().lower != 'windows' \
						and platform.system().lower != 'darwin':
							print('The file-open command here might be xdg-open.  If ' \
								+ 'files open with an unexpected application, you could ' \
								+ 'try altering the file associations using xdg-mime or ' \
								+ 'your graphical desktop' \
								+ '(right-click and try to set the file' \
								+ 'association properties).')
						rc, answer = natmsgclib.nm_menu_choice(menu_file_open, 
							title='Enter a number to choose which file to open ' \
								+ '(usually with graphical viewer or editor).')
						if rc < 0:
							# quit by entering 'Q'
							break
						else:
							if answer is not None:
								if rc == (len(menu_file_open) - 1):
									# Quit by entering a number
									break
								else:
									# open a specific file
									natmsgactions.nm_file_open(answer)
	
			else:
				input('There was an error during export: ' + err_msg)

		elif cmd in ('c', 'C'):
			# add contact
			if reply_to_box_id in ['', 'anonymous']:
				print('You can not add a blank or anonymous contact.')
				input('Press any key to continue...')
			else:
				natmsgactions.nm_add_contact(box_id=reply_to_box_id)
				
		elif cmd in ('d', 'D'):
			# Rename the archive file to 'Trash...'
			newname = os.path.join(os.path.dirname(fpath_data), 'Trash' \
				+ os.path.basename(fpath_data))
			shutil.move(fpath_data, newname)
			# Rename the meta.json file to 'Trash...'
			newname = os.path.join(os.path.dirname(fpath_meta), 'Trash' \
				+ os.path.basename(fpath_meta))
			shutil.move(fpath_meta, newname)
			##rebuild_needed = True
			return(1) # the caller captures this and rebuilds the file list
		elif cmd in ('j'):
			# Next line
			start_idx += multiplier
			max_start_idx = len(message) - display_lines
			if start_idx > max_start_idx:
				start_idx = max_start_idx
			if start_idx < 0:
				start_idx = 0
			end_idx = start_idx + display_lines
		elif cmd in ('h'):
			# Decrease screen height
			display_lines -= 1 * multiplier
			if display_lines < 10:
				display_lines = 10
			start_idx += display_lines
			max_start_idx = len(message) - display_lines
			if start_idx > max_start_idx:
				start_idx = max_start_idx
			if start_idx < 0:
				start_idx = 0
			end_idx = start_idx + display_lines
			try:
				natmsgclib.MAIN_CONFIG['SETTINGS']['screen_height'] = \
					str(display_lines \
					+ len(header) + len(footer) + 2)
				natmsgclib.nm_write_config()
			except:
				pass
		elif cmd in ('H'):
			# Increase screen height
			display_lines += 1 * multiplier
			start_idx += display_lines
			max_start_idx = len(message) - display_lines
			if start_idx > max_start_idx:
				start_idx = max_start_idx
			if start_idx < 0:
				start_idx = 0
			end_idx = start_idx + display_lines
			try:
				natmsgclib.MAIN_CONFIG['SETTINGS']['screen_height'] = \
					str(display_lines \
					+ len(header) + len(footer) + 2)
				natmsgclib.nm_write_config()
			except:
				pass
		elif cmd in ('f', 'F'):
			# forward
			send_forward = True
			break
		elif cmd in ('r', 'R'):
			# reply
			send_reply = True
			break
		elif cmd in ('w'):
			# Decrease screen width
			display_width -= 1 * multiplier
			if display_width < 10:
				display_width = 10
			rebuild_needed = True
			try:
				natmsgclib.MAIN_CONFIG['SETTINGS']['screen_width'] = str(display_width)
				natmsgclib.nm_write_config()
			except:
				pass
		elif cmd in ('W'):
			# Increase screen width
			display_width += 1 * multiplier
			if display_width < 10:
				display_width = 10
			rebuild_needed = True
			try:
				natmsgclib.MAIN_CONFIG['SETTINGS']['screen_width'] = str(display_width)
				natmsgclib.nm_write_config()
			except:
				pass
		elif cmd in ('p', 'P'):
			# Previous screen
			start_idx -= display_lines 
			if start_idx < 0:
				start_idx = 0		
			if start_idx < 0:
				start_idx = 0
			end_idx = start_idx + display_lines
		elif cmd in ('k'):
			# Previous line
			start_idx -= multiplier 
			if start_idx < 0:
				start_idx = 0		
			if start_idx < 0:
				start_idx = 0
			end_idx = start_idx + display_lines
		elif cmd == 'gg':
			# Go to top of file (like the vim command)
			start_idx = 0
			end_idx = start_idx + display_lines
			max_start_idx = len(message) - display_lines
			if start_idx > max_start_idx:
				start_idx = max_start_idx
		elif cmd == 'g':
			# Go to line (almost like the vim command)
			start_idx = multiplier
			end_idx = start_idx + display_lines
			max_start_idx = len(message) - display_lines
			if start_idx > max_start_idx:
				start_idx = max_start_idx
			if start_idx < 0:
				start_idx = 0
		elif cmd == 'GG':
			# Go to end of file (like the vim command)
			start_idx = len(message) - display_lines
			end_idx = start_idx + display_lines
			if start_idx < 0:
				start_idx = 0
		elif cmd in ('q', 'Q'):
			# quit
			break

	if send_reply or send_forward:
		MAIL_DIR = natmsgclib.MAIN_CONFIG['SETTINGS']['mail_dir']
		outbound_staging_dir = tempfile.mktemp(prefix='nm_tmp-', dir=MAIL_DIR \
			+ os.sep + 'tmp')
		try:
			os.makedirs(outbound_staging_dir, mode=0o700)
		except:
			e = sys.exc_info()[0]
			natmsgclib.print_err(3700, 'Failed to create outbound staging dir: ' \
				+ outbound_staging_dir)
			sys.exit(543)

		# pw is a bytes() object in base64 format
		pw = base64.b64encode(RNCryptor.Random.new().read(63)) 
		kek = base64.b64encode(RNCryptor.Random.new().read(63))
		
	if send_reply:
		# If the sender was anonymous, select the new destination box
		# (the reply_to address here is from the exiting msg, not the new one.)
		while reply_to_box_id in ['', 'anonymous']:
			err_nbr, box_dict, orig_prompt = natmsgactions.nm_select_contact( \
				prompt='This message ' \
				+ 'was sent anonymously.  Select the destination ID for the reply: ')
			if box_dict is None:
				# invalid or not found... break out of the loop
				reply_to_box_id = ''
				break
			else:
				if 'box_id' in box_dict.keys():
					reply_to_box_id = box_dict['box_id']
				else:
					reply_to_box_id = ''
					break

	if send_reply or send_forward:
		# Remember that 'destination_box_id' is for the current 
		# user/box id that received
		# the message that is being viewed now--it becoes the 'from' box id.
		flist = None
		if len(attachment_info)> 0 :
			if send_reply:
				pp = 'Do you want to include the attachments in the reply? (y/n): '
			else:
				pp = 'Do you want to include the attachments? (y/n): '

			if natmsgclib.nm_confirm(pp):
				# extract all the attachments to a tempdir, then include
				# those filenames in the flist,
				# then after sending, delete the files.
				attachment_staging_dir = tempfile.mktemp(prefix='nm_attachments-', 
					dir=outbound_staging_dir)

				err_nbr, err_msg, arch_json = natmsgclib.nm_archiver2(action='x',
					skip_existing=False,
					arch_fname=fpath_data,
					output_dir=attachment_staging_dir,
					extract_attachments=True)
				if err_nbr != 0:
					input('There was while staging the attachments to be forwarded: ' \
						+ err_msg)

					return(err_nbr)

				flist = os.listdir(attachment_staging_dir)		
				for j in range(len(flist)-1, -1, -1):
					# f is just the file name without the path.
					if flist[j] in ['__NM.txt', '__NM.rtf']:
						del(flist[j])

				# Modify the flist to contain the full path
				for j in range(len(flist)):
					flist[j] = os.path.join(attachment_staging_dir, flist[j])

		if send_forward:
			# Clear the reply_to field, which will become the new destination,
			# and let the send_message routine prompt for the destination.
			reply_to_box_id = None
		message.insert(0, os.linesep + os.linesep \
			+ '---------------- Original Message ' + dt + ' (GMT) -----------' + os.linesep)

		rc = natmsgactions.nm_send_message(outbound_staging_dir, pw, kek=kek,
			reply_to_box_id=destination_box_id, batch=batch,
			body_txt=message, dest_box_id=reply_to_box_id, subject='re: ' + subject,
			flist=flist, confirmation=True)
		if rc != 0:
			return(rc)
	return(0)
########################################################################
########################################################################
########################################################################
########################################################################
########################################################################
########################################################################

def nm_msg_meta_browser(top=None, file_list=None, 
	listing_format=None, batch=False):
	"""
	This displays a list of messages in either 'long' or 'short' format
	(2-5 lines of summary information per message), and allows the user
	to select a message to read.

	The long form of the display of message information includes:
	  destination box ID
	  reply-to box ID
		date
	  subject
	  number of attachments (with file sizes)
	  snippet of text from the message (about 250 bytes)

	If the caller passes file_list, that will be used to generate
	the list of files (such as when a search command is used and the file_list
	contains only the matches). If file_list is passed, it should be
	a Python list object with full path to each file.

	When the user selects a message to view, nm_display_message() is called
	to show the full message.
	"""

	quit_browser = False
	if 'current_identity' not in natmsgclib.MAIN_CONFIG['SETTINGS']:
		return(natmsgclib.print_err(4330, 'The setting for current_identity ' \
			+ 'does not exist. ' \
			+ 'This should have been fixed at startup.  Programmer error.'))

	if 'mail_dir' not in natmsgclib.MAIN_CONFIG['SETTINGS']:
		return(natmsgclib.print_err(4331, 'The setting for mail_dir ' \
			+ 'does not exist. ' \
			+ 'This should have been fixed at startup.  Programmer error.'))
		
	current_identity = natmsgclib.MAIN_CONFIG['SETTINGS']['current_identity']
	MAIL_DIR = natmsgclib.MAIN_CONFIG['SETTINGS']['mail_dir']

	if file_list is None and top is None:
		top = MAIL_DIR + os.sep + current_identity + os.sep + 'received'

	if listing_format is None:
		if 'listing_format' in natmsgclib.MAIN_CONFIG['SETTINGS'].keys():
			listing_format = natmsgclib.MAIN_CONFIG['SETTINGS']['listing_format']

	if listing_format is None:
		# the settings failed to work, set a default here
		listing_format = 'short'

	if isinstance(listing_format, str):
		listing_format = listing_format.lower()
		if listing_format not in ['long', 'short']:
			return(natmsgclib.print_err(4339, 'Error. listing_format is invalid in ' \
				+ 'nm_display_message.  Programmer error.  ' \
				+ ' The value must be either "long" or "short" but was: ' \
				+ listing_format))
	else:
		return(natmsgclib.print_err(4340, 'Error. listing_format is not a ' \
			+ 'string in ' \
			+ 'nm_display_message.  Programmer error.'))



	if top is not None:
		if not os.path.isdir(top):
			if os.path.isdir(os.path.dirname(top)):
				top = os.path.dirname(top)
			else:
				natmsgclib.print_err('Error. The value for the starting directory ' \
					+ 'for nm_msg_browser is not a directory: ' + str(top)) 
				return(2334)

	try:
		display_width = int(natmsgclib.MAIN_CONFIG['SETTINGS']['screen_width'])
		max_msg_browse = int(natmsgclib.MAIN_CONFIG['SETTINGS']['max_msg_browse'])
	except:
		display_width = 80
		max_msg_browse = 1000

	while not quit_browser:
		# Read the first 500 (max_msg_browse) json meta data files and build 
		# a list object with the main data
		msg_dict_array = [] # an array of Python dictionary objects
		menu_array = []
		if file_list is None:
			files_all = os.listdir(top)		
		else:
			files_all = file_list

		fail_count = 0
		good_count = 0
		for f in files_all:
			# f is just the file name without the path.
			if file_list is not None:
				# file_list already contains the full path
				f_path = f
			else:
				# construct the full path
				f_path = top + os.sep + f

			if f.find('meta.json') > 0 and f[0:5].lower() != 'trash' \
				and good_count < max_msg_browse:

				with open(f_path, 'r') as fd:
					try:
						mdata = json.loads(fd.read())
						mdata.update({'browser_fpath': f_path})
					except:
						fail_count += 1
						if fail_count < 5:
							natmsgclib.debug_msg(1, 'Could not load JSON information ' \
								+ 'from ' + f)
					else:
						good_count += 1

						msg_dict_array.append(mdata)	
	
		# I now have lots of JSON in the msg_dict_array, but it is not sorted.
		# It has keys for  meta, date, browser_fpath, dest, 
		# subj_reply_to_enc, attachment_count
	
		# Build a dictionary of contacts to decode box IDs into nicknames
		contact_dict_reverse = natmsgclib.nm_build_contact_dict(current_identity)
		contact_dict = {}
		for k in contact_dict_reverse:
			# build a dictionary with box IDs as keys and nicknames as values
			contact_dict.update({contact_dict_reverse[k]['box_id']: k})
	
		# add sort here
		## srt = sorted(d,   key=lambda  dict_entry: dict_entry['b'])
		# srtd_array will have keys for  meta, date, browser_fpath, dest, 
		# subj_reply_to_enc, attachment_count
		srtd_array = sorted(msg_dict_array,   reverse=True, 
			key=lambda  dict_entry: dict_entry['browser_fpath'])
	
		# I now have lots of JSON in the srtd_array... ORDERED by how 
		# they will display on the screen.
	
		# Construct an array of the formatted information that goes on the screen.
		for dd in srtd_array:
			dest = ['To: '] 
			if listing_format == 'long':
				reply_to = ['    Reply to: ' ]
			else:
				# for the short format, reply to is first, so
				# remove the hanging indent
				reply_to = ['Reply to: ' ]

			subject = ['    Subject: ']
			preview = ['    Preview: ']
			preview2= []
			if 'attachment_count' in dd.keys():
				# There are attachments... add a '+' indicator
				if int(dd['attachment_count']) > 0:
					msg_date = ['   +Date: ']
				else:
					# no attachments:	
					msg_date = ['    Date: ']
			else:
				# no attachments:	
				msg_date = ['    Date: ']

			attachment_sizes = ['    Attachments: '] 
		
			#	
			#### Note: The contact_dict already shows the shortened box ID
			reply_to_nickname = ''
			reply_to_box_id = ''
			if 'replyto' in dd['meta'].keys():
				reply_to_box_id = dd['meta']['replyto']
				if reply_to_box_id in contact_dict.keys():
					try:
						reply_to_nickname = contact_dict[dd['meta']['replyto']] + ' '
						reply_to.append( reply_to_nickname + ' ')
					except:
						pass
			else:
				##input('===== no replyto...')
				pass
	
			if reply_to_nickname == '':
				if reply_to_box_id != '':
					reply_to_nickname = reply_to_box_id[0:16] + '...' \
						+ reply_to_box_id[-6:]
	
			try:
				dest_nickname = contact_dict[dd['dest']]
				dest.append( dest_nickname + ' ')
			except:
				e = str(sys.exc_info()[0:2])
				if 'dest' in dd.keys():
					dest_nickname = dd['dest'][0:16] + '...' + dd['dest'][-6:]
				else:
					dest_nickname = ''
				pass
			
			try:
				tmp = base64.b64decode(bytes(dd['msg_snippet'], 
					'utf-8')).decode('utf-8').replace('\n',' ').replace('\r', ' ')
				# Adjust the length of the first line of the message preview
				# according to the length of the 'Preview: ' text:
				tmp_max = display_width - len(preview[0])
				if len(tmp) > tmp_max:
					tmp_idx = tmp_max
				else:
					tmp_idx = len(tmp) 
	
				preview.append(tmp[0:tmp_idx])
				if len(tmp) > tmp_idx:
					preview2.append(tmp[tmp_idx: ])
			except:
				e = str(sys.exc_info()[0:2])
			
			try:
				subject.append( dd['meta']['subject'])
			except:
				pass
	
			try:
				msg_date.append(dd['date'])
			except:
				pass
	
	
			# Construct the brief (a few lines) text that is used to summarize
			# each message in the list and append it to msg_display[].
			msg_display = []
			if listing_format == 'long':
				msg_display.append( ''.join(dest)[0:display_width] + os.linesep \
					+ ''.join(reply_to)[0:display_width] + os.linesep \
					+ ''.join(subject)[0:display_width]  + os.linesep \
					+ ''.join(msg_date))
			else:
				# short listing of message info
				msg_display.append(''.join(reply_to)[0:display_width] + os.linesep \
					+ ''.join(msg_date)+ ' ' + ''.join(subject)[0:display_width] )

			if listing_format == 'long':
				if len(attachment_sizes) > 1:
					msg_display.append('  ' + ''.join(attachment_sizes)[0:display_width] )
	
				if len(preview) > 1:
					msg_display.append(os.linesep + ''.join(preview)[0:display_width] )
	
				if len(preview2) > 0:
					msg_display.append(os.linesep + '    ' \
						+ ''.join(preview2)[0:display_width] )
	
			menu_array.append(''.join(msg_display)) 
	
	
		# Display the list of messages and prompt the user to select one.
		#
		# I am now rebuilding the menu each time in case the user
		# deletes a message
		natmsgactions.nm_clear_screen()
		idx, choice = natmsgclib.nm_menu_choice(menu_array)
		if idx < 0:
			# quit or error
			quit_browser = True
			break
	
		# I now have the content of 'choice' (which is the full 
		# header including the 'To: '
		# and 'Reply to: ' text) and the idx. The idx points to the
		# entry in both 'menu_array' and 'srtd_array'.
		# The srtd_array contains a list of dictionary objects from the .meta.json
		# files that have keys for dest, date, msg_snippet, meta{replyto, subject}
		#
		reply_to_nickname = ''
		dest_nick_name = ''
		reply_to_box = ''
		dest_box = ''
		if 'meta' in srtd_array[idx].keys():
			if 'replyto' in srtd_array[idx]['meta'].keys():
				reply_to_box = srtd_array[idx]['meta']['replyto']
				if reply_to_box in contact_dict.keys():
					reply_to_nickname = contact_dict[reply_to_box]

		if 'dest' in srtd_array[idx].keys():
			dest_box = srtd_array[idx]['dest']
			if dest_box in contact_dict.keys():
				dest_nickname = contact_dict[dest_box]

		# Show one, full message with its content:
		rc = nm_display_message(srtd_array[idx]['browser_fpath'],
			formatted_reply_to=reply_to_nickname, batch=batch,
			formatted_dest=dest_nickname)
		if rc == 1:
			rebuild_needed = True
	if quit_browser:
		return(1)
	else:
		return(0)
	
########################################################################
def main(top=None, verbosity=0):
	natmsgclib.nm_start()
	if top is None:
		top = natmsgclib.MAIN_CONFIG['SETTINGS']['mail_dir'] \
			+  os.sep + natmsgclib.MAIN_CONFIG['SETTINGS']['current_identity']
	elif top.lower() == 'received':
		top = natmsgclib.MAIN_CONFIG['SETTINGS']['mail_dir'] +  os.sep \
			+ natmsgclib.MAIN_CONFIG['SETTINGS']['current_identity'] \
			+ os.sep + 'received'

	keep_browsing = True
	while keep_browsing:
		natmsgactions.nm_clear_screen()
		## change this to select 4 dirs then call meta_browser
		#### This version chooses files by date/time in the filename:
		### fpath_orig = nm_file_chooser(top, mode='directory')
		### if fpath_orig is None:
		###	break
		###nm_display_message(fpath_orig)
		rc = nm_msg_meta_browser()
		if rc != 0:
			keep_browsing = False
		
########################################################################
# run it
if __name__ == '__main__':
	if len(sys.argv) > 1 :
		main(sys.argv[1])
	else:
		main(verbosity=6)

