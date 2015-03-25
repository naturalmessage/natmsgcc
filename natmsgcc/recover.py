import natmsgclib
import natmsgactions

# This is a test of manually recovering raw shards from a download
# temp directory that is created by natmscc_0_1.py

natmsgclib.nm_start()
natmsgclib.VERBOSITY = 9

#natmsgactions.unpack_metadata_files(inbound_save_dir='~/nm_mail/Identity1/incoming/20150225_175352.20',
#	private_box_id='PRV004001010113CC95900BF7D64498E8A23D6D00E3862CF3B29E2B597DB492BC65CCADF11AF529AF8914B7B2B4290E6F86D54DC1E6C4CB0AA08EFE1658465836B5808C2276CC',
#	fetch_id='20150225_140127.56', max_shard_count=3,
#  delete_shard_for_testing=False, delete_temp_files=False)

rc = natmsgactions.unpack_metadata_files(inbound_save_dir='/home/H1Ent/nm_mail/Identity1/incoming/20150301_000122.39/0001/shardtmp-z_q9o1g5',
	private_box_id='PRV004001010113CC95900BF7D64498E8A23D6D00E3862CF3B29E2B597DB492BC65CCADF11AF529AF8914B7B2B4290E6F86D54DC1E6C4CB0AA08EFE1658465836B5808C2276CC',
	fetch_id='20150225_140127.56', max_shard_count=3,
  delete_shard_for_testing=False, delete_temp_files=False)


print('rc was ' + str(rc))
