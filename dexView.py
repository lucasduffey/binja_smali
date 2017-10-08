from binaryninja import *
from dexFile import *
from dexArch import *
import struct
import traceback
import hashlib # to validate SHA1 signature
import zlib # to validate adler32 checksum
import os

DEX_MAGIC = "dex\x0a035\x00"

class DEXViewUpdateNotification(BinaryDataNotification):
	def __init__(self, view):
		self.view = view


# see NESView Example
# pretty sure this is triggered when we do the "write" call...
# https://github.com/JesusFreke/smali/wiki/Registers
class DEXView(BinaryView):#, dex_parser):
	name = "DEX"
	long_name = "Dalvik Executable"

	# data == BinaryView datatype
	def __init__(self, data):
		print("DEXView::__init__")
		self.raw = data
		self.data = data

		#return # even putting this doesn't prevent crash

		BinaryView.__init__(self, parent_view = data, file_metadata = data.file) # data.file)
		# self.raw = data # FIXME: is this what we can do DexFile() on?
		# self.notification = DEXViewUpdateNotification(self)
		# self.raw.register_notification(self.notification)

		# raw_binary_length = len(data.file.raw)
		# raw_binary = data.read(0, raw_binary_length) # TODO: eliminate this step...

		#log(3, self.entry_point) # populated by apkView - it's coming out as "0"....

		# https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/angr_plugin.py
		# thread it with "BackgroundTaskThread"

		# TODO: check if this works
		#global dex_file

		# dex object isn't used AFAIK
		#dex = dex_parser(self, raw_binary) # FIXME: is there a way to avoid re-analysis if it's been cached # TODO: implement
		#dex.run() # TODO: implement

		# BinaryViewType["DEX"].dex_obj = self.dex # does nothing
		#self.dex = dex_parser.__init__(self, self, raw_binary)

	# TODO: need a better mechanism, maybe provided by androguard
	@classmethod
	def is_valid_for_data(self, data):
		print("DEXView::is_valid_for_data")

		hdr = data.read(0, 16)
		if len(hdr) < 16:
			return False
		# magic - https://en.wikipedia.org/wiki/List_of_file_signatures
		if hdr[0:8] != DEX_MAGIC: # dex file format
			return False

		return True

	def init(self):
		print("DEXView::init")
		return True
		# try:
		# 	# TODO: look at NES.py
		# 	#self.add_entry_point(Architecture['dex'].standalone_platform, self.perform_get_entry_point())
		#
		# 	return True
		# except:
		# 	log_error(traceback.format_exc())
		# 	return False

	# FIXME
	#def perform_is_valid_offset(self, addr):
	#	if (addr >= 0x8000) and (addr < 0x10000):
	#			return True
	#	return False

	# NESView didn't have perform_read...
	# def perform_read(self, addr, length):
	# 	# for now...
	# 	return self.raw.read(addr, length) # TODO: make sure there isn't better way...

	# FIXME
	#def perform_write(self, addr, value):
	#	pass

	# FIXME
	#def perform_get_start(self):
	   #print("[perform_get_start]") # NOTE: seems to infinite loop (for both 0 or 1 return, haven't tested others)
	#   return 0

	# FIXME
	# def perform_get_length(self):
	# 	return 0x10000 # FIXME: wrong

	def perform_is_executable(self):
		return True

	# FIXME
	#def perform_get_entry_point(self):
		# complicated because this is called without self really existing
		#   * not really sure what self provides...

# class DEXViewBank(DEXView):
# 	name = "DEX"
# 	long_name = "Dalvik Executable"
#
# 	def __init__(self, data):
# 		DEXView.__init__(self, data)
#
# DEXViewBank.register()
#DEX.register()

# Architecture.register

'''
from pprint import pprint
pprint(dir(binaryninja.BinaryViewType["DEX"]))

'''
