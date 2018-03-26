import binaryninja

from binaryninja import log
# http://androguard.readthedocs.io/en/latest/
from androguard.core.bytecodes import apk
from androguard.util import read # XXX: FAIL - this will not work
from xml.dom import minidom
from dexFile import *
from dexView import *
from dexArch import *
import struct
import traceback
import os
import zipfile
from pprint import pprint

#from dexView import *

# just pull from dexBinja.py forf now
#InstructionNames = dexBinja.InstructionNames
#InstructionIL = dexBinja.InstructionIL

class APKViewUpdateNotification(BinaryDataNotification):
	def __init__(self, view):
		self.view = view

# TODO: this will be used to carve out useful stuff
class APK():
	def __init__(self):
		pass

# FIXME: should probably have an AndroidManifest class
#	* before doing so - check if androguard already has these capabilities
# TODO replace with androguard's get_main_activity
# NOTE: DO NOT DELETE THIS FUNCTION YET
# def get_entry_point(AndroidManifest):
# 	entry_point = ""
#
# 	# AndroidManifest.package is important for constucting entry point
# 	package = AndroidManifest.getAttribute('package')
#
# 	for activity in AndroidManifest.getElementsByTagName("activity"):
# 		intent_filter = activity.getElementsByTagName("intent-filter")
#
# 		# TODO: should there ever be more than one intent_filter????
# 		if len(intent_filter) != 0:
# 			action = intent_filter[0].getElementsByTagName("action")[0]
# 			action_name = action.getAttribute("android:name") # NOTHING....
#
# 			# check if it's the entry point
# 			if action_name == "android.intent.action.MAIN":
# 				entry_point = package + activity.getAttribute("android:name")
#
# 	return entry_point

# see NESView Example
class APKView(BinaryView):
	name = "APK"
	long_name = "android APK"

	def __init__(self, data):
		BinaryView.__init__(self, data.file)
		self.raw = data
		self.notification = APKViewUpdateNotification(self)
		self.raw.register_notification(self.notification)
		self.data = data # hmm...

		print("self.data.file.filename: ", self.data.file.filename)

		# binja issue: https://github.com/Vector35/binaryninja-api/issues/946
		tmp_raw = bv.file.raw.read(0, len(bv.file.raw)) # not sure if self.raw is the same
		#self.apk = apk.APK(self.data.file.filename) # filename could be bndb file..
		self.apk = apk.APK(tmp_raw, raw=True)

		print("APKView __init__")
		#print(1)

		#########################################
		apk_size = len(data.file.raw) # TODO: deprecate for androguard feature if possible

		# useful items: AndroidManifest.xml, classes.dex, maybe classes2.dex, lib/*
		# there might be more dex files - the assumption is if the number of classes exceeds 65k there are more files...

		# XXX: pretty sure self.z is no longer needed
		#self.z = zipfile.ZipFile(self.data.file.filename) # TODO: replace with handroguard? TODO: Need to port "extract_dex" first

		#print(2)

		self.BinaryAndroidManifest = self.apk.get_android_manifest_axml()
		self.dex_blob = self.apk.get_dex() # TODO: self.apk.get_all_dex() can be used to get all dex files

		##########################################
		# androguard magic
		##########################################
		dom = minidom.parseString(self.BinaryAndroidManifest.get_buff()) # TODO: simplify..

		print(self.apk)

		# XML AndroidManifest
		self.AndroidManifest = dom.getElementsByTagName("manifest")[0]
		self.entry_point_class = self.apk.get_main_activity() # get_entry_point(self.AndroidManifest) # TODO: check if androguard has this functionality and/or implement my own AndroidManifest class

		#log.log_error("entry_point_class: " + self.entry_point_class)
		#log.log_error("get_main_activity: " + self.apk.get_main_activity())
		#return

		# XXX: binja core blocker: You can't take raw data and make a BinaryView with it
		#	* Container formats support: https://github.com/Vector35/binaryninja-api/issues/133

		# TODO: how do we hand off entry_point to dexArch... - wait for container support or API where you can save it to database
		# create a new binary view with this data

		# obviously long-term we want to merge them all
		# XXX: currently binja doesn't let you make a view with extracted blobs so the perform_read just reads from self.dex_blob
		dex_banks = []

		#all_dex = self.apk.get_all_dex()
		#print("all_dex: " + str(all_dex))

		pprint(dir(self.apk))

		dex_count = 0
		for dex_blob in self.apk.get_all_dex(): # TODO: store it
			print("[%s] in self.apk.get_all_dex loop" % __file__)
			class DEXViewBank(DEXView):
				print("inside 1")
				bank = dex_count
				name = "DEX Bank %i" % dex_count
				long_name = "Dalvik Executable (bank %i) " % dex_count

				# AFAIK "data_data" type is bv
				def __init__(self, data):
					DEXView.__init__(self, data)

			# TODO: wait for binja container support
			# dex_banks.append(DEXViewBank)
			# DEXViewBank.register()

			dex_count += 1


		log.log_info("dex_count: " + str(dex_count))
		print("dex_count: " + str(dex_count)) # TODO: request len() option for get_all_dex generator

		# XXX: I don't trust dex_parser. Need to troubleshoot it
		#dex = dex_parser(self.data, self.dex_blob) # this is causing it to fail, need to structure it better. self.dex_parser() would be better
		# ^^ NO: perform it on the dexViewBank or whatever

		# #NOTE: overwriting everything with the DEX - this will switch control over to "DEXViewBank" until binja implementes container support
		# fluff_size = apk_size - len(self.dex_blob)
		# data.write(0, self.dex_blob + "\xff" * fluff_size) # zero the rest, but next line will remove it
		# data.remove(len(self.dex_blob), fluff_size) # remove excess stuff, starting after dex_blob - this may leave an extra free byte


	@classmethod
	def is_valid_for_data(self, data):
		# data == binaryninja.BinaryView

		try:
			# use raw, because data.file.filename can point to the bndb file, and no API to get original file
			# binja issue: https://github.com/Vector35/binaryninja-api/issues/946
			raw = bv.file.raw.read(0, len(bv.file.raw))
			is_valid = apk.APK(raw, raw=True).is_valid_APK()

			return is_valid

		except:
			# log.log_error("apkView.py - apk.APK failed to run is_valid_APK")
			return False


	def init(self):
		return True
		# try:
		# 	return True
		# except:
		# 	log_error(traceback.format_exc())
		# 	return False

	def dex(self):
		return self.dex_blob

	# FIXME
	#def perform_is_valid_offset(self, addr):
	#	if (addr >= 0x8000) and (addr < 0x10000):
	#		return True
	#	return False

	# FIXME
	def perform_read(self, addr, length):
		#return self.dex_blob[addr:addr+length] # XXX: read from dex blob instead, very important to keep. Maybe I should create viewbanks for dex, and do this there.
		return self.raw.read(addr, length)

	# FIXME
	#def perform_write(self, addr, value):
	#	pass

	# FIXME
	#def perform_get_start(self):
	#	return 0

	# REQUIRED
	def perform_get_length(self):
		return 0x10000

	# REQUIRED
	def perform_is_executable(self):
		return True

	# def create_new_dex_viewbank(self, dex_count):
	# 	print("[create_new_dex_viewbank]")
	#
	# 	class DEXViewBank(DEXView):
	# 		print("inside 1")
	# 		bank = dex_count
	# 		name = "DEX Bank %i" % dex_count
	# 		long_name = "Dalvik Executable (bank %i) " % dex_count
	#
	# 		# AFAIK "data_data" type is bv
	# 		def __init__(self, data):
	# 			#print("[DEXViewBank __init__]")
	# 			print(type(data))
	# 			DEXView.__init__(self, data)
	#
	# 	return DEXViewBank

		# print(1)
		# dex_banks.append(DEXViewBank) # was "DEXViewBank"
		# print(2)
		# DEXViewBank.register() # TODO; this might be the best thing to do. each dexView can have it's own perform_read

class APKViewBank(APKView):
	name = "APK"
	long_name = "android APK"

	def __init__(self, data):
		APKView.__init__(self, data)

		#
		# waiting for binja container format support: https://github.com/Vector35/binaryninja-api/issues/133
		#	* I think I can get around this for now

# for now, just do this. Binja doesn't really support better ways to make more dex banks...
class DEXViewBank(DEXView):
	print("inside 1")
	bank = dex_count
	name = "DEX Bank %i" % dex_count
	long_name = "Dalvik Executable (bank %i) " % dex_count

	# AFAIK "data_data" type is bv
	def __init__(self, data):
		DEXView.__init__(self, data)

# TODO: wait for binja container support
# dex_banks.append(DEXViewBank)
# DEXViewBank.register()

APKViewBank.register()


if __name__ == "__main__":
	# for now, apkView will just create a bank of DexView?
	print("working")
