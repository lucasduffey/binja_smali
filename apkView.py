import binaryninja

from binaryninja import log
# http://androguard.readthedocs.io/en/latest/
from androguard.core.bytecodes import apk
from androguard.util import read
from xml.dom import minidom
from dexFile import *
from dexArch import *
import struct
import traceback
import os
import zipfile

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
		self.apk = apk.APK(self.data.file.filename)

		print("APKView __init__")

		#########################################
		apk_size = len(data.file.raw) # TODO: deprecate for androguard feature if possible

		# useful items: AndroidManifest.xml, classes.dex, maybe classes2.dex, lib/*
		# there might be more dex files - the assumption is if the number of classes exceeds 65k there are more files...

		# XXX: pretty sure self.z is no longer needed
		#self.z = zipfile.ZipFile(self.data.file.filename) # TODO: replace with handroguard? TODO: Need to port "extract_dex" first

		self.BinaryAndroidManifest = self.apk.get_android_manifest_axml()
		self.dex_blob = self.apk.get_dex() # TODO: self.apk.get_all_dex() can be used to get all dex files

		##########################################
		# androguard magic
		##########################################
		dom = minidom.parseString(self.BinaryAndroidManifest.get_buff()) # TODO: simplify..

		# XML AndroidManifest
		self.AndroidManifest = dom.getElementsByTagName("manifest")[0]
		self.entry_point_class = self.apk.get_main_activity() # get_entry_point(self.AndroidManifest) # TODO: check if androguard has this functionality and/or implement my own AndroidManifest class

		#log.log_error("entry_point_class: " + self.entry_point_class)
		#log.log_error("get_main_activity: " + self.apk.get_main_activity())
		return

		# XXX: binja core blocker: You can't take raw data and make a BinaryView with it
		#	* Container formats support: https://github.com/Vector35/binaryninja-api/issues/133

		# TODO: how do we hand off entry_point to dexArch... - wait for container support or API where you can save it to database
		# create a new binary view with this data

		# obviously long-term we want to merge them all
		# XXX: currently binja doesn't let you make a view with extracted blobs
		for dex_blob in self.apk.get_all_dex():
			pass

			# dexView.register()

		#NOTE: overwriting everything with the DEX - this will switch control over to "DEXViewBank" until binja implementes container support
		fluff_size = apk_size - len(self.dex_blob)
		data.write(0, self.dex_blob + "\xff" * fluff_size) # zero the rest, but next line will remove it
		data.remove(len(self.dex_blob), fluff_size) # remove excess stuff, starting after dex_blob - this may leave an extra free byte


	@classmethod
	def is_valid_for_data(self, data):
		# data == binaryninja.BinaryView

		# TODO: maybe use androguard's apk.APK.is_valid_APK
		return apk.APK(data.file.filename).is_valid_APK()

		# hdr = data.read(0, 16)
		# if len(hdr) < 16:
		# 		return False
		# # magic - https://en.wikipedia.org/wiki/List_of_file_signatures
		# if hdr[0:4] != "PK\x03\x04": # zip file formats (zip, jar, odt, docx, apk, etc..}
		# 	return False
		#
		# #
		# # TODO: need to make sure we have classes.dex and AndroidManifest.xml inside
		# #
		#
		# return True


	def init(self):
		try:
			# TODO: look at NES.py

			return True
		except:
			log_error(traceback.format_exc())
			return False

	def dex(self):
		return self.dex_blob

	# FIXME
	#def perform_is_valid_offset(self, addr):
	#	if (addr >= 0x8000) and (addr < 0x10000):
	#		return True
	#	return False

	# FIXME
	def perform_read(self, addr, length):
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

	# FIXME
	#def perform_get_entry_point(self):
		#return struct.unpack("<H", str(self.perform_read(0xfffc, 2)))[0] # FIXME: being triggered
		#return struct.unpack("<H", "APPLE")[0] # FIXME: being triggered - might crash it...

		# how do I find this?
		#print "apkBinja::perform_get_entry_point: ", global_DexFile.dataOff()
		#return global_DexFile.dataOff() # unsure if correct

	#	return 0 # currently this value will never be used, dexBinja will be used instead

# TODO: how do you get apk - to run APK(blah) against it?


banks = []
class APKViewBank(APKView):
	name = "APK"
	long_name = "android APK"

	def __init__(self, data):
		APKView.__init__(self, data)

		#
		# waiting for binja container format support: https://github.com/Vector35/binaryninja-api/issues/133
		#

APKViewBank.register()


if __name__ == "__main__":

	print("working")
