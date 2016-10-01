from binaryninja import *
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
def get_entry_point(AndroidManifest):
	entry_point = ""

	# AndroidManifest.package is important for constucting entry point
	package = AndroidManifest.getAttribute('package')

	for activity in AndroidManifest.getElementsByTagName("activity"):
		intent_filter = activity.getElementsByTagName("intent-filter")

		# TODO: should there ever be more than one intent_filter????
		if len(intent_filter) != 0:
			action = intent_filter[0].getElementsByTagName("action")[0]
			action_name = action.getAttribute("android:name") # NOTHING....

			# check if it's the entry point
			if action_name == "android.intent.action.MAIN":
				entry_point = package + activity.getAttribute("android:name")

	return entry_point

# see NESView Example
class APKView(BinaryView):
	name = "APK"
	long_name = "android APK"

	def __init__(self, data):
		BinaryView.__init__(self, data.file)
		self.raw = data
		self.notification = APKViewUpdateNotification(self)
		self.raw.register_notification(self.notification)

		#########################################
		apk_size = len(data.file.raw) # TODO: deprecate

		# useful items: AndroidManifest.xml, classes.dex, maybe classes2.dex, lib/*
		# there might be more dex files - the assumption is if the number of classes exceeds 65k there are more files...
		z = zipfile.ZipFile(data.file.filename)
		self.dex_blob = z.read("classes.dex") # TODO: need to support classes1.dex, and others...
		# TODO: return False if "classes.dex" isn't present

		self.BinaryAndroidManifest = z.read("AndroidManifest.xml") # android uses binary xml format

		##########################################
		# androguard magic
		##########################################
		ap = apk.AXMLPrinter(self.BinaryAndroidManifest)
		dom = minidom.parseString(ap.get_buff())

		# XML AndroidManifest
		self.AndroidManifest = dom.getElementsByTagName("manifest")[0]
		self.entry_point_class = get_entry_point(self.AndroidManifest) # TODO: check if androguard has this functionality and/or implement my own AndroidManifest class

		# TODO: how do we hand off entry_point to dexArch... - wait for container support or API where you can save it to database

		# NOTE: overwriting everything with the DEX - this will switch control over to "DEXViewBank" until binja implementes container support
		fluff_size = apk_size - len(self.dex_blob)
		data.write(0, self.dex_blob + "\xff" * fluff_size) # zero the rest, but next line will remove it
		data.remove(len(self.dex_blob), fluff_size) # remove excess stuff, starting after dex_blob - this may leave an extra free byte



	@classmethod
	def is_valid_for_data(self, data):
		# data == binaryninja.BinaryView

		hdr = data.read(0, 16)
		if len(hdr) < 16:
				return False
		# magic - https://en.wikipedia.org/wiki/List_of_file_signatures
		if hdr[0:4] != "PK\x03\x04": # zip file formats (zip, jar, odt, docx, apk, etc..}
			return False

		#
		# TODO: need to make sure we have classes.dex and AndroidManifest.xml inside
		#

		return True


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
