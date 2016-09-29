from binaryninja import *
from dexFile import *
from dexArch import *
import struct
import traceback
import os
import zipfile

# comment out for now
#from dexView import DEXViewBank, DEX # need to provide dexView


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

#global_DexFile = False

# see NESView Example
class APKView(BinaryView):
	name = "APK"
	long_name = "android APK"

	def __init__(self, data):
		BinaryView.__init__(self, data.file)
		self.dex_blob = data
		self.notification = APKViewUpdateNotification(self) # TODO
		self.dex_blob.register_notification(self.notification)

	@classmethod
	def is_valid_for_data(self, data):
		# data == binaryninja.BinaryView

		hdr = data.read(0, 16)
		if len(hdr) < 16:
				return False
		# magic - https://en.wikipedia.org/wiki/List_of_file_signatures
		if hdr[0:4] != "PK\x03\x04": # zip file formats (zip, jar, odt, docx, apk, etc..}
			return False

		apk_size = len(data.file.raw)

		# useful items: AndroidManifest.xml, classes.dex, maybe classes2.dex, lib/*
		# there might be more dex files - the assumption is if the number of classes exceeds 65k there are more files...
		z = zipfile.ZipFile(data.file.filename)
		self.dex_blob = z.read("classes.dex") # TODO: need to support classes1.dex, and others...

		# do we just do:
		# write(addr, data) # start at 0, and write everything?
		fluff_size = apk_size - len(self.dex_blob)

		#print "about to overwrite everything with dex_blob"

		# NOTE: this will switch control over to "DEXViewBank"

		# FIXME: replace "data" with "self"??
		# removing - since perform_read will operate off the "data.raw"
		data.write(0, self.dex_blob + "\xff" * fluff_size) # zero the rest, but next line will remove it
		data.remove(len(self.dex_blob), fluff_size) # remove excess stuff, starting after dex_blob - this may leave an extra free byte

		# FIXME
		# FIXME: "write" will want to overwrite the ACTUAL FILE, when in "hex view" it really should show the file..
		# FIXME

		# FIXME: we don't want to overwrite the hex view - or do we? the real goal is to have "dalvik executable" mode point to something useful like OnCreate
		# FIXME: obviously this ^^ isn't correct

		return True


	def init(self):
		try:
			# TODO: look at NES.py

			return True
		except:
			log_error(traceback.format_exc())
			return False

	# FIXME
	#def perform_is_valid_offset(self, addr):
	#	if (addr >= 0x8000) and (addr < 0x10000):
	#		return True
	#	return False

	# FIXME
	def perform_read(self, addr, length):
		return self.dex_blob.read(addr, length)

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

class APKViewBank(APKView):
	name = "APK"
	long_name = "android APK"

	def __init__(self, data):
		APKView.__init__(self, data)

		# TODO: since APK is effectively a zip file
		#	* WARNING: not exactly zip - if you unzip the AndroidManifest.xml is corrupted or something
		#	* extract it

		# unzipped = unzip(binary_blob)
		'''
		contents:
			AndroidManifest.xml
			classes2.dex
			classes.dex
			instant-run.zip
			META-INF/
			res/
			resources.arsc
		'''

APKViewBank.register()


# also register DEX - but how do
#DEXViewBank.register()
#DEX.register()
