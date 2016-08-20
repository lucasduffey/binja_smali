from binaryninja import *
import struct
import traceback
import os
import zipfile
import tempfile
import shutil

from dexBinja import *

class APKViewUpdateNotification(BinaryDataNotification):
		def __init__(self, view):
				self.view = view

	# FIXME: don't trust - pulled from NES.py
		def data_written(self, view, offset, length):
				addr = offset - self.view.rom_offset
				while length > 0:
						bank_ofs = addr & 0x3fff
						if (bank_ofs + length) > 0x4000:
								to_read = 0x4000 - bank_ofs
						else:
								to_read = length
						if length < to_read:
								to_read = length
						if (addr >= (bank_ofs + (self.view.__class__.bank * 0x4000))) and (addr < (bank_ofs + ((self.view.__class__.bank + 1) * 0x4000))):
								self.view.notify_data_written(0x8000 + bank_ofs, to_read)
						elif (addr >= (bank_ofs + (self.view.rom_length - 0x4000))) and (addr < (bank_ofs + self.view.rom_length)):
								self.view.notify_data_written(0xc000 + bank_ofs, to_read)
						length -= to_read
						addr += to_read

	# FIXME: don't trust - pulled from NES.py
		def data_inserted(self, view, offset, length):
				self.view.notify_data_written(0x8000, 0x8000)

	# FIXME: don't trust - pulled from NES.py
		def data_removed(self, view, offset, length):
				self.view.notify_data_written(0x8000, 0x8000)

# TODO: this will be used to carve out useful stuff
class APK():
	def __init__(self):
		pass


# see NESView Example
class APKView(BinaryView):
	name = "APK"
	long_name = "android APK"

	def __init__(self, data):
			BinaryView.__init__(self, data.file)
			self.data = data
			self.notification = APKViewUpdateNotification(self) # TODO
			self.data.register_notification(self.notification)

	@classmethod
	def is_valid_for_data(self, data):
			hdr = data.read(0, 16)
			if len(hdr) < 16:
					return False
			# magic - https://en.wikipedia.org/wiki/List_of_file_signatures
			if hdr[0:4] != "PK\x03\x04": # zip file formats (zip, jar, odt, docx, apk, etc..}
					return False

			tmp_dir_path = tempfile.mkdtemp()
			tmp_apk_path = tmp_dir_path + "/binja.apk"

			# copy apk to tmp directory
			shutil.copyfile(data.file.filename, tmp_apk_path)

			z = zipfile.ZipFile(tmp_apk_path) # I don't think you can do from memory...
			for item in z.filelist:
				print item.filename # also ".orig_filename" might be useful

				# useful items: AndroidManifest.xml, classes.dex, maybe classes2.dex, lib/*

			dex_file = "classes.dex"
			dex_path = z.extract(dex_file, path=tmp_dir_path) # save to disk

			print "=================="
			print dex_path
			print "=================="

			# read dex blob into memory
			dex_blob = open(dex_path).read()

			# pass dexPath to dexBinja.py
			d = DexFile(dex_blob)

			#
			# TODO: now I have to operate on the classes.dex
			#


			return True


	def init(self):
		try:
			# TODO: look at NES.py

			return True
		except:
			log_error(traceback.format_exc())
			return False

	# FIXME
		def perform_is_valid_offset(self, addr):
			if (addr >= 0x8000) and (addr < 0x10000):
					return True
			return False

	# FIXME
		def perform_read(self, addr, length):
			return "" # FIXME

		"""
				if addr < 0x8000:
						return None
				if addr >= (0x8000 ):
						return None
				if (addr + length) > 0x10000:
						length = 0x10000 - addr
				result = ""

				while length > 0:
						bank_ofs = addr & 0x3fff
						to_read = 0x4000 - bank_ofs
						data = self.data.read(bank_ofs + 0x4000), to_read)
						result += data
						if len(data) < to_read:
								break
						length -= to_read
						addr += to_read

				return result
		"""

	# FIXME
		def perform_write(self, addr, value):
			if addr < 0x8000:
					return 0
			if addr >= (0x8000 + self.rom_length):
					return 0
			if (addr + len(value)) > (0x8000):
					length = (0x8000) - addr
			else:
					length = len(value)
			if (addr + length) > 0x10000:
					length = 0x10000 - addr
			offset = 0
			while length > 0:
				bank_ofs = addr & 0x3fff
				if (bank_ofs + length) > 0x4000:
						to_write = 0x4000 - bank_ofs
				else:
						to_write = length
				written = self.data.write(s+ bank_ofs + (0x4000), value[offset : offset + to_write])
				if written < to_write:
						break
				length -= to_write
				addr += to_write
				offset += to_write
			return offset

	# FIXME
		def perform_get_start(self):
			return 0


	# FIXME
		def perform_get_length(self):
			return 0x10000

		def perform_is_executable(self):
			return True

	# FIXME
		def perform_get_entry_point(self):
			#return struct.unpack("<H", str(self.perform_read(0xfffc, 2)))[0] # FIXME: being triggered
			#return struct.unpack("<H", "APPLE")[0] # FIXME: being triggered - might crash it...

			# how do I find this?
			return 0

# TODO: how do you get apk - to run APK(blah) against it?

print("dexBinja")
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



# Architecture.register
