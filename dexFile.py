from binaryninja import *
from dexFile import *
import struct
import traceback
import hashlib # to validate SHA1 signature
import zlib # to validate adler32 checksum
import os

DEX_MAGIC = "dex\x0a035\x00"

'''
DEX Structure - https://source.android.com/devices/tech/dalvik/dex-format.html (best resource)
http://elinux.org/images/d/d9/A_deep_dive_into_dex_file_format--chiossi.pdf
https://android.googlesource.com/platform/art/+/master/tools/dexfuzz/src/dexfuzz/rawdex/HeaderItem.java

IMPORTANT
.read(offset, 4) # last arg is the "count", not the "last idex to read"

'''

# sizes of fields
# look at dex.c -  DexHeader is the first header (is what it really seems to be)
# https://docs.python.org/2/library/struct.html
# https://gist.github.com/ezterry/1239615

#
# in dexparse.py - the fp seeks to dexOptHdr.dexOffset
#
class dexHeader():
	def __init__(self, binary_blob, binary_blob_length):
		# how do I make it so it just inherits it, and compiler thingy doesn't complain?
		self.binary_blob = binary_blob
		self.binary_blob_length = binary_blob_length

		pass

	# returns hex
	# ubyte[8] = DEX_FILE_MAGIC
	def magic(self):
		result = self.binary_blob[0:8] # FIXME: it says data is not defined

		assert len(result) != 0

		#result = struct.unpack("<Q", hdr[0:8])[0] # "dex\x0a035\x00"

		# dex file validation
		if result != DEX_MAGIC:
			print "magic result: ", hex(result), " correct magic: ", hex(DEX_MAGIC)
			assert False

		return DEX_MAGIC

	# adler32 checksum of the rest of the file (everything but magic and this field); used to detect file corruption
	# format: uint
	def checksum(self):
		offset = 8
		checksum_size = 4

		result = self.binary_blob[offset: offset+checksum_size]
		result = struct.unpack("<I", result)[0] # unsigned int

		idx_start = offset+checksum_size
		idx_end = idx_start + self.file_size()-offset-checksum_size
		adler32 = zlib.adler32(self.binary_blob[idx_start: idx_end]) & (2**32-1)
		# 32 bit: & (2**32-1)
		# 64 bit: & (2**64-1)

		if adler32 != result:
			print "adler32: ", hex(adler32), " checksum: ", hex(result)
			assert False

		return result

	# sha-1 signature of the rest of the file (excluding magic, checksum, and signature)
	# format: ubyte[20]
	def signature(self):
		offset = 12  # why 16? - this must be wrong. I validated file_size which starts at offset 32
		signature_size = 20

		result = self.binary_blob[offset: offset+signature_size] # I'm not sure why this is longer than "20"
		result = result.encode('hex')

		idx_start = offset+signature_size
		idx_end = idx_start + self.file_size()-offset-signature_size
		sha1 = hashlib.sha1(self.binary_blob[idx_start:idx_end]).hexdigest()

		if result != sha1:
			print "sha1: ", sha1, " signature: ", result
			assert False

		return result

	# returns unsigned int
	def file_size(self):
		offset = 32

		result = self.binary_blob[offset: offset+4]
		result = struct.unpack("<I", result)[0] # is currently printing correct info

		# dex file validation
		if result != self.binary_blob_length: # FIXME GREPME - was self.data.file.raw
			print "file_size method: ", hex(result), ", self.file.raw: ", hex(binary_blob_length)
			assert False

		# binary string => unsigned int
		return result

	# format: unit = 0x70
	def header_size(self):
		offset = 36
		result = self.binary_blob[offset: offset+4]
		result = struct.unpack("<I", result)[0] # uint

		if result != 0x70:
			print "header_size: ", result
			assert False

		return 0x70

	###############################################3

	# TODO - validate
	# format: uint = 0x12345678
	def endian_tag(self):

		# int ENDIAN_CONSTANT = 0x12345678;

		print "endian_tag isn't implemented"
		assert False

	# TODO - validate
	# format: uint
	def link_size(self):
		pass

	# TODO - validate
	# format: uint
	def link_off(self):
		pass

	# TODO - validate
	# format: uint
	# Purpose: offset from the start of the file to the map item. The offset, which must be non-zero, should be to an offset into the data section,
	#  				and the data should be in the format specified by "map_list" below.
	# Questions: what is the "map item"?
	def map_off(self):
		pass


	# mapOff
	# stringIdsSize, stringIdsOff,
	# typeIdsSize, typeIdsOff
	# protoIdsSize, protoIdsOff,

	# 76 offset
	# TODO - validate
	def protoIdsOff(self):
		offset = 76
		_protoIdsOff = self.binary_blob[offset: offset+4]

		return struct.unpack("<I", _protoIdsOff)[0] # TODO: verify

	# fieldIdsSize, fieldIdsOff

	# methodIdsSize, methodIdsOff (92 offset)
	# TODO - validate
	def methodIdsOff(self):
		offset = 92
		_methodIdsOff = self.binary_blob[offset: offset+4]

		return struct.unpack("<I", _methodIdsOff)[0] # TODO: verify


	# each class_defs instance has a "class_data_off" field
	def class_defs(self):
		_class_defs_size = self.class_defs_size()
		_class_defs_off = self.class_defs_off()

		print "\n===============================\n"
		print "class_defs_size: ", _class_defs_size, "\n"
		print "class_defs_off: ", hex(_class_defs_off), "\n"

		#results = [] # list of class_def_item
		_class_defs_bytes = _class_defs_size*8*4 # class_def_item has 8 uints
		raw_class_defs = self.binary_blob[_class_defs_off: _class_defs_off+ _class_defs_bytes]

		# split by class_def_item_size
		class_def_item_size = 8*4 # 8 uints
		results = [raw_class_defs[i:i+class_def_item_size] for i in range(0, len(raw_class_defs), class_def_item_size)]

		# TODO: parse each all_class_defs - into a dict maybe?
		for idx, result in enumerate(results):
		#for idx in range(3): # FIXME: so, when it crashes for some reason it actually shows the functions.. maybe because the Arch hasn't failed....??
			result = results[idx]

			print "class_defs: in enumerate loop"

			class_data_off = result[4*6: 4*7]

			print "len(class_data_off)", len(class_data_off)

			class_data_off = struct.unpack("<I", class_data_off)[0]

			# add the dex function to function list, TODO: finish
			print "create_user_function: ", hex(class_data_off)

			#log(1, "example debug log 1")
			#log(2, "example debug log 2")


			self.data.create_user_function(Architecture['dex'].standalone_platform, class_data_off) # AFAIK
			# 1st arg was self.data.file.platform
			# "bv.platform" - "bv" is not defined
			# "self.platform" - might be valid....???

			print "class_data_off:", hex(class_data_off)


		print "\n===============================\n"

		class_def_item = {
			"class_idx": 0,
			"access_flags": 0,
			"superclass_idx": 0,
			"interfaces_off": 0,
			"source_file_idx": 0,
			"annotations_off": 0,
			"class_data_off": 0,
			"static_values_off": 0
		}

		# TODO: get list of "class_data_off" items (a struct with 8 uints)
		#print "class_def_item"


	# GREPME
	# format: uint
	# TODO - validate
	def class_defs_size(self):
		offset = 96 # AFAIK

		result = self.binary_blob[offset: offset+4]
		result = struct.unpack("<I", result)[0]

		#print "\nclass_defs_size: ", result, "\n"

		return result

	# format: uint
	# TODO - validate
	# offset from the start of the file to the class definitions list, or 0 if class_defs_size == 0 (admittedly a strange edge case). The offset, if non-zero, should be to the start of the class_defs section.
	def class_defs_off(self):
		offset = 100 # AFAIK

		result = self.binary_blob[offset: offset+4]
		result = struct.unpack("<I", result)[0]

		#print "\nclass_defs_off: ", result, "\n"

		assert result < self.binary_blob_length

		return result

	# dataSize, dataOff (108)
	# TODO - validate

	# complicated - becaus
	def dataSize(self):
		offset = 104 # unknown if this is correct..
		_dataOff = self.binary_blob[offset: offset+4]

		return struct.unpack("<I", _dataOff)[0] # TODO: verify

	# TODO - validate
	def dataOff(self):
		offset = 108 # I believe this is correct
		_dataOff = self.binary_blob[offset:offset + 4]

		# print len(_dataOff)
		assert len(_dataOff) > 0 # TODO: be more specific

		return struct.unpack("<I", _dataOff)[0] # TODO: verify

# https://source.android.com/devices/tech/dalvik/dex-format.html - VERY GOOD RESOURCE
# Decompiling Android book is very useful, but it's 4 years old..
# ~/Documents/dexinfo/a.out
'''
.dex
	header
	strings_ids
	type_ids
	proto_ids
	fields
	methods
	classes
	data

'''

# TODO: DexFile should be passed bv.binary.raw, and parse that...

# class_data_item - the juicy item AFAIK
#	* referenced in class_def_item
#	* appears in the data section
#	* alignment: none (byte-aligned)

class DexFile(dexHeader):
	def __init__(self, binary_blob, binary_blob_length): # data is binaryView
		self.binary_blob = binary_blob
		self.binary_blob_length = binary_blob_length

		dexHeader.__init__(self, binary_blob, binary_blob_length)

	'''
	header
		self.magic() - believed correct
		self.checksum() - validated
		self.signature() - validated
		self.file_size() - validated
		self.header_size  - validated
		endian_tag - skipped
		link_size
		link_offset
		map_offset
		string_ids_size
		string_ids_offset
		type_ids_size
		type_ids_offset
		proto_ids_size
		proto_ids_offset
		field_ids_size
		field_ids_offset
		method_ids_size
		method_ids_offset
		class_defs_size
		class_defs_offset
		data_size
		data_offset
	'''
	def header(self):
		results = []

		results += [self.magic()]
		results += [self.checksum()]
		results += [self.signature()]
		results += [self.file_size()]

		pass

	# I believe "data" is the whole file
	def print_metadata(self):
		# https://docs.python.org/2/library/struct.html
		# pretty sure we want "unpack" to take binary string, and print in readable format

		# DexHeader
		# FIXME: we now inheirit these functions, which may need to be renamed to DexHeader_magic, dex_header_checksum, etc...
		print "magic: ", self.magic()
		print "checksum: ", self.checksum()
		print "signature: ", self.signature()
		print "file_size: ", self.file_size()
		print "header_size: ", self.header_size()

		# unvalidated
		self.class_defs() # return object that includes: size, off
		#print "class_defs_size: ",  # currently testing
		#print "class_defs_off: ", self.class_defs() # currently testing

		print "protoIdsOff: ", self.protoIdsOff()
		print "methodIdsOff: ", self.methodIdsOff()
		print "dataSize: ", self.dataSize()
		#print "dataOff: ", self.dataOff()


		# the following may be wrong -
		'''
		print "="*50
		print "fileSize: ", dex_data.fileSize()
		print "protoIdsOff", dex_data.protoIdsOff()
		print "methodIdsOff", dex_data.methodIdsOff()
		print "dataOff", dex_data.dataOff()
		'''

		print "="*50

		#print "fileSize (?): ", fileSize
		print ""


	def getData(self):
		# dataOffset is in dexHeader (I think) - pull the data starting at the offset and figure out what it is

		pass
