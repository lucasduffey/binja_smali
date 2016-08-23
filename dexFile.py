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

reference: https://github.com/ondreji/dex_parser/blob/master/dex.py

IMPORTANT
.read(offset, 4) # last arg is the "count", not the "last idex to read"

uleb128 - unsigned LEB128, variable-length
	* consists of one to five bytes, which represent a single 32-bit value
'''

# sizes of fields
# look at dex.c -  DexHeader is the first header (is what it really seems to be)
# https://docs.python.org/2/library/struct.html
# https://gist.github.com/ezterry/1239615

# Little-Endian Base 128 - consists of one to five bytes, which represent a single 32-bit value
# data should be five bytes

# return value, size_of_ULEB128
def get_ULEB128(data):
	# the first bit of each byte is 1, unless that's the last byte
	total = 0
	found = False

	#print "=============="
	#print "ULEB128"
	#print "type(data): ", type(data)
	#print "len(data): ", len(data)

	for i in xrange(5):
		value = ord(data[i])

		value = value & 0x7f # clear the high bit
		total += value << (i * 7) | total

		#print "value: 0x%x" % value
		#print "value: %i" % value

		# this is the last byte, so break
		if (value >> 7) == 1:
			found = True
			break

	if i == 4 and not found:
		log(4, "invalid ULEB128")
		assert False

	# return (value, num_of_bytes) # where num_of_bytes indicates how much space this LEB128 took up
	return total, i+1

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

	########################################

	# string_ids_size, string_ids_off
	def string_ids(self):
		string_ids_size_offset = 56
		string_ids_off_offset = 60

		string_ids_size = self.binary_blob[string_ids_size_offset: string_ids_size_offset+4]
		string_ids_size = struct.unpack("<I", string_ids_size)[0]
		# FIXME: loot at class_defs for how to calculate size in bytes

		string_ids_off = self.binary_blob[string_ids_off_offset: string_ids_off_offset+4]
		string_ids_off = struct.unpack("<I", string_ids_off)[0]

	# type_ids_size, type_ids_off
	def type_ids(self):
		type_ids_size_offset = 64
		type_ids_off_offset = 68

		type_ids_size = self.binary_blob[type_ids_size_offset: type_ids_size_offset+4]
		type_ids_size = struct.unpack("<I", type_ids_size)[0]
		# FIXME: loot at class_defs for how to calculate size in bytes

		type_ids_off = self.binary_blob[type_ids_off_offset: type_ids_off_offset+4]
		type_ids_off = struct.unpack("<I", type_ids_off)[0]

	# pulls proto_ids_size, proto_ids_off
	def proto_ids(self):
		proto_ids_size_offset = 72
		proto_ids_off_offset = 76

		proto_ids_size = self.binary_blob[proto_ids_size_offset: proto_ids_size_offset+4]
		proto_ids_size = struct.unpack("<I", proto_ids_size)[0]
		# FIXME: loot at class_defs for how to calculate size in bytes

		proto_ids_off = self.binary_blob[proto_ids_off_offset: proto_ids_off_offset+4]
		proto_ids_off = struct.unpack("<I", proto_ids_off)[0]

	# pulls field_ids_size, field_ids_off
	def field_ids(self):
		field_ids_size_offset = 80
		field_ids_off_offset = 84

		field_ids_size = self.binary_blob[field_ids_size_offset: field_ids_size_offset+4]
		field_ids_size = struct.unpack("<I", field_ids_size)[0]
		# FIXME: loot at class_defs for how to calculate size in bytes

		field_ids_off = self.binary_blob[field_ids_off_offset: field_ids_off_offset+4]
		field_ids_off = struct.unpack("<I", field_ids_off)[0]


	# TODO - validate
	# pulls method_ids_size, method_ids_off
	def method_ids(self):
		method_ids_size_offset = 88
		method_ids_off_offset = 92

		method_ids_size = self.binary_blob[method_ids_size_offset: method_ids_size_offset+4]
		method_ids_size = struct.unpack("<I", method_ids_size)[0]
		# FIXME: loot at class_defs for how to calculate size in bytes

		method_ids_off = self.binary_blob[method_ids_off_offset: method_ids_off_offset+4]
		method_ids_off = struct.unpack("<I", _methodIdsOff)[0]

		# TODO: now carve out method_ids
		method_ids_data = self.binary_blob[method_ids_off: method_ids_off+method_ids_size]

	# each class_defs instance has a "class_data_off" field, this field is the offset to a "class_data_item" which has a direct_methods which has "code_off"
	#
	# header:
	#	* class_defs_size
	#	* class_defs_off
	#
	# return list of class_def_item objects
	def class_defs(self):
		class_defs_size_offset = 96 # AFAIK
		class_defs_off_offset = 100 # AFAIK

		class_defs_size = self.binary_blob[class_defs_size_offset: class_defs_size_offset+4]
		class_defs_size = struct.unpack("<I", class_defs_size)[0]

		class_defs_off = self.binary_blob[class_defs_off_offset: class_defs_off_offset+4]
		class_defs_off = struct.unpack("<I", class_defs_off)[0]

		print "\n===============================\n"
		print "class_defs_size: ", class_defs_size, "\n"
		print "class_defs_off: ", hex(class_defs_off), "\n"

		# class_def_items will store the class_def_items, see "class_def_item" @ https://source.android.com/devices/tech/dalvik/dex-format.html
		_class_defs_bytes = class_defs_size*8*4 # class_def_item has 8 uints
		raw_class_defs = self.binary_blob[class_defs_off: class_defs_off+ _class_defs_bytes]

		#
		# FIXME: class_def_items is not returning 8
		#

		# split by class_def_item_size
		class_def_item_size = 8*4 # 8 uints
		class_def_items = [self.class_def_item(raw_class_defs[i:i+class_def_item_size]) for i in range(0, len(raw_class_defs), class_def_item_size)]

		# list of class_def_item objects
		return class_def_items

	# dataSize, dataOff (108)
	# TODO - validate

	# collision?
	# handles data_size, data_off
	def data(self):
		data_size_offset = 104
		data_off_offset = 108

		data_size = self.binary_blob[data_off_offset: data_off_offset+4]
		data_size = struct.unpack("<I", data_size)[0]
		# FIXME: loot at class_defs for how to calculate size in bytes

		data_off = self.binary_blob[data_off_offset:data_off_offset + 4]
		data_off = struct.unpack("<I", data_off)[0]

	def link_data(self):
		print "link_data not yet implemented"
		assert False


	###########################
	# helper functions
	###########################
	class class_def_item():
		def __init__(self, binary_blob):
			# class_def_item should be 32 bytes
			if len(binary_blob) != 32:
				print "len(binary_blob): ", len(binary_blob)
				assert len(binary_blob) == 32

			self.class_idx = struct.unpack("<I", binary_blob[0:4])[0]
			self.access_flags = struct.unpack("<I", binary_blob[4:8])[0]
			self.superclass_idx = struct.unpack("<I", binary_blob[8:12])[0]
			self.interfaces_off = struct.unpack("<I", binary_blob[12:16])[0]
			self.source_file_idx = struct.unpack("<I", binary_blob[16:20])[0]
			self.annotations_off = struct.unpack("<I", binary_blob[20:24])[0]
			self.class_data_off = struct.unpack("<I", binary_blob[24:28])[0]
			self.static_values_off = struct.unpack("<I", binary_blob[28:32])[0]


	# name					| format
	# =========================================
	# static_fields_size	| uleb128
	# instance_fields_size	| uleb128
	# direct_methods_size	| uleb128
	# virtual_methods_size	| uleb128
	# static_fields			| encoded_field[static_fields_size]
	# instance_fields		| encoded_field[instance_fields_size]
	# direct_methods		| encoded_method[direct_methods_size]
	# virtual_methods		| encoded_method[virtual_methods_size]
	class class_data_item():
		# the size of this item is unknown, which is why it's passed an offset
		def __init__(self, binary_blob, offset):
			#self.size = 0 # unknown so-far, VERY ANNOYING TO CALCULATE
			self.binary_blob = binary_blob
			self.offset = offset # NEVER MODIFY THIS

			# pull four ULEB128s
			print "type(offset): ", type(offset) # string - WTF
			print "offset: ", offset

			self.static_fields_size, static_fields_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5]) # ULEB128 can be up to 5 bytes long
			offset += static_fields_ULEB128_size

			self.instance_fields_size, instance_fields_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5]) # ULEB128 can be up to 5 bytes long
			offset += instance_fields_ULEB128_size

			self.direct_methods_size, direct_methods_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5]) # ULEB128 can be up to 5 bytes long
			offset += direct_methods_ULEB128_size

			self.virtual_methods_size, virtual_methods_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5]) # ULEB128 can be up to 5 bytes long
			offset += virtual_methods_ULEB128_size

			# save data field offsets
			self.static_fields_off = offset

			self.static_fields() # populate self.instance_fields_off
			self.instance_fields() # populate self.direct_methods_off
			self.direct_methods() # populate self.virtual_methods_off
			self.virtual_methods() # populate self.size


		# static_fields	encoded_field[static_fields_size]
		# for now returning a list of dict
		def static_fields(self):
			offset = self.static_fields_off

			results = []
			for i in xrange(self.static_fields_size):
				field_idx_diff, field_idx_diff_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += field_idx_diff_ULEB128_size

				access_flags, access_flags_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += field_idx_diff_ULEB128_size

				result = {
					"field_idx_diff": field_idx_diff,
					"access_flags": access_flags
				}
				results.append(result)

			self.instance_fields_off = offset

			# return list of dicts
			return results


		# instance_fields	encoded_field[instance_fields_size]
		def instance_fields(self):
			offset = self.instance_fields_off

			results = []
			for i in xrange(self.instance_fields_size):
				field_idx_diff, field_idx_diff_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += field_idx_diff_ULEB128_size

				access_flags, access_flags_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += field_idx_diff_ULEB128_size

				result = {
					"field_idx_diff": field_idx_diff,
					"access_flags": access_flags
				}
				results.append(result)

			self.direct_methods_off = offset

			# return list of dicts
			return results

		# direct_methods	encoded_method[direct_methods_size]
		# TODO: populate self.virtual_methods_off
		def direct_methods(self):
			offset = self.direct_methods_off

			results = []
			for i in xrange(self.direct_methods_size):
				method_idx_diff, method_idx_diff_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += method_idx_diff_ULEB128_size

				access_flags, access_flags_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += access_flags_ULEB128_size

				code_off, code_off_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += code_off_ULEB128_size

				result = {
					"method_idx_diff": method_idx_diff,
					"access_flags": access_flags,
					"code_off": code_off # GREPME
				}

			self.virtual_methods_off = offset

			# return list of dicts
			return results

		# virtual_methods	encoded_method[virtual_methods_size]
		def virtual_methods(self):
			offset = self.virtual_methods_off

			results = []
			for i in xrange(self.virtual_methods_size): #
				method_idx_diff, method_idx_diff_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += method_idx_diff_ULEB128_size

				access_flags, access_flags_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += access_flags_ULEB128_size

				code_off, code_off_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += code_off_ULEB128_size

				result = {
					"method_idx_diff": method_idx_diff,
					"access_flags": access_flags,
					"code_off": code_off # GREPME
				}

			self.size = offset - self.offset # TODO: validate this...

			# return list of dicts
			return results


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
		#class_defs_obj = self.class_defs() # return list of objects that includes: size, off
		#for class_def in class_defs_obj:

		#	class_data_item_obj = class_data_item(class_def.class_data_off)

		#	for direct_method in class_data_item_obj.direct_methods(): # TODO: what do I do with this?
		#		# direct_method.code_off

		#	for virtual_method in class_data_item_obj.virtual_methods() # TODO: what do I do with this?
		#		# virtual_method.code_off



	def getData(self):
		# dataOffset is in dexHeader (I think) - pull the data starting at the offset and figure out what it is

		pass
