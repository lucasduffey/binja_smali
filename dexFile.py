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

	#p =  ["value: "]
	for i in xrange(5):
		value = ord(data[i])

		value = value & 0x7f # clear the high bit
		total += value << (i * 7) | total

		#p.append("0x%x " % value)
		#print "value: %i" % value

		# this is the last byte, so break
		if (ord(data[i]) >> 7) == 0:
			found = True
			break

	#print "".join(p)

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
		offset = 40

		# int ENDIAN_CONSTANT = 0x12345678;

		print "endian_tag isn't implemented"
		assert False

	# TODO - validate
	# format: uint
	def link_size(self):
		offset = 44
		pass

	# TODO - validate
	# format: uint
	def link_off(self):
		offset = 48
		pass

	# TODO - validate
	# format: uint
	# Purpose: offset from the start of the file to the map item. The offset, which must be non-zero, should be to an offset into the data section,
	#  				and the data should be in the format specified by "map_list" below.
	# Questions: what is the "map item"?
		# VERY IMPORTANT FUNCTION - simplifies everything
	def map_off(self):
		offset = 52

		result = self.binary_blob[offset: offset+4]
		result = struct.unpack("<I", result)[0] # uint

		# wait: should I do anything with this? probably not
		return result

	########################################

	# string_ids_size, string_ids_off
	# return list of strings
	# strings are encored in MUTF-8
	#	* Only the one-, two-, and three-byte encodings are used.
	#	* A plain null byte (value 0) indicates the end of a string, as is the standard C language interpretation.
	# TODO: cache results
	def string_ids(self):
		string_ids_size_offset = 56
		string_ids_off_offset = 60

		string_ids_size = self.binary_blob[string_ids_size_offset: string_ids_size_offset+4]
		string_ids_size = struct.unpack("<I", string_ids_size)[0]
		# FIXME: loot at class_defs for how to calculate size in bytes

		string_ids_off = self.binary_blob[string_ids_off_offset: string_ids_off_offset+4]
		string_ids_off = struct.unpack("<I", string_ids_off)[0]

		strings = []
		for i in xrange(string_ids_size):
			string_data_off = self.binary_blob[string_ids_off: string_ids_off+4]
			string_data_off = struct.unpack("<I", string_data_off)[0]

			null_byte_offset = string_data_off
			string_result = [""]

			# lets just find the string...
			while self.binary_blob[null_byte_offset] != "\x00":
				string_result.append(self.binary_blob[null_byte_offset])
				null_byte_offset += 1

			string_result = "".join(string_result)
			strings.append(string_result)

			#string_data_offs.append(string_data_off)
			string_ids_off += 4

		return strings

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


		###########################
		# HELPER FUNCTIONS
		###########################

		# Name	| Format			| Description
		######################################################
		# size	| uint				| size of the list, in entries
		# list	| map_item[size]	| elements of the list

		# SUPER CRITICAL
		def map_list(self):
			offset = self.map_off()

			map_list_size = self.binary_blob[offset: offset+4]
			map_list_size = struct.unpack("<I", map_list_size)[0]
			offset += 4

			# map_items are 12 bytes

			map_items = []

			for i in xrange(map_list_size): # FIXME: does this include the last item?
				# Name		| Format	| Description
				##############################################################################
				# type		| ushort	| type of the items; see table below
				# unused	| ushort	| (unused)
				# size		| uint		| count of the number of items to be found at the indicated offset
				# offset	| uint		| offset from the start of the file to the items in question

				map_item = self.binary_blob[offset: offset+12]



				# map_items.append()
				pass


	# each class_defs instance has a "class_data_off" field, this field is the offset to a "class_data_item" which has a direct_methods which has "code_off"
	#
	# header:
	#	* class_defs_size
	#	* class_defs_off
	#
	# return list of class_def_item objects
	def class_defs(self):
		class_defs_size_offset = 96 # VERIFIED
		class_defs_off_offset = 100 # VERIFIED

		# calculate class_defs_size - ok
		class_defs_size = self.binary_blob[class_defs_size_offset: class_defs_size_offset+4]
		class_defs_size = struct.unpack("<I", class_defs_size)[0]

		# calculate class_defs_off - ok
		class_defs_off = self.binary_blob[class_defs_off_offset: class_defs_off_offset+4]
		class_defs_off = struct.unpack("<I", class_defs_off)[0]

		print "\n===============================\n"
		print "class_defs_size: ", class_defs_size, "\n"
		print "class_defs_off: ", hex(class_defs_off), "\n"

		# class_def_items will store the class_def_items, see "class_def_item" @ https://source.android.com/devices/tech/dalvik/dex-format.html

		# Name				| 	Format
		# ========================================
		# class_idx	uint	|	uint
		# access_flags		| 	uint
		# superclass_idx	|	uint
		# interfaces_off	|	uint
		# source_file_idx	|	uint
		# annotations_off	|	uint
		# class_data_off	|	uint
		# static_values_off	|	uint

		class_def_item_size = 0x20 # 0x20 is class_def_item size in bytes

		# OK
		class_defs_byte_size = class_defs_size * class_def_item_size # class_defs_size indicates how many of them there are
		raw_class_defs = self.binary_blob[class_defs_off: class_defs_off+ class_defs_byte_size]

		# split by class_def_item_size - seems OK
		class_def_items = [self.class_def_item(raw_class_defs[i:i+class_def_item_size]) for i in range(0, len(raw_class_defs), class_def_item_size)]

		# list of class_def_item objects
		return class_def_items


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
			#print "type(offset): ", type(offset)
			#print "offset: ", offset

			#
			# TODO: the problem most likely with get_ULEB128
			#

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
			self.direct_methods() # populate self.virtual_methods_off # FIXME: is this right?
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


		# Name				| Format	| Description
		#########################################################
		# method_idx_diff	| uleb128	| index into the method_ids list for the identity of this method
		# access_flags		| uleb128	|
		# code_off			| uleb128	| offset from the start of the file to the code structure for this method, format of the data is specified by "code_item" below.

		# direct_methods	encoded_method[direct_methods_size]
		#  populate self.virtual_methods_off
		# FIXME: code_off is a data structure
		def direct_methods(self):
			offset = self.direct_methods_off # FIXME: is this correct?

			results = []
			for i in xrange(self.direct_methods_size):
				method_idx_diff, method_idx_diff_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += method_idx_diff_ULEB128_size

				access_flags, access_flags_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += access_flags_ULEB128_size

				# FIXME: code_off value is wrong
				code_off, code_off_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += code_off_ULEB128_size

				result = {
					"method_idx_diff": method_idx_diff,
					"access_flags": access_flags,
					"code_off": code_off # GREPME # FIXME: code_off is a data structure
				}
				results.append(result)

			self.virtual_methods_off = offset

			# return list of dicts
			return results

		# virtual_methods	encoded_method[virtual_methods_size]
		def virtual_methods(self):
			offset = self.virtual_methods_off # FIXME: is this correct?

			results = []
			for i in xrange(self.virtual_methods_size): #
				method_idx_diff, method_idx_diff_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += method_idx_diff_ULEB128_size

				access_flags, access_flags_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += access_flags_ULEB128_size

				# FIXME: code_off value is wrong
				code_off, code_off_ULEB128_size = get_ULEB128(self.binary_blob[offset:offset+5])
				offset += code_off_ULEB128_size

				result = {
					"method_idx_diff": method_idx_diff,
					"access_flags": access_flags,
					"code_off": code_off # GREPME
				}
				results.append(result)

			self.size = offset - self.offset # TODO: validate this...

			# return list of dicts
			return results


		# Name				| Format									| Description
		################################################################################
		# registers_size	| ushort									| number of registers used by this code
		# ins_size			| ushort						 			|
		# outs_size			| ushort								 	| number of words of outgoing argument space required by this co
		# tries_size		| ushort									| number of try_items for this instance.
		# debug_info_off	| uint										| offset from the start of the file to the debug info
		# insns_size		| uint										| size of the instructions list, in 16-bit code units
		# insns				| ushort[insns_size]						| actual array of bytecode.
		# padding			| ushort (optional) = 0						| two bytes of padding to make tries four-byte aligned.
		# tries				| try_item[tries_size] (optional)			| array indicating where in the code exceptions
		# handlers			| encoded_catch_handler_list (optional)		| bytes representing a list of lists

		# ushort == 2 bytes
		# FIXME: incomplete
		def code_item(self, offset):
			registers_size = self.binary_blob[offset:offset+2]
			offset += 2

			ins_size = self.binary_blob[offset:offset+2]
			offset += 2

			outs_size = self.binary_blob[offset:offset+2]
			offset += 2

			tries_size = self.binary_blob[offset:offset+2]
			offset += 2

			debug_info_off = self.binary_blob[offset:offset+4]
			offset += 4

			insns_size = self.binary_blob[offset:offset+4]
			insns_size = struct.unpack("<I", insns_size)[0]
			offset += 4


			insns_off = offset
			#insns = self.binary_blob[offset:offset+(insns_size*2)] # the actual dex code, but lets not save as variable unless we need to

			offset += (insns_size*2)

			# FIXME: need to handle "padding", "tries", and "handlers"

			result = {
				"registers_size": registers_size,
				"ins_size": ins_size,
				"outs_size": outs_size,
				"tries_size": tries_size,
				"debug_info_off": debug_info_off,
				"insns_size": insns_size,
				"insns_off": insns_off
				# "insns": insns
			}

			return result


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



	def getData(self):
		# dataOffset is in dexHeader (I think) - pull the data starting at the offset and figure out what it is

		pass
