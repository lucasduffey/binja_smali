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
# https://docs.python.org/2/library/struct.html
# https://gist.github.com/ezterry/1239615

'''
Item Type	Constant	Value	Item Size In Bytes
header_item	TYPE_HEADER_ITEM	0x0000	0x70
string_id_item	TYPE_STRING_ID_ITEM	0x0001	0x04
type_id_item	TYPE_TYPE_ID_ITEM	0x0002	0x04
proto_id_item	TYPE_PROTO_ID_ITEM	0x0003	0x0c
field_id_item	TYPE_FIELD_ID_ITEM	0x0004	0x08
method_id_item	TYPE_METHOD_ID_ITEM	0x0005	0x08
class_def_item	TYPE_CLASS_DEF_ITEM	0x0006	0x20
map_list	TYPE_MAP_LIST	0x1000	4 + (item.size * 12)
type_list	TYPE_TYPE_LIST	0x1001	4 + (item.size * 2)
annotation_set_ref_list	TYPE_ANNOTATION_SET_REF_LIST	0x1002	4 + (item.size * 4)
annotation_set_item	TYPE_ANNOTATION_SET_ITEM	0x1003	4 + (item.size * 4)
class_data_item	TYPE_CLASS_DATA_ITEM	0x2000	implicit; must parse
code_item	TYPE_CODE_ITEM	0x2001	implicit; must parse
string_data_item	TYPE_STRING_DATA_ITEM	0x2002	implicit; must parse
debug_info_item	TYPE_DEBUG_INFO_ITEM	0x2003	implicit; must parse
annotation_item	TYPE_ANNOTATION_ITEM	0x2004	implicit; must parse
encoded_array_item	TYPE_ENCODED_ARRAY_ITEM	0x2005	implicit; must parse
annotations_directory_item	TYPE_ANNOTATIONS_DIRECTORY_ITEM	0x2006	implicit; must parse
'''
ItemType = {
	0x0000: "header_item",
	0x0001: "string_id_item",
	0x0002: "type_id_item",
	0x0003: "proto_id_item",
	0x0004: "field_id_item",
	0x0005: "method_id_item",
	0x0006: "class_def_item",
	0x1000: "map_list",
	0x1001: "type_list",
	0x1002: "annotation_set_ref_list",
	0x1003: "annotation_set_item",
	0x2000: "class_data_item",
	0x2001: "code_item",
	0x2002: "string_data_item",
	0x2003: "debug_info_item",
	0x2004: "annotation_item",
	0x2005: "encoded_array_item",
	0x2006: "annotations_directory_item"
}

# Little-Endian Base 128 - consists of one to five bytes, which represent a single 32-bit value
# data should be five bytes

# return value, size_of_ULEB128
def read_ULEB128(data):
	# the first bit of each byte is 1, unless that's the last byte
	total = 0
	found = False

	# so technically it doesn't have to be 5...
	assert len(data) == 5

	#print "=============="
	#print "ULEB128"
	#print "type(data): ", type(data)
	#print "len(data): ", len(data)

	#p =  ["value: "]
	for i in xrange(5):
		value = ord(data[i])
		high_bit = (ord(data[i]) >> 7)

		# clear the high bit
		total += (value & 0x7f) << (i * 7) | total

		#p.append("0x%x " % value)
		#print "value: %i" % value

		# this is the last byte, so break
		if high_bit == 0:
			found = True
			break

	#print "".join(p)

	if i == 4 and not found:
		log(4, "invalid ULEB128")
		assert False

	# return (value, num_of_bytes) # where num_of_bytes indicates how much space this LEB128 took up
	return total, i+1


# http://llvm.org/docs/doxygen/html/LEB128_8h_source.html
def read_sleb128(data):
	
	assert False

class DexFile():
	def __init__(self, binary_blob, binary_blob_length): # data is binaryView
		self.binary_blob = binary_blob
		self.binary_blob_length = binary_blob_length

		# just map everything in..
		self.map_list()

	'''
	header
		self.magic() - believed correct
		self.checksum() - validated
		self.signature() - validated
		self.file_size() - validated
		self.header_size - validated
		endian_tag - validated

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
		print "endian_tag: ", self.endian_tag()

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

		result = self.read_uint(offset)

		idx_start = offset+checksum_size
		idx_end = idx_start + self.file_size() - offset - checksum_size
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
		offset = 12
		signature_size = 20

		result = self.binary_blob[offset: offset+signature_size]
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

		result = self.read_uint(offset)

		# dex file validation
		if result != self.binary_blob_length:
			print "file_size method: ", hex(result), ", self.file.raw: ", hex(binary_blob_length)
			assert False

		# binary string => unsigned int
		return result

	# format: unit = 0x70
	def header_size(self):
		offset = 36
		result = self.read_uint(offset)

		if result != 0x70:
			print "header_size: ", result
			assert False

		return 0x70

	# format: uint = 0x12345678
	def endian_tag(self):
		offset = 40
		ENDIAN_CONSTANT = 0x12345678

		result = self.read_uint(offset)
		if result != ENDIAN_CONSTANT:
			print "endian_tag: ", result
			assert False

		return result

	###############################################3

	# TODO - can it be validated?
	# format: uint
	def link_size(self):
		offset = 44
		result = self.read_uint(offset)

		return result

	# TODO - can it be validated?
	# format: uint
	def link_off(self):
		offset = 48

		result = self.read_uint(offset)
		return result

	# TODO - validate
	# format: uint
	# Purpose: offset from the start of the file to the map item. The offset, which must be non-zero, should be to an offset into the data section,
	#  				and the data should be in the format specified by "map_list" below.
	# Questions: what is the "map item"?
		# VERY IMPORTANT FUNCTION - simplifies everything
	def map_off(self):
		offset = 52

		result = self.read_uint(offset)

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

		string_ids_size = self.read_uint(string_ids_size_offset)
		# FIXME: loot at class_defs for how to calculate size in bytes

		string_ids_off = self.read_uint(string_ids_off_offset)

		strings = []
		for i in xrange(string_ids_size):
			string_data_off = self.read_uint(string_ids_off)

			string = self.read_string(string_data_off)
			strings.append(string)

			#string_data_offs.append(string_data_off)
			string_ids_off += 4

		return strings

	# TODO: implement
	# type_ids_size, type_ids_off
	def type_ids(self):
		type_ids_size_offset = 64
		type_ids_off_offset = 68

		type_ids_size = self.read_uint(type_ids_size_offset)
		# FIXME: loot at class_defs for how to calculate size in bytes

		type_ids_off = self.read_uint(type_ids_off_offset)

	# TODO: implement
	# pulls proto_ids_size, proto_ids_off
	def proto_ids(self):
		proto_ids_size_offset = 72
		proto_ids_off_offset = 76

		proto_ids_size = self.read_uint(proto_ids_size_offset)
		# FIXME: loot at class_defs for how to calculate size in bytes

		proto_ids_off = self.read_uint(proto_ids_off_offset)

	# TODO: implement
	# pulls field_ids_size, field_ids_off
	def field_ids(self):
		field_ids_size_offset = 80
		field_ids_off_offset = 84

		field_ids_size = self.read_uint(field_ids_size_offset)
		# FIXME: loot at class_defs for how to calculate size in bytes

		field_ids_off = self.read_uint(field_ids_off_offset)


	# TODO - validate
	# pulls method_ids_size, method_ids_off
	# method_ids	method_id_item[]
	def method_ids(self):
		method_ids_size_offset = 88
		method_ids_off_offset = 92

		method_ids_size = self.read_uint(method_ids_size_offset)
		method_ids_off = self.read_uint(method_ids_off_offset)

		methods = []
		for i in xrange(method_ids_size):
			# Name			| Format	| Description
			############################################
			# class_idx		| ushort	| index into the type_ids list for the definer of this method. This must be a class or array type, and not a primitive type.
			# proto_idx		| ushort	| index into the proto_ids list for the prototype of this method
			# name_idx		| uint		| index into the string_ids list for the name of this method. The string must conform to the syntax for MemberName, defined above.

			# now carve out method_id_item
			method = {
				"class_idx": self.read_ushort(method_ids_off), # struct.unpack("<H", method_ids_data[0:2])[0],
				"proto_idx": self.read_ushort(method_ids_off+2), # struct.unpack("<H", method_ids_data[2:4])[0],
				"name_idx": self.read_uint(method_ids_off+4) # struct.unpack("<I", method_ids_data[4:8])[0], # index into the string_ids
			}
			method_ids_off += 8

			methods.append(method)

		return methods

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
		map_list_size = self.read_uint(offset)
		offset += 4

		# map_items are 12 bytes

		map_items = []

		print(3, "map_list_size: %i" % map_list_size) # only 17 - this can't be right..
		self.strings = []
		self.codes = []


		for i in xrange(map_list_size): # FIXME: does this include the last item?
			# Name		| Format	| Description
			##############################################################################
			# type		| ushort	| type of the items; see table below
			# unused	| ushort	| (unused)
			# size		| uint		| count of the number of items to be found at the indicated offset
			# offset	| uint		| offset from the start of the file to the items in question

			# map_item
			map_type = self.read_ushort(offset) # yes this is a ushort
			map_size = self.read_uint(offset+4)
			map_offset = self.read_uint(offset+8)
			offset += 12

			# string_id_item works
			if ItemType[map_type] == "string_id_item": # I don't think we care about "string_data_item" for now (but that may fix the string_list[idx] problem)
				for i in range(map_size):
					# map_offset points to a string_id_item
					string_off = self.read_uint(map_offset + i*4)

					string = self.read_string(string_off)
					self.strings.append(string)

			elif ItemType[map_type] == "code_item":
				log(3, "there are %i code_items" % map_size)
				for i in range(map_size):
					code_off = self.read_uint(map_offset + i*4)

					# TODO: I need to determine the size of the code_item

 					code = self.code_item(code_off)

					self.codes.append(code)


			map_item = {
				"type": map_type,
				"size": map_size,
				"offset": map_offset,
			}
			map_items.append(map_item)


		#log(3, "string_count: %i" % string_count) # returning 0

			# TypeItem[map_type] # will print what it actually is..


	# each class_defs instance has a "class_data_off" field, this field is the offset to a "class_data_item" which has a direct_methods which has "code_off"
	#
	# header:
	#	* class_defs_size
	#	* class_defs_off
	#
	# return list of class_def_item objects
	def class_defs(self): # seems ok
		class_defs_size_offset = 96 # VERIFIED
		class_defs_off_offset = 100 # VERIFIED

		class_defs_size = self.read_uint(class_defs_size_offset) # ok
		class_defs_off = self.read_uint(class_defs_off_offset) # ok

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

		class_def_item_size = 0x20 # 0x20 is 32 decimal, the class_def_item size in bytes

		class_def_items = []
		for i in range(class_defs_size):
			item = self.class_def_item(class_defs_off)
			class_defs_off += class_def_item_size

			class_def_items.append(item)

		# list of class_def_item objects
		return class_def_items


	# collision?
	# handles data_size, data_off
	def data(self):
		data_size_offset = 104
		data_off_offset = 108

		data_size = self.read_uint(data_size_offset)
		# FIXME: loot at class_defs for how to calculate size in bytes

		data_off = self.read_uint(data_off_offset)

	def link_data(self):
		print "link_data not yet implemented"
		assert False


	###########################
	# helper functions
	###########################
	def read_uint(self, offset):
		return struct.unpack("<I", self.binary_blob[offset:offset+4])[0]

	def read_ushort(self, offset):
		return struct.unpack("<H", self.binary_blob[offset:offset+2])[0]

	# wrapper function
	def read_ULEB128(self, offset):
		return read_ULEB128(self.binary_blob[offset:offset+5])

	def read_string(self, offset):
		string_result = [""]

		# lets just find the string...
		while self.binary_blob[offset] != "\x00":
			string_result.append(self.binary_blob[offset])
			offset += 1

		return "".join(string_result)

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
		registers_size = self.read_ushort(offset) # binary_blob[offset:offset+2]
		ins_size = self.read_ushort(offset+2) # self.binary_blob[offset:offset+2]
		outs_size = self.read_ushort(offset+4) # self.binary_blob[offset:offset+2]
		tries_size = self.read_ushort(offset+6) # self.binary_blob[offset:offset+2]
		debug_info_off = self.read_uint(offset+8) # self.binary_blob[offset:offset+4]
		insns_size = self.read_uint(offset+12) # struct.unpack("<I", self.binary_blob[offset:offset+4])[0]
		offset += 16
		#print "insns_size: ", insns_size

		# pretty sure this is correct
		insns_off = offset

		#insns = self.binary_blob[insns_off:insns_off+(insns_size*2)] # the actual dex code, but lets not save as variable unless we need to

		offset += (insns_size*2)

		# optional padding
		if (tries_size != 0) and (insns_size % 2 == 1):
			offset += 2

		# tries
		#tries =  # each "tries" is 8 bytes
		offset += tries_size * 8

		# handlers
		if tries_size != 0:
			val, handlers_size = self.read_ULEB128(offset)
			offset += size

			handlers = []
			for i in range(handlers_size):
				# read an "encoded_catch_handler" struct

				# what's a "sleb128"
				#encoded_catch_handler_size = read_sleb128() # FIXME: need to create read_sleb128 wrapper

				assert False # lots to do here
				pass

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

	def class_def_item(self, offset):
		return {
			"class_idx": self.read_uint(offset), # struct.unpack("<I", binary_blob[0:4])[0]
			"access_flags": self.read_uint(offset+4), # struct.unpack("<I", binary_blob[4:8])[0]
			"superclass_idx": self.read_uint(offset+8), # struct.unpack("<I", binary_blob[8:12])[0]
			"interfaces_off": self.read_uint(offset+12), # struct.unpack("<I", binary_blob[12:16])[0]
			"source_file_idx": self.read_uint(offset+16), # struct.unpack("<I", binary_blob[16:20])[0]
			"annotations_off": self.read_uint(offset+20), # struct.unpack("<I", binary_blob[20:24])[0]
			"class_data_off": self.read_uint(offset+24), # struct.unpack("<I", binary_blob[24:28])[0]
			"static_values_off": self.read_uint(offset+28) # struct.unpack("<I", binary_blob[28:32])[0]
		}


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
		def __init__(self, binary_blob, binary_blob_length, offset):
			if offset > binary_blob_length:
				log(3, "length: %i, binary_blob_length: %i" % (offset, binary_blob_length))
				assert False

			#self.size = 0 # unknown so-far, VERY ANNOYING TO CALCULATE
			self.binary_blob = binary_blob
			self.binary_blob_length = binary_blob_length
			self.offset = offset # NEVER MODIFY THIS

			# pull four ULEB128s
			#print "type(offset): ", type(offset)
			#print "offset: ", offset

			self.static_fields_size, static_fields_ULEB128_size = self.read_ULEB128(offset) # self.binary_blob[offset:offset+5]) # ULEB128 can be up to 5 bytes long
			offset += static_fields_ULEB128_size

			self.instance_fields_size, instance_fields_ULEB128_size = self.read_ULEB128(offset) # read_ULEB128(self.binary_blob[offset:offset+5]) # ULEB128 can be up to 5 bytes long
			offset += instance_fields_ULEB128_size

			self.direct_methods_size, direct_methods_ULEB128_size = self.read_ULEB128(offset) # read_ULEB128(self.binary_blob[offset:offset+5]) # ULEB128 can be up to 5 bytes long
			offset += direct_methods_ULEB128_size

			self.virtual_methods_size, virtual_methods_ULEB128_size = self.read_ULEB128(offset) # read_ULEB128(self.binary_blob[offset:offset+5]) # ULEB128 can be up to 5 bytes long
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
				field_idx_diff, field_idx_diff_ULEB128_size = self.read_ULEB128(offset) # read_ULEB128(self.binary_blob[offset:offset+5])
				offset += field_idx_diff_ULEB128_size

				access_flags, access_flags_ULEB128_size = self.read_ULEB128(offset) # read_ULEB128(self.binary_blob[offset:offset+5])
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
				field_idx_diff, field_idx_diff_ULEB128_size = self.read_ULEB128(offset) # read_ULEB128(self.binary_blob[offset:offset+5])
				offset += field_idx_diff_ULEB128_size

				access_flags, access_flags_ULEB128_size = self.read_ULEB128(offset) # read_ULEB128(self.binary_blob[offset:offset+5])
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
			print(4, "self.direct_methods_size: %i" % self.direct_methods_size)
			for i in xrange(self.direct_methods_size):
				method_idx_diff, method_idx_diff_ULEB128_size = self.read_ULEB128(offset) # read_ULEB128(self.binary_blob[offset:offset+5])
				offset += method_idx_diff_ULEB128_size

				access_flags, access_flags_ULEB128_size = self.read_ULEB128(offset) # read_ULEB128(self.binary_blob[offset:offset+5])
				offset += access_flags_ULEB128_size

				# FIXME: code_off value is wrong
				code_off, code_off_ULEB128_size = self.read_ULEB128(offset) # read_ULEB128(self.binary_blob[offset:offset+5])
				offset += code_off_ULEB128_size

				#assert code_off < self.binary_blob_length
				#log(3, "code_off: %i" % code_off)
				if code_off < self.binary_blob_length:
					continue
					#assert False

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
				method_idx_diff, method_idx_diff_ULEB128_size = self.read_ULEB128(offset) # read_ULEB128(self.binary_blob[offset:offset+5])
				offset += method_idx_diff_ULEB128_size

				access_flags, access_flags_ULEB128_size = self.read_ULEB128(offset) # read_ULEB128(self.binary_blob[offset:offset+5])
				offset += access_flags_ULEB128_size

				# FIXME: code_off value is wrong
				code_off, code_off_ULEB128_size = self.read_ULEB128(offset) # read_ULEB128(self.binary_blob[offset:offset+5])
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


		###########################
		# helper functions
		###########################
		def read_uint(self, offset):
			return struct.unpack("<I", self.binary_blob[offset:offset+4])[0]

		def read_ushort(self, offset):
			return struct.unpack("<H", self.binary_blob[offset:offset+2])[0]

		# wrapper function
		def read_ULEB128(self, offset):
			return read_ULEB128(self.binary_blob[offset:offset+5])


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
