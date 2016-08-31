from binaryninja import *
from dexFile import *
import struct
import traceback
import hashlib # to validate SHA1 signature
import zlib # to validate adler32 checksum
import os

DEX_MAGIC = "dex\x0a035\x00"

'''
# BEST REFERENCE
DEX Structure: https://source.android.com/devices/tech/dalvik/dex-format.html (best resource)
BYTECODE:   https://source.android.com/devices/tech/dalvik/dalvik-bytecode.html
            http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html

# OTHER REFERENCE
http://elinux.org/images/d/d9/A_deep_dive_into_dex_file_format--chiossi.pdf
https://android.googlesource.com/platform/art/+/master/tools/dexfuzz/src/dexfuzz/rawdex/HeaderItem.java
https://github.com/ondreji/dex_parser/blob/master/dex.py

IMPORTANT
.read(offset, 4) # last arg is the "count", not the "last idex to read"

DEX NOTES - design problems
* they use "size" when "count" for map_item
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
	0x0002: "type_id_item", # 4 byte aligned
	0x0003: "proto_id_item", # 4 byte aligned
	0x0004: "field_id_item", # 4 byte aligned
	0x0005: "method_id_item", # 4 byte aligned
	0x0006: "class_def_item",
	0x1000: "map_list",
	0x1001: "type_list", # 4 byte aligned
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

def four_byte_align(number):
	# 0x0, 0x4, 0x8, 0xc
	val = number & 0xF

	# already aligned: keep this code
	if val & 3 == 0:
		return number

	# AFAIK
	padding = (4 - (val & 3))
	return number + padding

# Little-Endian Base 128 - consists of one to five bytes, which represent a single 32-bit value
# data is up to five bytes
# return value, size_of_ULEB128
def read_uleb128(data):
	# the first bit of each byte is 1, unless that's the last byte
	total = 0
	found = False

	# so technically it doesn't have to be 5...
	if len(data) != 5:
		log(3, "read_uleb128, where len(data) == %i" % len(data))
		#assert len(data) == 5


	for i in xrange(5):
		value = ord(data[i])
		high_bit = (ord(data[i]) >> 7)

		# clear the high bit
		total += (value & 0x7f) << (i * 7) | total

		# this is the last byte, so break
		if high_bit == 0:
			found = True
			break

	if not found: # redundant to also check for "i == 4"?
		log(3, "invalid ULEB128")
		assert False

	# return (value, num_of_bytes) # where num_of_bytes indicates how much space this LEB128 took up
	return total, i+1

# http://llvm.org/docs/doxygen/html/LEB128_8h_source.html
# hex => decimal
###############3
# 00 => 0
# 01 => 1
# 7f => -1
# 80 7f => -128

def read_sleb128(data):
	total = 0
	found = False
	shift = 0

	# NOT SURE IF THIS IS RIGHT...
	for i in xrange(5):
		value = ord(data[i])
		high_bit = (ord(data[i]) >> 7)

		total |= (value & 0x7f) << shift
		shift += 7

		if high_bit == 0:
			found = True
			break

	if value & 0x40:
		total |= (-1) << shift

	if not found: # redundant to also check for "i == 4"?
		assert False

	return total, i+1

# test cases
assert read_sleb128("\x00")[0] == 0
assert read_sleb128("\x01")[0] == 1
assert read_sleb128("\x7f")[0] == -1
assert read_sleb128("\x80\x7f")[0] == -128


class dex_class:
	def __init__(self,dex_object, classId):
		if classId >= dex_object.class_defs_size:
			return ""
		offset = dex_object.class_defs_off + classId * struct.calcsize("8I")
		self.offset = offset
		format = "I"
		self.thisClass, = struct.unpack_from(format, dex_object.binary_blob, offset) # m_content => binary_blob
		offset += struct.calcsize(format)
		self.modifiers, = struct.unpack_from(format, dex_object.binary_blob, offset)
		offset += struct.calcsize(format)
		self.superClass, = struct.unpack_from(format, dex_object.binary_blob, offset)
		offset += struct.calcsize(format)
		self.interfacesOff, = struct.unpack_from(format, dex_object.binary_blob, offset)
		offset += struct.calcsize(format)
		self.sourceFileIdx, = struct.unpack_from(format, dex_object.binary_blob, offset)
		offset += struct.calcsize(format)
		self.annotationsOff, = struct.unpack_from(format, dex_object.binary_blob, offset)
		offset += struct.calcsize(format)
		self.classDataOff, = struct.unpack_from(format, dex_object.binary_blob, offset)
		offset += struct.calcsize(format)
		self.staticValuesOff, = struct.unpack_from(format, dex_object.binary_blob, offset)
		offset += struct.calcsize(format)
		self.index = classId
		self.interfacesSize = 0
		if self.interfacesOff != 0:
			self.interfacesSize, = struct.unpack_from("I", dex_object.binary_blob, self.interfacesOff)
		if self.classDataOff != 0:
			offset = self.classDataOff
			count,self.numStaticFields = read_uleb128(dex_object.binary_blob[offset:])
			offset += count
			count,self.numInstanceFields = read_uleb128(dex_object.binary_blob[offset:])
			offset += count
			count,self.numDirectMethods = read_uleb128(dex_object.binary_blob[offset:])
			offset += count
			count,self.numVirtualMethods = read_uleb128(dex_object.binary_blob[offset:])
		else:
			self.numStaticFields = 0
			self.numInstanceFields = 0
			self.numDirectMethods = 0
			self.numVirtualMethods = 0

	def format_classname(self, name):
		name = name[1:-1].replace("/","_")
		name = name.replace("$","_")
		return name

	def create_header_file_for_cplusplus(self, dex_object):
		typelist = []
		name = self.format_classname(dex_object.get_type_name(self.thisClass))
		f = open(name+".h","w")
		str1 =  "class %s"%name
		supername = dex_object.get_type_name(self.superClass)

		if dex_object.m_class_name_id.has_key(supername) :
			str1 += " : "
			supername = dex_object.get_type_name(self.superClass)
			str1 += self.format_classname(supername)
		str1 += "\n{\n"
		offset = self.classDataOff
		n,tmp = get_uleb128(dex_object.binary_blob[offset:offset+5])
		offset += n
		n,tmp = get_uleb128(dex_object.binary_blob[offset:offset+5])
		offset += n
		n,tmp = get_uleb128(dex_object.binary_blob[offset:offset+5])
		offset += n
		n,tmp = get_uleb128(dex_object.binary_blob[offset:offset+5])
		offset += n
		field_idx = 0
		prev_access = -1
		for i in xrange(0,self.numStaticFields):
			n,field_idx_diff = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			field_idx+=field_idx_diff

			n,modifiers = get_uleb128(dex_object.binary_blob[offset:offset+5])

			access_str,cur_access = dex_object.get_access_flags1(modifiers)
			if cur_access != prev_access:
				str1 += access_str
				str1 += "\n"
				prev_access = cur_access
			str1 += "\tconst "
			str1 += dex_object.getfieldfullname1(field_idx)
			if field_idx not in typelist:
				typelist.append(field_idx)
			offset += n
			if self.staticValuesOff:
				str1 += " = "
				staticoffset=get_static_offset(dex_object.binary_blob[self.staticValuesOff:],i)
				if staticoffset == -1:
					str1 += "0;\n"
					continue
				size,str2 = parse_encoded_value1(dex_object, dex_object.binary_blob[self.staticValuesOff+staticoffset:])
				str1 += str2
			str1 += ";\n"
		field_idx=0
		str1+="////////////////////////////////////////////////////////\n"
		for i in xrange(0,self.numInstanceFields):
			n,field_idx_diff = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			field_idx+=field_idx_diff
			n,modifiers = get_uleb128(dex_object.binary_blob[offset:offset+5])
			access_str,cur_access = dex_object.get_access_flags1(modifiers)
			if cur_access != prev_access:
				str1 += access_str
				str1 += "\n"
				prev_access = cur_access
			str1 += "\t"
			str1 += dex_object.getfieldfullname1(field_idx)
			if field_idx not in typelist:
				typelist.append(field_idx)
			str1 += ";\n"
			offset += n
		#print str1
		method_idx = 0
		prev_access = -1
		for i in xrange(0,self.numDirectMethods):
			n,method_idx_diff = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			n,access_flags = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			n,code_off = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			method_idx += method_idx_diff
			access_str,cur_access = dex_object.get_access_flags1(access_flags)
			if cur_access != prev_access:
				str1 += access_str
				str1 += "\n"
				prev_access = cur_access
			str1 += "\t"
			parameter_list=[]
			if code_off != 0:
				parameter_list = method_code(dex_object,code_off).get_param_list(dex_object)
			str1 += dex_object.getmethodfullname1(method_idx,parameter_list,True)
			#print "%s           codeoff=%x"%(dex_object.get_method_name(method_idx),code_off)
			str1 += ";\n"
		method_idx = 0
		str1+="//////////////////////virtual method//////////////////////////////////\n"
		for i in xrange(0,self.numVirtualMethods):
			n,method_idx_diff = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			n,access_flags = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			n,code_off = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			method_idx += method_idx_diff
			access_str,cur_access = dex_object.get_access_flags1(access_flags)
			if cur_access != prev_access:
				str1 += access_str
				str1 += "\n"
				prev_access = cur_access
			str1 +="\tvirtual "
			parameter_list=[]
			if code_off != 0:
				parameter_list = method_code(dex_object,code_off).get_param_list(dex_object)
			str1 += dex_object.getmethodfullname1(method_idx,parameter_list,True)
			str1 += ";\n"
		str1 += "}"
		#print str1
		f.write(str1)
		f.close()
		return typelist
	def printf(self,dex_object):
		#if dex_object.get_type_name(self.thisClass)!="Landroid/Manifest$permission;":
		#	return
		print "%-20s:%08x:%10d  %s"%("thisClass",self.thisClass,self.thisClass,dex_object.get_type_name(self.thisClass))
		print "%-20s:%08x:%10d  %s"%("superClass",self.superClass,self.superClass,dex_object.get_type_name(self.superClass))
		print "%-20s:%08x:%10d"%("modifiers",self.modifiers,self.modifiers)
		print "%-20s:%08x:%10d"%("offset",self.offset,self.offset)
		print "%-20s:%08x:%10d"%("annotationsOff",self.annotationsOff,self.annotationsOff)
		print "%-20s:%08x:%10d"%("numStaticFields",self.numStaticFields,self.numStaticFields)
		print "%-20s:%08x:%10d"%("numInstanceFields",self.numInstanceFields,self.numInstanceFields)
		print "%-20s:%08x:%10d"%("numDirectMethods",self.numDirectMethods,self.numDirectMethods)
		print "%-20s:%08x:%10d"%("numVirtualMethods",self.numVirtualMethods,self.numVirtualMethods)
		print "%-20s:%08x:%10d"%("classDataOff",self.classDataOff,self.classDataOff)
		print "%-20s:%08x:%10d"%("interfacesOff",self.interfacesOff,self.interfacesOff)
		print "%-20s:%08x:%10d"%("interfacesSize",self.interfacesSize,self.interfacesSize)
		offset = self.interfacesOff + struct.calcsize("I")
		for n in xrange(0,self.interfacesSize):
			typeid, = struct.unpack_from("H",dex_object.binary_blob,offset)
			offset += struct.calcsize("H")
			print "\t\t"+ dex_object.get_type_name(typeid)

		print "%-20s:%08x:%10d"%("staticValuesOff",self.staticValuesOff,self.staticValuesOff)
		print "%-20s:%08x:%10d  %s"%("sourceFileIdx",self.sourceFileIdx,self.sourceFileIdx,dex_object.get_string_by_id(self.sourceFileIdx))
		offset = self.classDataOff
		n,tmp = get_uleb128(dex_object.binary_blob[offset:offset+5])
		offset += n
		n,tmp = get_uleb128(dex_object.binary_blob[offset:offset+5])
		offset += n
		n,tmp = get_uleb128(dex_object.binary_blob[offset:offset+5])
		offset += n
		n,tmp = get_uleb128(dex_object.binary_blob[offset:offset+5])
		offset += n
		field_idx=0
		for i in xrange(0,self.numStaticFields):
			n,field_idx_diff = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			field_idx+=field_idx_diff
			print dex_object.getfieldfullname(field_idx),
			n,modifiers = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			if self.staticValuesOff:
				staticoffset=get_static_offset(dex_object.binary_blob[self.staticValuesOff:],i)
				if staticoffset == -1:
					print "0;"
					continue
				parse_encoded_value(dex_object,dex_object.binary_blob[self.staticValuesOff+staticoffset:])
			print ""

		field_idx=0
		for i in xrange(0,self.numInstanceFields):
			n,field_idx_diff = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			field_idx+=field_idx_diff
			print dex_object.getfieldfullname(field_idx)
			n,modifiers = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n

		print "=========numDirectMethods[%d]=numVirtualMethods[%d]=numStaticMethods[0]========="%(self.numDirectMethods,self.numVirtualMethods)
		method_idx = 0
		for i in xrange(0,self.numDirectMethods):
			n,method_idx_diff = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			n,access_flags = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			n,code_off = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			method_idx += method_idx_diff
			print dex_object.getmethodfullname(method_idx,True)
			#print "%s           codeoff=%x"%(dex_object.get_method_name(method_idx),code_off)
			if code_off != 0:

				method_code(dex_object,code_off).printf(dex_object,"\t\t")
		method_idx = 0
		for i in xrange(0,self.numVirtualMethods):
			n,method_idx_diff = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			n,access_flags = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			n,code_off = get_uleb128(dex_object.binary_blob[offset:offset+5])
			offset += n
			method_idx += method_idx_diff
			print dex_object.getmethodfullname(method_idx,True)
			#print "%s           codeoff=%x"%(dex_object.get_method_name(method_idx),code_off)
			if code_off != 0:
				method_code(dex_object,code_off).printf(dex_object,"\t\t")

		print "================================================================================"
		if self.annotationsOff != 0:
			offset = self.annotationsOff
			self.class_annotations_off,self.fields_size,self.annotated_methods_size,self.annotated_parameters_size,=struct.unpack_from("4I",dex_object.binary_blob,offset)
			#print "%-30s:%08x:%09d"%("class_annotations_off",self.class_annotations_off,self.class_annotations_off)
			#print "%-30s:%08x:%09d"%("fields_size",self.fields_size,self.fields_size)
			#print "%-30s:%08x:%09d"%("annotated_methods_size",self.annotated_methods_size,self.annotated_methods_size)
			#print "%-30s:%08x:%09d"%("annotated_parameters_size",self.annotated_parameters_size,self.annotated_parameters_size)
			offset =  self.annotationsOff + struct.calcsize("4I")

			if self.fields_size:
				for  i in xrange(0,self.fields_size):
					field_idx,annotations_off,=struct.unpack_from("2I",dex_object.binary_blob,offset)
					offset += struct.calcsize("2I")
					print dex_object.getfieldname(field_idx),
					parse_annotation_set_item(dex_object,annotations_off)

			if self.annotated_methods_size:
				print "=====annotated_methods_size=====    offset=[%x]===="%offset
				for  i in xrange(0,self.annotated_methods_size):
					method_idx,annotations_off,=struct.unpack_from("2I",dex_object.binary_blob,offset)
					offset += struct.calcsize("2I")
					print dex_object.get_method_name(method_idx),
					parse_annotation_set_item(dex_object,annotations_off)
			if self.annotated_parameters_size:
				for  i in xrange(0,self.annotated_parameters_size):
					method_idx,annotations_off,=struct.unpack_from("2I",dex_object.binary_blob,offset)
					offset+=struct.calcsize("2I")
					print dex_object.get_method_name(method_idx),
					parse_annotation_set_ref_list(dex_object,annotations_off)
			if self.class_annotations_off == 0:
				return
			print "self.class_annotations_off = %x" % self.class_annotations_off
			parse_annotation_set_item(dex_object, self.class_annotations_off)



class DexFile():
	def __init__(self, binary_blob, binary_blob_length): # data is binaryView
		self.binary_blob = binary_blob
		self.binary_blob_length = binary_blob_length

		self.m_class_name_id = {}

		self.header_item() # initalize header variables

		self.string_table = self.string_ids() # initalize self.string_ids_size, self.string_ids_off

		# just map everything in..
		#self.map_list() # FIXME: disable this

	'''
	header
		self.magic - believed correct
		self.checksum - validated
		self.signature - validated
		self.file_size - validated
		self.header_size - validated
		self.endian_tag - validated

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
		print "file_size: ", self.file_size
		print "header_size: ", self.header_size()
		print "endian_tag: ", self.endian_tag()
	'''
	def header_item(self):
		############################################################################################################
		# magic
		############################################################################################################
		# ubyte[8] = DEX_FILE_MAGIC
		self.magic = self.binary_blob[0:8] # FIXME: it says data is not defined
		if self.magic != DEX_MAGIC:
			print "magic result: ", hex(result), " correct magic: ", hex(DEX_MAGIC)
			assert False

		#return DEX_MAGIC

		############################################################################################################
		# checksum: adler32 checksum of the rest of the file (everything but magic and this field); used to detect file corruption
		############################################################################################################
		# format: uint
		checksum_offset = 8
		checksum_size = 4

		self.checksum = self.read_uint(checksum_offset)

		idx_start = checksum_offset+checksum_size
		idx_end = idx_start + self.binary_blob_length - checksum_offset - checksum_size
		adler32 = zlib.adler32(self.binary_blob[idx_start: idx_end]) & (2**32-1)
		# 32 bit: & (2**32-1)
		# 64 bit: & (2**64-1)

		if adler32 != self.checksum:
			print "adler32: ", hex(adler32), " checksum: ", hex(self.checksum)
			assert False


		############################################################################################################
		# signature: sha-1 signature of the rest of the file (excluding magic, checksum, and signature)
		############################################################################################################
		# format: ubyte[20]
		signature_offset = 12
		signature_size = 20

		self.signature = self.binary_blob[signature_offset: signature_offset+signature_size]
		self.signature = self.signature.encode('hex')

		idx_start = signature_offset + signature_size
		idx_end = idx_start + self.binary_blob_length - signature_offset - signature_size
		sha1 = hashlib.sha1(self.binary_blob[idx_start:idx_end]).hexdigest()

		if self.signature != sha1:
			print "sha1: ", sha1, " signature: ", self.signature
			assert False

		############################################################################################################
		# file_size
		############################################################################################################
		# returns unsigned int
		self.file_size = self.read_uint(32)

		# dex file validation
		if self.file_size != self.binary_blob_length:
			print "file_size method: ", hex(result), ", self.file.raw: ", hex(binary_blob_length)
			assert False

		############################################################################################################
		# header_size
		############################################################################################################
		# format: unit = 0x70
		self.header_size = self.read_uint(36)

		if self.header_size != 0x70:
			print "header_size: ", self.header_size
			assert False

		############################################################################################################
		# endian_tag
		############################################################################################################
		# format: uint = 0x12345678
		ENDIAN_CONSTANT = 0x12345678

		self.endian_tag = self.read_uint(40)
		if self.endian_tag != ENDIAN_CONSTANT:
			print "endian_tag: ", self.endian_tag
			assert False

		############################################################################################################
		# link_size - can it be validated?
		############################################################################################################
		self.link_size = self.read_uint(44)
		self.link_off = self.read_uint(48)

		############################################################################################################
		# map_off - offset from the start of the file to the map item. offset must be non-zero
		############################################################################################################
		# format: uint
		self.map_off = self.read_uint(52)
		assert self.map_off > 0 # must be non-zero

		############################################################################################################
		# string_ids_size, string_ids_off
		############################################################################################################
		self.string_ids_size = self.read_uint(56)
		self.string_ids_off = self.read_uint(60)
		self.type_ids_size = self.read_uint(64)
		self.type_ids_off = self.read_uint(68)
		self.proto_ids_size = self.read_uint(72)
		self.proto_ids_off = self.read_uint(76)
		self.field_ids_size = self.read_uint(80)
		self.field_ids_off = self.read_uint(84)
		self.method_ids_size = self.read_uint(88)
		self.method_ids_off = self.read_uint(92)

	########################################
	# string_ids_size, string_ids_off
	# return list of strings
	# strings are encored in MUTF-8
	#	* Only the one-, two-, and three-byte encodings are used.
	#	* A plain null byte (value 0) indicates the end of a string, as is the standard C language interpretation.
	# TODO: cache results
	def string_ids(self): # FIXME: maybe deprecating??
		strings = []
		offset = self.string_ids_off # offset points to "string_ids" section, which is just a list of uint "string_data_off"
		for i in xrange(self.string_ids_size):
			string_off = self.read_uint(offset)

			string = self.read_string(string_off)
			strings.append(string)

			#string_data_offs.append(string_data_off)
			offset += 4

		return strings

	# TODO - validate
	# pulls method_ids_size, method_ids_off
	# method_ids	method_id_item[]
	def method_ids(self):
		methods = []
		offset = self.method_ids_off
		for i in xrange(self.method_ids_size):
			# Name			| Format	| Description
			############################################
			# class_idx		| ushort	| index into the type_ids list for the definer of this method. This must be a class or array type, and not a primitive type.
			# proto_idx		| ushort	| index into the proto_ids list for the prototype of this method
			# name_idx		| uint		| index into the string_ids list for the name of this method. The string must conform to the syntax for MemberName, defined above.

			# now carve out method_id_item
			offset = four_byte_align(offset)
			method = {
				"class_idx": self.read_ushort(offset),
				"proto_idx": self.read_ushort(offset+2),
				"name_idx": self.read_uint(offset+4)
			}
			offset += 8

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
	# alignment: 4 bytes
	def map_list(self):
		offset = self.map_off

		# map_items are 12 bytes
		map_items = []

		strings = []
		codes = {}
		class_data_items = [] # FIXME: the encoded_methods are wrong...
		method_id_items = []

		# NOTE: I have seen apks in wild that do not automatically 4 byte align the offset..., not sure if four_byte_align is necessary though...
		padding = 0
		if offset & 3 == 0:
			log(3, "Error: map_list offset was not 4 byte aligned")
			log(2, "map_list(), offset: %x" % offset)
			offset = four_byte_align(offset) # will this fix it?

		map_list_size = self.read_uint(offset) # ok
		offset += 4

		# offset should point to the first map_list
		for map_list_idx in xrange(map_list_size): # FIXME: does this include the last item?
			# Name		| Format	| Description
			##############################################################################
			# type		| ushort	| type of the items; see table below
			# unused	| ushort	| (unused)
			# size		| uint		| count of the number of items to be found at the indicated offset
			# offset	| uint		| offset from the start of the file to the items in question

			# map_item attributes
			map_type = self.read_ushort(offset) # yes this is a ushort
			map_size = self.read_uint(offset+4) # ok
			map_offset = self.read_uint(offset+8) # ok
			offset += 12

			map_item = {
				"type": map_type,
				"size": map_size,
				"offset": map_offset,
			}
			map_items.append(map_item)

			log(1, "offset: 0x%x, map_type: 0x%x, map_size: %i, map_offset: 0x%x" % (offset, map_type, map_size, map_offset))

			# string_id_item works
			##############################
			if ItemType[map_type] == "string_id_item": # I don't think we care about "string_data_item" for now (but that may fix the string_list[idx] problem)
				strings = self.read_string_id_items(map_offset, map_size)

			# FIXME: code_items are aligned to 4 bytes.. does that matter?
			# variable length item
			##############################
			elif ItemType[map_type] == "code_item":
				codes = self.read_code_items(map_offset, map_size) # FIXME: make sure these args are right

			# size is 0x20
			# FIXME: BYTE ALIGNED - aka irrelevant  AFAIK...
			elif ItemType[map_type] == "class_data_item":
				class_data_items = self.read_class_data_items(map_offset, map_size)

			# size is 0x8
			# TODO: save in dict by offset
			# alignment: 4 bytes -??
			elif ItemType[map_type] == "method_id_item":
				method_id_items = self.read_method_id_items(map_offset, map_size)

		# TEMP - THIS IS FOR TESTING
		for class_data_item in class_data_items:
			methods = class_data_item["direct_methods"] + class_data_item["virtual_methods"]

			for method in methods:
				method_idx = method["method_idx_diff"]
				log(3, "TODO - %s" % self.get_method_name(method_idx))

		# return list of map_item dicts

		result = {
			"map_items": map_items,
			"strings": strings,
			"codes": codes,
			"class_data_items": class_data_items,
			"method_id_items": method_id_items
		}

		return result


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

		self.class_defs_size = self.read_uint(class_defs_size_offset) # ok
		self.class_defs_off = self.read_uint(class_defs_off_offset) # ok

		print "\n===============================\n"
		print "class_defs_size: ", self.class_defs_size, "\n"
		print "class_defs_off: ", hex(self.class_defs_off), "\n"

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
		offset = 0
		for i in range(self.class_defs_size):
			offset = four_byte_align(offset)
			item = self.read_class_def_item(offset)
			offset += class_def_item_size

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
	# data retrieval functions
	###########################
	def get_method_name(self, methodId):
		if methodId >= self.method_ids_size:
			return ""
		offset = self.method_ids_off + methodId * struct.calcsize("HHI")

		class_idx, proto_idx, name_idx, = struct.unpack_from("HHI", self.binary_blob, offset)

		return self.string_table[name_idx]

	def get_method_fullname(self, methodId, hidden_classname=False):
		if methodId >= self.method_ids_size:
			return ""

		offset = self.method_ids_off + methodId * struct.calcsize("HHI")
		class_idx, proto_idx, name_idx, = struct.unpack_from("HHI", self.binary_blob, offset)

		# FIXME: TODO
		classname = self.get_type_name(class_idx) # TODO implement
		classname = shorty_decode(classname) # TODO implement
		funcname = self.get_string_by_id(name_idx) # TODO implement
		if not hidden_classname:
			classname = ""
		return self.get_proto_fullname(proto_idx,classname,funcname)

	def get_field_name(self, fieldId):
			if fieldId >= self.m_fieldIdsSize:
				return ""
			offset = self.field_ids_off + fieldId * struct.calcsize("HHI")
			class_idx, type_idx, name_idx, = struct.unpack_from("HHI", self.binary_blob, offset)
			return self.string_table[name_idx]

	def get_field_fullname(self, fieldId):
		if fieldId >= self.field_ids_size:
			return ""

		offset = self.field_ids_off + fieldId * struct.calcsize("HHI")
		class_idx, type_idx, name_idx, = struct.unpack_from("HHI", self.binary_blob, offset)
		name = self.get_type_name(type_idx)
		name = shorty_decode(name)
		fname = self.get_string_by_id(name_idx)
		return "%s %s" % (name, fname)

	def get_field_type_name(self, fieldId):
		if fieldid >= self.field_ids_size:
			return ""

		offset = self.field_ids_off + fieldId * struct.calcsize("HHI")
		class_idx, type_idx, name_idx, = struct.unpack_from("HHI", self.binary_blob, offset)
		name = self.get_type_name(type_idx)
		if name[-1] != ";":
			name = shorty_decode(name)
		return name

	def get_type_name(self, typeId):
		if typeId >= self.type_ids_size:
			return ""
		offset = self.type_ids_off + typeId * struct.calcsize("I")
		descriptor_idx, = struct.unpack_from("I" ,self.binary_blob, offset)
		return self.string_table[descriptor_idx]

	def get_proto_name(self, protoId):
		if protoId >= self.proto_ids_size:
			return ""
		offset = self.proto_ids_off + protoId * struct.calcsize("3I")
		shorty_idx, return_type_idx, parameters_off, = struct.unpack_from("3I", self.binary_blob, offset)
		return self.string_table[shorty_idx]

	def get_proto_fullname(self, protoId, classname, func_name):
		if protoId >= self.proto_ids_size:
			return ""
		offset = self.proto_ids_off + protoId * struct.calcsize("3I")
		shorty_idx, return_type_idx, parameters_off, = struct.unpack_from("3I", self.binary_blob, offset)
		retname = self.get_type_name(return_type_idx)
		retname = shorty_decode(retname)
		retstr = retname + " "
		if len(classname) == 0:
			retstr += "%s(" % func_name
		else:
			retstr += "%s::%s(" % (classname, func_name)
		if parameters_off != 0:
			offset = parameters_off
			size, = struct.unpack_from("I", self.binary_blob, offset)
			offset += struct.calcsize("I")
			n = 0
			for i in xrange(0,size):
				type_idx, = struct.unpack_from("H", self.binary_blob, offset)
				offset += struct.calcsize("H")
				arg = self.get_type_name(type_idx)
				arg = shorty_decode(arg)
				if n != 0:
					retstr += ","
				retstr += arg
				n += 1
		retstr += ")"
		return retstr

	def get_class_method_count(self, classId):
		if classId >= self.class_defs_size:
			return ""
		offset = self.class_defs_off + classId * struct.calcsize("8I")
		class_idx,access_flags,superclass_idx,interfaces_off,source_file_idx,annotations_off,class_data_off,static_values_off,= struct.unpack_from("8I", self.binary_blob, offset)
		if class_data_off:
			offset = class_data_off
			static_fields_size, n = self.read_uleb128(offset)
			offset += n

			instance_fields_size, n = self.read_uleb128(offset)
			offset += n

			direct_methods_size, n = self.read_uleb128(offset) # NOTE: this might be important
			offset += n

			virtual_methods_size, n = self.read_uleb128(offset)
			offset += n

			return static_fields_size + instance_fields_size
		return 0

	def get_class_method(self, classId, method_idx):
		count = 0
		if classId >= self.class_defs_size:
			return ""
		offset = self.class_defs_off + classId * struct.calcsize("8I")
		class_idx,access_flags,superclass_idx,interfaces_off,source_file_idx,annotations_off,class_data_off,static_values_off,= struct.unpack_from("8I", self.binary_blob, offset)
		if class_data_off:
			offset = class_data_off
			static_fields_size, n = self.read_uleb128(offset)
			offset += n
			instance_fields_size, n = self.read_uleb128(offset)
			offset += n
			direct_methods_size, n = self.read_uleb128(offset)
			offset += n
			virtual_methods_size, n = self.read_uleb128(offset)
			offset += n
			count = direct_methods_size + virtual_methods_size
		if method_idx >= count:
			return ""
		ncount = static_fields_size + instance_fields_size
		ncount *= 2
		for i in xrange(0, ncount):
			tmp, n = self.read_uleb128(offset)
			offset += n
		ncount *= 3
		for i in xrange(0, ncount):
			tmp, n = self.read_uleb128(offset)
			offset += n
		method_idx_diff, n = self.read_uleb128(offset)
		offset += n
		access_flags, n = self.read_uleb128(offset)
		offset += n
		code_off, n = self.read_uleb128(offset)

	def get_class_name(self, classId):
		if classId >= self.class_defs_size:
			return ""
		offset = self.class_defs_off + classId * struct.calcsize("8I")
		class_idx,access_flags,superclass_idx,interfaces_off,source_file_idx,annotations_off,class_data_off,static_values_off,= struct.unpack_from("8I", self.binary_blob, offset)
		return self.get_type_name(class_idx)

	def get_type_name_by_id(self, typeId):
		if typeId >= self.type_ids_size:
			return ""
		offset = self.type_ids_off + typeId * struct.calcsize("I")
		descriptor_idx, = struct.unpack_from("I", self.binary_blob, offset)
		return self.string_table[descriptor_idx]


	# TODO: get_access_flags, get_access_flags1, getclass

	###########################
	# helper functions
	###########################
	def read_uint(self, offset):
		if offset > self.binary_blob_length:
			assert False

		return struct.unpack("<I", self.binary_blob[offset:offset+4])[0]

	def read_ushort(self, offset):
		if offset > self.binary_blob_length:
			assert False

		return struct.unpack("<H", self.binary_blob[offset:offset+2])[0]

	# wrapper function
	def read_uleb128(self, offset):
		if offset > self.binary_blob_length:
			log(3, "read_uleb128(0x%x)" % offset)
			assert False

		return read_uleb128(self.binary_blob[offset:offset+5])

	def read_sleb128(self, offset):
		if offset > self.binary_blob_length:
			assert False

		return read_sleb128(self.binary_blob[offset:offset+5])

	def read_string_id_items(self, offset, item_count):
		strings = []
		for i in range(item_count):
			if offset & 3 != 0:
				log(3, "string_id_item should be 4 byte aligned")
				# map_offset += four_byte_align(map_offset) WARNING: need to account for the padding, and add that to the main offset counter

			# map_offset points to a string_id_item
			string_off = self.read_uint(offset + i*4)

			string = self.read_string(string_off)
			strings.append(string)

		return strings

	def read_string(self, offset):
		if offset > self.binary_blob_length:
			assert False

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

	# "code_item" alignment: 4 bytes
	def read_code_items(self, offset, item_count):
		#log(3, "code_item map_size: %i" % map_size)

		codes = {}
		for i in range(item_count):
			try:
			#if True:
				offset = four_byte_align(offset) # is this really needed?
				code_item, read_size = self.read_code_item(offset) # FAILING..

				# log(2, "code_size: 0x%x" % code_size)
				if read_size == -1:
					log(3, "read_code_items - read_size == -1")
					break

				offset += read_size # but what if code_size == -1....

				# the actual code offset, not the code_item_offset
				code_offset = code_item["insns_off"]
				codes[code_offset] = code_item

			except:

				# if it's invalid, or we can't read it we have to break. Otherwise it will keep reading the same invalid one
			#	log(3, "breaking out of code_item loop - this means we're skipping %i methods" % (map_size-i))
				break
		return codes

	# ushort == 2 bytes
	# FIXME: incomplete

	def read_code_item(self, offset):
		size = 0
		log(1, "read_code_item(0x%x)" % offset)

		# alignment: 4 bytes
		assert offset & 3 == 0

		# FIXME: I assume "code_item" is incorrect at https://source.android.com/devices/tech/dalvik/dex-format.html
		#print "----------------------------------------------------"
		#log(2, "read_code_item(0x%x)" % offset)
		#log(2, "read_code_item(aligned 0x%x)" % offset)

		registers_size = self.read_ushort(offset)
		ins_size = self.read_ushort(offset+2)
		outs_size = self.read_ushort(offset+4)
		tries_size = self.read_ushort(offset+6)
		debug_info_off = self.read_uint(offset+8)
		instructions_size = self.read_uint(offset+12)
		size += 16

		# FIXME: this is getting hit....
		if instructions_size*2 > self.binary_blob_length:
			log(3, "instructions_size: 0x%x" % instructions_size)
			assert False

		# pretty sure this is correct
		instructions_off = offset + size
		instructions = self.binary_blob[instructions_off:instructions_off+(instructions_size*2)] # the actual dex code, but lets not save as variable unless we need to

		#log(3, "offset: 0x%x, insns_size: 0x%x" % (offset, instructions_size))

		size += (instructions_size*2) # ok
		#log(3, "offset: 0x%x, insns_size: 0x%x" % (offset, instructions_size))

		# optional padding
		if (tries_size != 0) and (instructions_size % 2 == 1):
			#log(3, "optional padding is 2 bytes")
			size += 2

		# tries try_item[tries_size] - each "try_item" is 8 bytes - ok
		if tries_size != 0:
			#log(3, "try_item is %i bytes" % (tries_size * 8))
			size += (tries_size * 8) # ok

		# handlers encoded_catch_handler_list
		if tries_size != 0:
			handlers_size, read_size = self.read_uleb128(offset + size) # FAILING HERE...
			size += read_size # FIXME: is this right

			#log(3, "handlers is at least %i bytes" % handlers_size)

			handlers = []
			#log(2, "handlers_size: %i" % handlers_size)
			for i in range(handlers_size):
				# read an "encoded_catch_handler" struct

				# I DO NOT TRUST THIS...

				# number of catch types in this list.
				# If non-positive, then this is the negative of the number of catch types, and the catches are followed by a catch-all handler.
				# 		For example: A size of 0 means that there is a catch-all but no explicitly typed catches.
				# 		A size of 2 means that there are two explicitly typed catches and no catch-all. And a size of -1 means that there is one typed catch along with a catch-all.
				encoded_catch_handler_size, read_size = self.read_sleb128(offset + size) # FIXME: I do not trust this function....
				size += read_size # is this right..???

				# handlers	encoded_type_addr_pair[abs(size)]
				encoded_type_addr_pairs = []

				# read encoded_type_addr_pairs
				for pair_count in range(abs(encoded_catch_handler_size)):
					item = {}
					item["type_idx"], read_size = self.read_uleb128(offset + size)
					size += read_size

					item["addr"], read_size = self.read_uleb128(offset + size)
					size += read_size

					encoded_type_addr_pairs.append(item)

				if encoded_catch_handler_size < 0:
					catch_all_addr, read_size = self.read_uleb128(offset + size)
					size += read_size


		result = {
			"registers_size": registers_size,
			"ins_size": ins_size,
			"outs_size": outs_size,
			"tries_size": tries_size,
			"debug_info_off": debug_info_off,
			"insns_size": instructions_size,
			"insns_off": instructions_off
			# "insns": insns
		}

		return result, size

	def read_method_id_items(self, offset, item_count):
		method_id_items = []

		# four_byte_align
		for i in range(item_count):
			offset = four_byte_align(offset)

			# pull a method_id_item
			method_item, read_size = self.read_method_id_item(offset)
			offset += read_size

			if read_size <= 0:
				break

			method_id_items.append(method_item)
		return method_id_items

	def read_method_id_item(self, offset):
		# alignment: 4 bytes
		assert offset & 3 == 0

		if offset > self.binary_blob_length:
			log(3, "length: %i, binary_blob_length: %i" % (offset, self.binary_blob_length))
			assert False

		result = {
			"class_idx": self.read_ushort(offset),
			"proto_idx": self.read_ushort(offset+2),
			"name_idx": self.read_uint(offset+4)
		}

		return result, 8


	def read_class_def_item(self, offset):
		# alignment: 4 bytes
		assert offset & 3 == 0

		return {
			"class_idx": self.read_uint(offset),
			"access_flags": self.read_uint(offset+4),
			"superclass_idx": self.read_uint(offset+8),
			"interfaces_off": self.read_uint(offset+12),
			"source_file_idx": self.read_uint(offset+16),
			"annotations_off": self.read_uint(offset+20),
			"class_data_off": self.read_uint(offset+24),
			"static_values_off": self.read_uint(offset+28)
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

	def read_class_data_items(self, offset, item_count):
		class_data_items = []

		log(1, "class_data_items - map_size: %i" % item_count) # Example: 123 in the apk I'm testing
		for i in range(item_count):
			try:
			#if True:
				log(1, "class_item_off: 0x%x" % offset)
				class_item, read_size = self.read_class_data_item(offset) # FIXME: need to implement class_data_item...
				if read_size <= 0:
					log(3, "class_size <= 0, breaking")
					break

				offset += read_size
				class_data_items.append(class_item)
			except:
				break
		# method_id_item
		return class_data_items

	# alignment: none
	# THIS SEEMS CORRECT
	def read_class_data_item(self, offset):
		log(1, "read_class_data_item(0x%x)" % offset)
		result = {}
		result["direct_methods"] = []
		result["virtual_methods"] = []
		size = 0

		if offset > self.binary_blob_length:
			log(3, "length: %i, binary_blob_length: %i" % (offset, self.binary_blob_length))
			assert False

		static_fields_size, read_size = self.read_uleb128(offset)
		size += read_size

		instance_fields_size, read_size = self.read_uleb128(offset + size)
		size += read_size

		direct_methods_size, read_size = self.read_uleb128(offset + size)
		size += read_size

		virtual_methods_size, read_size = self.read_uleb128(offset + size)
		size += read_size

		###################

		# ok for now AFAIK
		if static_fields_size > 0:
			result["static_fields"], read_size = self.read_encoded_fields(offset + size, static_fields_size)
			size += read_size

		# TODO
		if instance_fields_size > 0:
			result["instance_fields"], read_size = self.read_encoded_fields(offset + size, instance_fields_size)
			size += read_size

		# TODO
		if direct_methods_size > 0:
			result["direct_methods"], read_size = self.read_encoded_methods(offset + size, direct_methods_size)
			size += read_size

		# TODO
		if virtual_methods_size > 0:
			result["virtual_methods"], read_size = self.read_encoded_methods(offset + size, virtual_methods_size)
			size += read_size

		return result, size

	# static_fields	encoded_field[static_fields_size]
	# for now returning a list of dict
	# THIS SEEMS CORRECT
	def read_encoded_fields(self, offset, count):
		size = 0
		log(1, "static_fields(0x%x, %i)" % (offset, count))

		results = []
		for i in xrange(count):
			try:
				field_idx_diff, read_size = self.read_uleb128(offset + size)
				size += read_size

				access_flags, read_size = self.read_uleb128(offset + size)
				size += read_size

				result = {
					"field_idx_diff": field_idx_diff,
					"access_flags": access_flags
				}
				results.append(result)
			except:
				break

		# return list of dicts
		return results, size

	# Name				| Format	| Description
	#########################################################
	# method_idx_diff	| uleb128	| index into the method_ids list for the identity of this method
	# access_flags		| uleb128	|
	# code_off			| uleb128	| offset from the start of the file to the code structure for this method, format of the data is specified by "code_item" below.

	# direct_methods	encoded_method[direct_methods_size]
	#  populate self.virtual_methods_off
	# FIXME: code_off is a data structure
	# THIS SEEMS CORRECT
	def read_encoded_methods(self, offset, count):
		size = 0

		results = []
		#print(4, "self.direct_methods_size: %i" % count)
		for i in xrange(count):
			try:
			#if True:
				method_idx_diff, read_size = self.read_uleb128(offset + size)
				size += read_size

				access_flags, read_size = self.read_uleb128(offset + size)
				size += read_size

				code_off, read_size = self.read_uleb128(offset + size)
				size += read_size

				#assert code_off < self.binary_blob_length
				#log(3, "code_off: %i" % code_off)
				if 0 < code_off < self.binary_blob_length: # FIXME:  and code_off != 0
					continue
					#assert False

				result = {
					"method_idx_diff": method_idx_diff,
					"access_flags": access_flags,
					"code_off": code_off # GREPME # FIXME: code_off is a data structure
				}
				results.append(result)
			except:
				break

		# return list of dicts
		return results, size

if __name__ == "__main__":
	def log(level, message):
		print message

	dexPath = os.path.expanduser("~") + "/Downloads/classes2.dex"

	dex = open(dexPath).read()
	dex_length = len(dex)

	dex = DexFile(dex, dex_length)
	dex.header_item()
	#method_list = dex.method_ids() # this will be used to get the method names :) TODO # FIXME: method_list also provides class_idx, proto_idx
	#string_list = dex.string_ids() # FIXME: cache the results
	#function_list =

	map_list = dex.map_list() # this contains everything - but still need to finish map_list function...
	strings = map_list["strings"]
	codes = map_list["codes"] # NOW A DICT, key is the offset
	class_data_items = map_list["class_data_items"] # has  (direct_methods, virtual_methods) which contain code_off + method name
	method_id_items = map_list["method_id_items"]

	dex.class_defs() # instantiate class_defs_size

	for i in xrange(dex.class_defs_size): # was originally "class_def_size"
		str1 = dex.get_class_name(i)
		dex.m_class_name_id[str1] = i
		dex_class(dex, i).printf(dex) # WHAT


	#print "dex_length: %i" % dex_length

	##################################
	##################################
	# add all the methods
	#log(3, "len(self.dex_file.codes): %i" % len(dex.codes))
	# looks ok - missing some, but w/e
	#for idx, code_item in enumerate(dex.codes):
	#	print "%s: %x" % ("insns_off", code_item["insns_off"]) # FIXME: they're all wrong, and the same


	#log(3, "len(self.class_data_items): %i" % len(class_data_items)) # this is not getting hit...
	assert len(class_data_items) > 0

	# class_data_item => "encoded_method" (direct_methods, virtual_methods) => method_id_item => (class_idx, proto_idx, name_idx)
	# class_data_item => "encoded_method" (direct_methods, virtual_methods) => code_item

	# FIXME: this whole section seems wrong....
	for class_data_item in class_data_items:
		encoded_methods = class_data_item["direct_methods"] + class_data_item["virtual_methods"]

		for encoded_method in encoded_methods:
			#try:
			if True:
				method_idx_diff = encoded_method["method_idx_diff"] # use this to get (class_idx, proto_idx, name_idx)
				code_off = encoded_method["code_off"]
				if code_off == 0:
					# method is either abstract or native
					continue

				assert code_off < dex_length # FIXME: can't figure out why this is triggering...

				instructions_off = dex.read_code_item(code_off) # causing errors at some times...

				name_idx = method_list[method_idx_diff]["name_idx"]
				#method["class_idx"] # TODO
				#method["proto_idx"] # TODO

				print "="*100
				log(2, "%s: %x" % (strings[name_idx], instructions_off))
			#except:
			#	pass
