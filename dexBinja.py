from binaryninja import *
import struct
import traceback
import hashlib # to validate SHA1 signature
import zlib # to validate adler32 checksum
import os

DEX_MAGIC = "dex\x0a035\x00"

# ~/binaryninja/binaryninja /home/noot/CTF/tmp/classes2.dex
	# they already did it https://gist.github.com/ezterry/1239615

#
# WARNING: dex file format changes constantly...
#

# style guideline: https://google.github.io/styleguide/pyguide.html
# 010Editor: https://github.com/strazzere/010Editor-stuff/blob/master/Templates/DEXTemplate.bt
# export PYTHONPATH=$PYTHONPATH:$HOME/binaryninja/python

# https://source.android.com/devices/tech/dalvik/dalvik-bytecode.html


# style guideline: https://google.github.io/styleguide/pyguide.html
# export PYTHONPATH=$PYTHONPATH:$HOME/binaryninja/python

# https://source.android.com/devices/tech/dalvik/dalvik-bytecode.html
InstructionNames = [
        "nop" # "ora", None, None, None, "ora", "asl", None, # 0x00
]
# following list is for ^^
'''
"php", "ora", "asl@", None, None, "ora", "asl", None, # 0x08
"bpl", "ora", None, None, None, "ora", "asl", None, # 0x10
"clc", "ora", None, None, None, "ora", "asl", None, # 0x18
"jsr", "and", None, None, "bit", "and", "rol", None, # 0x20
"plp", "and", "rol@", None, "bit", "and", "rol", None, # 0x28
"bmi", "and", None, None, None, "and", "rol", None, # 0x30
"sec", "and", None, None, None, "and", "rol", None, # 0x38
"rti", "eor", None, None, None, "eor", "lsr", None, # 0x40
"pha", "eor", "lsr@", None, "jmp", "eor", "lsr", None, # 0x48
"bvc", "eor", None, None, None, "eor", "lsr", None, # 0x50
"cli", "eor", None, None, None, "eor", "lsr", None, # 0x58
"rts", "adc", None, None, None, "adc", "ror", None, # 0x60
"pla", "adc", "ror@", None, "jmp", "adc", "ror", None, # 0x68
"bvs", "adc", None, None, None, "adc", "ror", None, # 0x70
"sei", "adc", None, None, None, "adc", "ror", None, # 0x78
None, "sta", None, None, "sty", "sta", "stx", None, # 0x80
"dey", None, "txa", None, "sty", "sta", "stx", None, # 0x88
"bcc", "sta", None, None, "sty", "sta", "stx", None, # 0x90
"tya", "sta", "txs", None, None, "sta", None, None, # 0x98
"ldy", "lda", "ldx", None, "ldy", "lda", "ldx", None, # 0xa0
"tay", "lda", "tax", None, "ldy", "lda", "ldx", None, # 0xa8
"bcs", "lda", None, None, "ldy", "lda", "ldx", None, # 0xb0
"clv", "lda", "tsx", None, "ldy", "lda", "ldx", None, # 0xb8
"cpy", "cmp", None, None, "cpy", "cmp", "dec", None, # 0xc0
"iny", "cmp", "dex", None, "cpy", "cmp", "dec", None, # 0xc8
"bne", "cmp", None, None, None, "cmp", "dec", None, # 0xd0
"cld", "cmp", None, None, None, "cmp", "dec", None, # 0xd8
"cpx", "sbc", None, None, "cpx", "sbc", "inc", None, # 0xe0
"inx", "sbc", "nop", None, "cpx", "sbc", "inc", None, # 0xe8
"beq", "sbc", None, None, None, "sbc", "inc", None, # 0xf0
"sed", "sbc", None, None, None, "sbc", "inc", None # 0xf8
'''

NONE = 0
ABS = 1
ABS_DEST = 2
ABS_X = 3
ABS_X_DEST = 4
ABS_Y = 5
ABS_Y_DEST = 6
ACCUM = 7
ADDR = 8
IMMED = 9
IND = 10
IND_X = 11
IND_X_DEST = 12
IND_Y = 13
IND_Y_DEST = 14
REL = 15
ZERO = 16
ZERO_DEST = 17
ZERO_X = 18
ZERO_X_DEST = 19
ZERO_Y = 20
ZERO_Y_DEST = 21

InstructionOperandTypes = [
	NONE
]
'''
	IND_X, NONE, NONE, NONE, ZERO, ZERO_DEST, NONE, # 0x00
	NONE, IMMED, ACCUM, NONE, NONE, ABS, ABS_DEST, NONE, # 0x08
	REL, IND_Y, NONE, NONE, NONE, ZERO_X, ZERO_X_DEST, NONE, # 0x10
	NONE, ABS_Y, NONE, NONE, NONE, ABS_X, ABS_X_DEST, NONE, # 0x18
	ADDR, IND_X, NONE, NONE, ZERO, ZERO, ZERO_DEST, NONE, # 0x20
	NONE, IMMED, ACCUM, NONE, ABS, ABS, ABS_DEST, NONE, # 0x28
	REL, IND_Y, NONE, NONE, NONE, ZERO_X, ZERO_X_DEST, NONE, # 0x30
	NONE, ABS_Y, NONE, NONE, NONE, ABS_X, ABS_X_DEST, NONE, # 0x38
	NONE, IND_X, NONE, NONE, NONE, ZERO, ZERO_DEST, NONE, # 0x40
	NONE, IMMED, ACCUM, NONE, ADDR, ABS, ABS_DEST, NONE, # 0x48
	REL, IND_Y, NONE, NONE, NONE, ZERO_X, ZERO_X_DEST, NONE, # 0x50
	NONE, ABS_Y, NONE, NONE, NONE, ABS_X, ABS_X_DEST, NONE, # 0x58
	NONE, IND_X, NONE, NONE, NONE, ZERO, ZERO_DEST, NONE, # 0x60
	NONE, IMMED, ACCUM, NONE, IND, ABS, ABS_DEST, NONE, # 0x68
	REL, IND_Y, NONE, NONE, NONE, ZERO_X, ZERO_X_DEST, NONE, # 0x70
	NONE, ABS_Y, NONE, NONE, NONE, ABS_X, ABS_X_DEST, NONE, # 0x78
	NONE, IND_X_DEST, NONE, NONE, ZERO_DEST, ZERO_DEST, ZERO_DEST, NONE, # 0x80
	NONE, NONE, NONE, NONE, ABS_DEST, ABS_DEST, ABS_DEST, NONE, # 0x88
	REL, IND_Y_DEST, NONE, NONE, ZERO_X_DEST, ZERO_X_DEST, ZERO_Y_DEST, NONE, # 0x90
	NONE, ABS_Y_DEST, NONE, NONE, NONE, ABS_X_DEST, NONE, NONE, # 0x98
	IMMED, IND_X, IMMED, NONE, ZERO, ZERO, ZERO, NONE, # 0xa0
	NONE, IMMED, NONE, NONE, ABS, ABS, ABS, NONE, # 0xa8
	REL, IND_Y, NONE, NONE, ZERO_X, ZERO_X, ZERO_Y, NONE, # 0xb0
	NONE, ABS_Y, NONE, NONE, ABS_X, ABS_X, ABS_Y, NONE, # 0xb8
	IMMED, IND_X, NONE, NONE, ZERO, ZERO, ZERO_DEST, NONE, # 0xc0
	NONE, IMMED, NONE, NONE, ABS, ABS, ABS_DEST, NONE, # 0xc8
	REL, IND_Y, NONE, NONE, NONE, ZERO_X, ZERO_X_DEST, NONE, # 0xd0
	NONE, ABS_Y, NONE, NONE, NONE, ABS_X, ABS_X_DEST, NONE, # 0xd8
	IMMED, IND_X, NONE, NONE, ZERO, ZERO, ZERO_DEST, NONE, # 0xe0
	NONE, IMMED, NONE, NONE, ABS, ABS, ABS_DEST, NONE, # 0xe8
	REL, IND_Y, NONE, NONE, NONE, ZERO_X, ZERO_X_DEST, NONE, # 0xf0
	NONE, ABS_Y, NONE, NONE, NONE, ABS_X, ABS_X_DEST, NONE # 0xf8
'''

OperandLengths = [
	0, # NONE
	2, # ABS
	2, # ABS_DEST
	2, # ABS_X
	2, # ABS_X_DEST
	2, # ABS_Y
	2, # ABS_Y_DEST
	0, # ACCUM
	2, # ADDR
	1, # IMMED
	2, # IND
	1, # IND_X
	1, # IND_X_DEST
	1, # IND_Y
	1, # IND_Y_DEST
	1, # REL
	1, # ZERO
	1, # ZREO_DEST
	1, # ZERO_X
	1, # ZERO_X_DEST
	1, # ZERO_Y
	1  # ZERO_Y_DEST
]

# used for perform_get_instruction_text
OperandTokens = [
	lambda value: [] # NONE
]
# below comment is for OperandTokens
'''
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.4x" % value, value)], # ABS
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.4x" % value, value)], # ABS_DEST
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.4x" % value, value),
		InstructionTextToken(TextToken, ", "), InstructionTextToken(RegisterToken, "x")], # ABS_X
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.4x" % value, value),
		InstructionTextToken(TextToken, ", "), InstructionTextToken(RegisterToken, "x")], # ABS_X_DEST
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.4x" % value, value),
		InstructionTextToken(TextToken, ", "), InstructionTextToken(RegisterToken, "y")], # ABS_Y
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.4x" % value, value),
		InstructionTextToken(TextToken, ", "), InstructionTextToken(RegisterToken, "y")], # ABS_Y_DEST
	lambda value: [InstructionTextToken(RegisterToken, "a")], # ACCUM
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.4x" % value, value)], # ADDR
	lambda value: [InstructionTextToken(TextToken, "#"), InstructionTextToken(IntegerToken, "$%.2x" % value, value)], # IMMED
	lambda value: [InstructionTextToken(TextToken, "["), InstructionTextToken(PossibleAddressToken, "$%.4x" % value, value),
		InstructionTextToken(TextToken, "]")], # IND
	lambda value: [InstructionTextToken(TextToken, "["), InstructionTextToken(PossibleAddressToken, "$%.2x" % value, value),
		InstructionTextToken(TextToken, ", "), InstructionTextToken(RegisterToken, "x"),
		InstructionTextToken(TextToken, "]")], # IND_X
	lambda value: [InstructionTextToken(TextToken, "["), InstructionTextToken(PossibleAddressToken, "$%.2x" % value, value),
		InstructionTextToken(TextToken, ", "), InstructionTextToken(RegisterToken, "x"),
		InstructionTextToken(TextToken, "]")], # IND_X_DEST
	lambda value: [InstructionTextToken(TextToken, "["), InstructionTextToken(PossibleAddressToken, "$%.2x" % value, value),
		InstructionTextToken(TextToken, "], "), InstructionTextToken(RegisterToken, "y")], # IND_Y
	lambda value: [InstructionTextToken(TextToken, "["), InstructionTextToken(PossibleAddressToken, "$%.2x" % value, value),
		InstructionTextToken(TextToken, "], "), InstructionTextToken(RegisterToken, "y")], # IND_Y_DEST
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.4x" % value, value)], # REL
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.2x" % value, value)], # ZERO
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.2x" % value, value)], # ZERO_DEST
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.2x" % value, value),
		InstructionTextToken(TextToken, ", "), InstructionTextToken(RegisterToken, "x")], # ZERO_X
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.2x" % value, value),
		InstructionTextToken(TextToken, ", "), InstructionTextToken(RegisterToken, "x")], # ZERO_X_DEST
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.2x" % value, value),
		InstructionTextToken(TextToken, ", "), InstructionTextToken(RegisterToken, "y")], # ZERO_Y
	lambda value: [InstructionTextToken(PossibleAddressToken, "$%.2x" % value, value),
		InstructionTextToken(TextToken, ", "), InstructionTextToken(RegisterToken, "y")] # ZERO_Y_DEST
'''

InstructionIL = {
	"adc": lambda il, operand: il.set_reg(1, "a", il.add_carry(1, il.reg(1, "a"), operand, flags = "*")),
	"asl": lambda il, operand: il.store(1, operand, il.shift_left(1, il.load(1, operand), il.const(1, 1), flags = "czs")),
	"asl@": lambda il, operand: il.set_reg(1, "a", il.shift_left(1, operand, il.const(1, 1), flags = "czs")),
	"and": lambda il, operand: il.set_reg(1, "a", il.and_expr(1, il.reg(1, "a"), operand, flags = "zs")),
	"bcc": lambda il, operand: cond_branch(il, il.flag_condition(LLFC_UGE), operand),
	"bcs": lambda il, operand: cond_branch(il, il.flag_condition(LLFC_ULT), operand),
	"beq": lambda il, operand: cond_branch(il, il.flag_condition(LLFC_E), operand),
	"bit": lambda il, operand: il.and_expr(1, il.reg(1, "a"), operand, flags = "czs"),
	"bmi": lambda il, operand: cond_branch(il, il.flag("s"), operand),
	"bne": lambda il, operand: cond_branch(il, il.flag_condition(LLFC_NE), operand),
	"bpl": lambda il, operand: cond_branch(il, il.not_expr(0, il.flag("s")), operand),
	"brk": lambda il, operand: il.system_call(),
	"bvc": lambda il, operand: cond_branch(il, il.not_expr(0, il.flag("v")), operand),
	"bvs": lambda il, operand: cond_branch(il, il.flag("v"), operand),
	"clc": lambda il, operand: il.set_flag("c", il.const(0, 0)),
	"cld": lambda il, operand: il.set_flag("d", il.const(0, 0)),
	"cli": lambda il, operand: il.set_flag("i", il.const(0, 0)),
	"clv": lambda il, operand: il.set_flag("v", il.const(0, 0)),
	"cmp": lambda il, operand: il.sub(1, il.reg(1, "a"), operand, flags = "czs"),
	"cpx": lambda il, operand: il.sub(1, il.reg(1, "x"), operand, flags = "czs"),
	"cpy": lambda il, operand: il.sub(1, il.reg(1, "y"), operand, flags = "czs"),
	"dec": lambda il, operand: il.store(1, operand, il.sub(1, il.load(1, operand), il.const(1, 1), flags = "zs")),
	"dex": lambda il, operand: il.set_reg(1, "x", il.sub(1, il.reg(1, "x"), il.const(1, 1), flags = "zs")),
	"dey": lambda il, operand: il.set_reg(1, "y", il.sub(1, il.reg(1, "y"), il.const(1, 1), flags = "zs")),
	"eor": lambda il, operand: il.set_reg(1, "a", il.xor_expr(1, il.reg(1, "a"), operand, flags = "zs")),
	"inc": lambda il, operand: il.store(1, operand, il.add(1, il.load(1, operand), il.const(1, 1), flags = "zs")),
	"inx": lambda il, operand: il.set_reg(1, "x", il.add(1, il.reg(1, "x"), il.const(1, 1), flags = "zs")),
	"iny": lambda il, operand: il.set_reg(1, "y", il.add(1, il.reg(1, "y"), il.const(1, 1), flags = "zs")),
	"jmp": lambda il, operand: jump(il, operand),
	"jsr": lambda il, operand: il.call(operand),
	"lda": lambda il, operand: il.set_reg(1, "a", operand, flags = "zs"),
	"ldx": lambda il, operand: il.set_reg(1, "x", operand, flags = "zs"),
	"ldy": lambda il, operand: il.set_reg(1, "y", operand, flags = "zs"),
	"lsr": lambda il, operand: il.store(1, operand, il.logical_shift_right(1, il.load(1, operand), il.const(1, 1), flags = "czs")),
	"lsr@": lambda il, operand: il.set_reg(1, "a", il.logical_shift_right(1, il.reg(1, "a"), il.const(1, 1), flags = "czs")),
	"nop": lambda il, operand: il.nop(),
	"ora": lambda il, operand: il.set_reg(1, "a", il.or_expr(1, il.reg(1, "a"), operand, flags = "zs")),
	"pha": lambda il, operand: il.push(1, il.reg(1, "a")),
	"php": lambda il, operand: il.push(1, get_p_value(il)),
	"pla": lambda il, operand: il.set_reg(1, "a", il.pop(1), flags = "zs"),
	"plp": lambda il, operand: set_p_value(il, il.pop(1)),
	"rol": lambda il, operand: il.store(1, operand, il.rotate_left_carry(1, il.load(1, operand), il.const(1, 1), flags = "czs")),
	"rol@": lambda il, operand: il.set_reg(1, "a", il.rotate_left_carry(1, il.reg(1, "a"), il.const(1, 1), flags = "czs")),
	"ror": lambda il, operand: il.store(1, operand, il.rotate_right_carry(1, il.load(1, operand), il.const(1, 1), flags = "czs")),
	"ror@": lambda il, operand: il.set_reg(1, "a", il.rotate_right_carry(1, il.reg(1, "a"), il.const(1, 1), flags = "czs")),
	"rti": lambda il, operand: rti(il),
	"rts": lambda il, operand: il.ret(il.add(2, il.pop(2), il.const(2, 1))),
	"sbc": lambda il, operand: il.set_reg(1, "a", il.sub_borrow(1, il.reg(1, "a"), operand, flags = "*")),
	"sec": lambda il, operand: il.set_flag("c", il.const(0, 1)),
	"sed": lambda il, operand: il.set_flag("d", il.const(0, 1)),
	"sei": lambda il, operand: il.set_flag("i", il.const(0, 1)),
	"sta": lambda il, operand: il.store(1, operand, il.reg(1, "a")),
	"stx": lambda il, operand: il.store(1, operand, il.reg(1, "x")),
	"sty": lambda il, operand: il.store(1, operand, il.reg(1, "y")),
	"tax": lambda il, operand: il.set_reg(1, "x", il.reg(1, "a"), flags = "zs"),
	"tay": lambda il, operand: il.set_reg(1, "y", il.reg(1, "a"), flags = "zs"),
	"tsx": lambda il, operand: il.set_reg(1, "x", il.reg(1, "s"), flags = "zs"),
	"txa": lambda il, operand: il.set_reg(1, "a", il.reg(1, "x"), flags = "zs"),
	"txs": lambda il, operand: il.set_reg(1, "s", il.reg(1, "x")),
	"tya": lambda il, operand: il.set_reg(1, "a", il.reg(1, "y"), flags = "zs")
}

'''
DEX Structure - https://source.android.com/devices/tech/dalvik/dex-format.html (best resource)
http://elinux.org/images/d/d9/A_deep_dive_into_dex_file_format--chiossi.pdf
https://android.googlesource.com/platform/art/+/master/tools/dexfuzz/src/dexfuzz/rawdex/HeaderItem.java

IMPORTANT
.read(offset, 4) # last arg is the "count", not the "last idex to read"

'''


# sizes of fields
# look at dex.c -  DexHeader is the first header (is what it really seems to be)
	# looking at dexparse.py - DexOptHeader seems to be the first header..
# https://docs.python.org/2/library/struct.html
# https://gist.github.com/ezterry/1239615

class dexOptHeader:
	def __init__(self):
		pass

	def dexOffset(self):
		offset = 4

		tmp = self.data.read(offset, 4)

		print "|", len(tmp), "|"

		return struct.unpack("<I", tmp)[0]

	# assuming DexOptHeader is first header
	def dexLength(self):
		offset = 8

		tmp = self.data.read(offset, 4)
		return struct.unpack("<I", tmp)[0]

	# assuming DexOptHeader is first header
	def depsOffset(self):
		offset = 16

		tmp = self.data.read(offset, 4)
		return struct.unpack("<I", tmp)[0]

	# assuming DexOptHeader is first header
	def depsLength(self):
		offset = 20

		tmp = self.data.read(offset, 4)
		return struct.unpack("<I", tmp)[0]

	# assuming DexOptHeader is first header
	def optOffset(self):
		offset = 24

		tmp = self.data.read(offset, 4)
		return struct.unpack("<I", tmp)[0]

	# assuming DexOptHeader is first header
	def optLength(self):
		offset = 28

		tmp = self.data.read(offset, 4)
		return struct.unpack("<I", tmp)[0]

#
# in dexparse.py - the fp seeks to dexOptHdr.dexOffset
#
class dexHeader(dexOptHeader):
	def __init__(self):
		dexOptHeader.__init__(self)

	# returns hex
	# ubyte[8] = DEX_FILE_MAGIC
	def magic(self):
		result = self.data.read(0, 8)

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

		result = self.data.read(offset, checksum_size)
		result = struct.unpack("<I", result)[0] # unsigned int

		adler32 = zlib.adler32(self.data.read(offset+checksum_size, self.file_size()-offset-checksum_size)) & (2**32-1)
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

		result = self.data.read(offset, signature_size) # I'm not sure why this is longer than "20"
		result = result.encode('hex')

		sha1 = hashlib.sha1(self.data.read(offset+signature_size, self.file_size()-offset-signature_size)).hexdigest()

		if result != sha1:
			print "sha1: ", sha1, " signature: ", result
			assert False

		return result

	# returns unsigned int
	def file_size(self):
		offset = 32

		result = self.data.read(offset, offset+4)[0:4]
		result = struct.unpack("<I", result)[0] # is currently printing correct info

		# dex file validation
		if result != len(self.data.file.raw):
			print "file_size method: ", hex(result), ", self.file.raw: ", hex(len(self.data.file.raw))
			assert False

		# binary string => unsigned int
		return result

	# format: unit = 0x70
	def header_size(self):
		offset = 36
		result = self.data.read(offset, 4)
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
		_protoIdsOff = self.data.read(offset, 4)

		return struct.unpack("<I", _protoIdsOff)[0] # TODO: verify

	# fieldIdsSize, fieldIdsOff

	# methodIdsSize, methodIdsOff (92 offset)
	# TODO - validate
	def methodIdsOff(self):
		offset = 92
		_methodIdsOff = self.data.read(offset, 4)[0:4]

		return struct.unpack("<I", _methodIdsOff)[0] # TODO: verify


	# each class_defs instance has a "class_data_off" field
	def class_defs(self):
		_class_defs_size = self.class_defs_size()
		_class_defs_off = self.class_defs_off()

		print "\nclass_defs_size: ", _class_defs_size, "\n"
		print "\nclass_defs_off: ", hex(_class_defs_off), "\n"

		#results = [] # list of class_def_item
		raw_class_defs = self.data.read(_class_defs_off, _class_defs_size)

		# split by class_def_item_size
		class_def_item_size = 8*4 # 8 uints
		results = [raw_class_defs[i:i+class_def_item_size] for i in range(0, len(raw_class_defs), class_def_item_size)]

		# TODO: parse each all_class_defs - into a dict maybe?
		#for idx, result in enumerate(results):
		for idx in range(3): # FIXME: so, when it crashes for some reason it actually shows the functions.. maybe because the Arch hasn't failed....??
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



			pass

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

		pass

	# GREPME
	# format: uint
	# TODO - validate
	def class_defs_size(self):
		offset = 96 # AFAIK

		result = self.data.read(offset, 4)
		result = struct.unpack("<I", result)[0]

		#print "\nclass_defs_size: ", result, "\n"

		return result

	# format: uint
	# TODO - validate
	# offset from the start of the file to the class definitions list, or 0 if class_defs_size == 0 (admittedly a strange edge case). The offset, if non-zero, should be to the start of the class_defs section.
	def class_defs_off(self):
		offset = 100 # AFAIK

		result = self.data.read(offset, 4)
		result = struct.unpack("<I", result)[0]

		#print "\nclass_defs_off: ", result, "\n"

		assert result < len(self.data.file.raw)

		return result

	# dataSize, dataOff (108)
	# TODO - validate
	def dataSize(self):
		offset = 104 # unknown if this is correct..
		_dataOff = self.data.read(offset, 4)[0:4]

		return struct.unpack("<I", _dataOff)[0] # TODO: verify

	# TODO - validate
	def dataOff(self):
		offset = 108 # I believe this is correct
		_dataOff = self.data.read(offset, 4)[0:4]

		# print len(_dataOff)
		assert len(_dataOff) > 0 # TODO: be more specific


		return struct.unpack("<I", _dataOff)[0] # TODO: verify

'''
	 = {
			"DexOptHeader": 40, # - sizeof == 40
			"DexHeader": 112, # - sizeof == 112
			"DexStringId": 4,
			"DexTypeId": 4,
			"DexFieldId": 8,
			"DexMethodId": 8,
			"DexProtoId": 12,
			"DexClassDef": 32,

			"DexLink": 1,
			"DexClassLookup": 20,
			"pRegisterMapPool": 8 # void*
}

	^^^^

			baseAddr # so this is at position 249 or 250
			overhead
'''

# I DO NOT believe DexOptHeader is the first header..

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

class DexFile(dexHeader): # DexOptHeader not defined...
	def __init__(self): # data is binaryView
		dexHeader.__init__(self)

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

		# DexOptHeader - these values seem wrong
		#print "dexOffset: ", DexOptHeader_data.dexOffset()
		#print "dexLength: ", DexOptHeader_data.dexLength()
		#print "depsOffset: ", DexOptHeader_data.depsOffset()
		#print "depsLength: ", DexOptHeader_data.depsLength()
		#print "optOffset: ", DexOptHeader_data.optOffset()
		#print "optLength: ", DexOptHeader_data.optLength()

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


class DEXViewUpdateNotification(BinaryDataNotification):
	def __init__(self, view):
		self.view = view

	# FIXME: don't trust - pulled from NES.py
	# NOTE: when you patche and write dex code
	#	* must update checksum + signature + file size + something else?
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


# FIXME TODO
# https://source.android.com/devices/tech/dalvik/dalvik-bytecode.html
# https://source.android.com/devices/tech/dalvik/dex-format.html
# smali is the "bytecode"
'''
registers are considered 32 bits wide. Adjacent register pairs are used for 64-bit values. There is no alignment requirement for register pairs.

The storage unit in the instruction stream is a 16-bit unsigned quantity. Some bits in some instructions are ignored / must-be-zero.
'''
class DEX(Architecture):
	name = "dex"
	address_size = 2 # TODO - doesn't seem to impact size of data in "decode_instruction"
	default_int_size = 1 # TODO
	regs = {
		# register-based, and frames are fixed in size upon creation
		"r0": RegisterInfo("r0", 1), # TODO
		"r1": RegisterInfo("r1", 1), # TODO
		"r2": RegisterInfo("r2", 1), # TODO
		"r3": RegisterInfo("r3", 1), # TODO
		"r4": RegisterInfo("r4", 1), # TODO
		"r5": RegisterInfo("r5", 1), # TODO

		"r13": RegisterInfo("r5", 1) # stack pointer (SP), which isn't used in dalvik
		# TODO: more


	}
	stack_pointer = "r13" # TODO - no stack in dalvik? - techically R13 or SP, FIXME: this shouldn't be required by binja
	flags = ["c", "z", "i", "d", "b", "v", "s"] # TODO
	flag_write_types = ["*", "czs", "zvs", "zs"] # TODO

	def decode_instruction(self, data, addr):
		if len(data) < 1:
			return None, None, None, None

		opcode = ord(data[0])

		# temp hack - will be elimated when I fully populate InstructionNames list
		if opcode >= len(InstructionNames):
			return None, None, None, None

		#log(2, "opcode: %s" % str(opcode))

		instr = InstructionNames[opcode]
		if instr is None:
			return None, None, None, None

		operand = InstructionOperandTypes[opcode] # TODO
		#log(2, "operand: %s" % str(operand))

		length = 1 + OperandLengths[operand] # TODO
		#log(2, "length: %s" % str(length))

		if len(data) < length:
			return None, None, None, None

		# len(data) == 16, why??
		#log(2, "decode_instruction, len(data): %i" % len(data))

		print data.encode('hex')

		value = None # for the NOP
		return instr, operand, length, value

	# first one called
	def perform_get_instruction_info(self, data, addr):
		#log(2, "perform_get_instruction_info")

		instr, operand, length, value = self.decode_instruction(data, addr)
		if instr is None:
			return None

		result = InstructionInfo()
		result.length = length

		#
		# TODO: implement jumps and other oddities
		#

		return result


	def perform_get_instruction_text(self, data, addr):
		#log(2, "perform_get_instruction_text")

		instr, operand, length, value = self.decode_instruction(data, addr)
		if instr is None:
			return None

		# I don't think we control "InstructionTextToken"

		tokens = []
		tokens.append(InstructionTextToken(TextToken, "%-7s " % instr.replace("@", "")))
		tokens += OperandTokens[operand](value)
		return tokens, length
	

# see NESView Example
# pretty sure this is triggered when we do the "write" call...
class DEXView(BinaryView, DexFile):
	name = "DEX"
	long_name = "Dalvik Executable"

	# data == BinaryView datatype
	def __init__(self, data):
		print "DEXView::__init__"
		BinaryView.__init__(self, data.file)

		self.data = data # FIXME: is this what we can do DexFile() on?
		DexFile.__init__(self) # how do I make sure this has access to BinaryView... (to read from it)

		self.notification = DEXViewUpdateNotification(self) # TODO
		self.data.register_notification(self.notification)

		self.print_metadata()

		# this might be a better way to do it. Just create functions
		#data.create_user_function(bv.platform, 0) # FAILURE TO CREATE VIEW..

	@classmethod
	def is_valid_for_data(self, data):
		print "DEXView::is_valid_for_data"

		hdr = data.read(0, 16)
		if len(hdr) < 16:
				return False
		# magic - https://en.wikipedia.org/wiki/List_of_file_signatures
		if hdr[0:8] != DEX_MAGIC: # dex file format
				return False

		return True


	def init(self):
		try:
			# TODO: look at NES.py
			self.add_entry_point(Architecture['dex'].standalone_platform, self.perform_get_entry_point())

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
	#print("[perform_get_start]") # NOTE: seems to infinite loop (for both 0 or 1 return, haven't tested others)
			return 0


	# FIXME
	def perform_get_length(self):
			return 0x10000

	def perform_is_executable(self):
			return True

	# FIXME
	def perform_get_entry_point(self):
		dataOff = self.dataOff()
		fileSize = len(self.data.file.raw) # TODO: is this checking size of APK, or size of dex...

		print "dexBinja::perform_get_entry_point: ", dataOff, "hex(dataOff): ", hex(dataOff), ", file size: ", fileSize

		assert dataOff <= fileSize

		return dataOff


	'''
		[DexOptHeader] - sizeof == 40
		[DexHeader] - sizeof == 112
		[DexStringId]
		[DexTypeId
		[DexFieldId
		[DexMethodId]
		[DexProtoId]
		[DexClassDef]
		[DexLink]

		[DexClassLookup]
		[void * pRegisterMapPool]
		[baseAddr]
		[overhead]

	'''

'''
# this would be easier with UI plugins

# I'll need to carve out the dex code


'''

print("dexBinja - for real")
print("test against classes2.dex - because there is actually dex code..")
class DEXViewBank(DEXView):
	name = "DEX"
	long_name = "Dalvik Executable"

	def __init__(self, data):
		DEXView.__init__(self, data)


DEXViewBank.register() # so, currently depending on apkBinja NOT dexBinja.py....

DEX.register() # TODO


# Architecture.register
