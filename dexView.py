from binaryninja import *
from dexFile import *
import struct
import traceback
import hashlib # to validate SHA1 signature
import zlib # to validate adler32 checksum
import os

DEX_MAGIC = "dex\x0a035\x00"

# android dex opcodes: https://docs.google.com/spreadsheets/d/1SN5W0uwl0BRRAIngPOk9eMAt9VSkGCGD6w4bCe5akvc/edit#gid=0

# ~/binaryninja/binaryninja /home/noot/CTF/tmp/classes2.dex
	# they already did it https://gist.github.com/ezterry/1239615

# style guideline: https://google.github.io/styleguide/pyguide.html
# 010Editor: https://github.com/strazzere/010Editor-stuff/blob/master/Templates/DEXTemplate.bt
# export PYTHONPATH=$PYTHONPATH:$HOME/binaryninja/python

# https://source.android.com/devices/tech/dalvik/dalvik-bytecode.html

# style guideline: https://google.github.io/styleguide/pyguide.html
# export PYTHONPATH=$PYTHONPATH:$HOME/binaryninja/python

# https://source.android.com/devices/tech/dalvik/dalvik-bytecode.html
# https://source.android.com/devices/tech/dalvik/instruction-formats.html
# http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html

# TODO: verify accuracy - http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html

codes = {
	# "offset": "length",

}

'''
# read from "android dex opcodes" google spreadsheet
for line in open("data").readlines():
	opcode, instructionName, operandLength = line.rstrip().split("\t")
	print  "%s: {\"name\": \"%s\", \"length\": \"%s\"}," % (opcode, instructionName, operandLength)
'''

# FIXME:
Instruction = {
	0x0: {"name": "nop", "length": 0},
	0x1: {"name": "move", "length": 1},
	0x2: {"name": "move/from16", "length": 2},
	0x3: {"name": "move/16", "length": 3}, # FIXME: is this right?
	0x4: {"name": "move-wide", "length": 2},
	0x5: {"name": "move-wide/from16", "length": 2},
	0x6: {"name": "move-wide/16", "length": 3}, # FIXME: is this right?
	0x7: {"name": "move-object", "length": 1},
	0x8: {"name": "move-object/from16", "length": 2},
	0x9: {"name": "move-object/16", "length": 3}, # FIXME: is this right?
	0xa: {"name": "move-result", "length": 1},
	0xb: {"name": "move-result-wide", "length": 1},
	0xc: {"name": "move-result-object", "length": 1},
	0xd: {"name": "move-exception", "length": 1},
	0xe: {"name": "return-void", "length": 1},
	0xf: {"name": "return", "length": 1},
	0x10: {"name": "return-wide", "length": 1},
	0x11: {"name": "return-object", "length": 1},
	0x12: {"name": "const/4", "length": 1},
	0x13: {"name": "const/16", "length": 3},
	0x14: {"name": "const", "length": 3}, # FIXME - look at the lambda
	0x15: {"name": "const/high16", "length": 2},
	0x16: {"name": "const-wide/16", "length": 2},
	0x17: {"name": "const-wide/32", "length": 5},
	0x18: {"name": "const-wide", "length": 7},
	0x19: {"name": "const-wide/high16", "length": 3},
	0x1a: {"name": "const-string", "length": 3},
	0x1b: {"name": "const-string-jumbo", "length": 3},
	0x1c: {"name": "const-class", "length": 3},
	0x1d: {"name": "monitor-enter", "length": 1},
	0x1e: {"name": "monitor-exit", "length": 1},
	0x1f: {"name": "check-cast", "length": 3},
	0x20: {"name": "instance-of", "length": 3},
	0x21: {"name": "array-length", "length": 1},
	0x22: {"name": "new-instance", "length": 3},
	0x23: {"name": "new-array", "length": 3},
	0x24: {"name": "filled-new-array", "length": 5},
	0x25: {"name": "filled-new-array-range ", "length": 5},
	0x26: {"name": "fill-array-data", "length": 5},
	0x27: {"name": "throw", "length": 1},
	0x28: {"name": "goto", "length": 1},
	0x29: {"name": "goto/16", "length": 3},
	0x2a: {"name": "goto/32", "length": 3},
	0x2b: {"name": "packed-switch", "length": 5},
	0x2c: {"name": "sparse-switch", "length": 5},
	0x2d: {"name": "cmpl-float", "length": 3},
	0x2e: {"name": "cmpg-float", "length": 3},
	0x2f: {"name": "cmpl-double", "length": 3},
	0x30: {"name": "cmpg-double", "length": 3},
	0x31: {"name": "cmp-long", "length": 3},
	0x32: {"name": "if-eq", "length": 3},
	0x33: {"name": "if-ne", "length": 3},
	0x34: {"name": "if-lt", "length": 3},
	0x35: {"name": "if-ge", "length": 3},
	0x36: {"name": "if-gt", "length": 3},
	0x37: {"name": "if-le", "length": 3},
	0x38: {"name": "if-eqz", "length": 3},
	0x39: {"name": "if-nez", "length": 3},
	0x3a: {"name": "if-ltz", "length": 3},
	0x3b: {"name": "if-gez", "length": 3},
	0x3c: {"name": "if-gtz", "length": 3},
	0x3d: {"name": "if-lez", "length": 3},
	0x3e: {"name": "None", "length": 0},
	0x3f: {"name": "None", "length": 0},
	0x40: {"name": "None", "length": 0},
	0x41: {"name": "None", "length": 0},
	0x42: {"name": "None", "length": 0},
	0x43: {"name": "None", "length": 0},
	0x44: {"name": "aget", "length": 3},
	0x45: {"name": "aget-wide", "length": 3},
	0x46: {"name": "aget-object", "length": 3},
	0x47: {"name": "aget-boolean", "length": 3},
	0x48: {"name": "aget-byte", "length": 3},
	0x49: {"name": "aget-char", "length": 3},
	0x4a: {"name": "aget-short", "length": 3},
	0x4b: {"name": "aput", "length": 3},
	0x4c: {"name": "aput-wide", "length": 3},
	0x4d: {"name": "aput-object", "length": 3},
	0x4e: {"name": "aput-boolean", "length": 3},
	0x4f: {"name": "aput-byte", "length": 3},
	0x50: {"name": "aput-char", "length": 3},
	0x51: {"name": "aput-short", "length": 3},
	0x52: {"name": "iget", "length": 3},
	0x53: {"name": "iget-wide", "length": 3},
	0x54: {"name": "iget-object", "length": 3},
	0x55: {"name": "iget-boolean", "length": 3},
	0x56: {"name": "iget-byte", "length": 3},
	0x57: {"name": "iget-char", "length": 3},
	0x58: {"name": "iget-short", "length": 3},
	0x59: {"name": "iput", "length": 3},
	0x5a: {"name": "iput-wide", "length": 3},
	0x5b: {"name": "iput-object", "length": 3},
	0x5c: {"name": "iput-boolean", "length": 3},
	0x5d: {"name": "iput-byte", "length": 3},
	0x5e: {"name": "iput-char", "length": 3},
	0x5f: {"name": "iput-short", "length": 3},
	0x60: {"name": "sget", "length": 3},
	0x61: {"name": "sget-wide", "length": 3},
	0x62: {"name": "sget-object", "length": 3},
	0x63: {"name": "sget-boolean", "length": 3},
	0x64: {"name": "sget-byte", "length": 3},
	0x65: {"name": "sget-char", "length": 3},
	0x66: {"name": "sget-short", "length": 3},
	0x67: {"name": "sput", "length": 3},
	0x68: {"name": "sput-wide", "length": 3},
	0x69: {"name": "sput-object", "length": 3},
	0x6a: {"name": "sput-boolean", "length": 3},
	0x6b: {"name": "sput-byte", "length": 3},
	0x6c: {"name": "sput-char", "length": 3},
	0x6d: {"name": "sput-short", "length": 3},
	0x6e: {"name": "invoke-virtual", "length": 5},
	0x6f: {"name": "invoke-super", "length": 5},
	0x70: {"name": "invoke-direct", "length": 5},
	0x71: {"name": "invoke-static", "length": 5},
	0x72: {"name": "invoke-interface", "length": 5},
	0x73: {"name": "None", "length": 0},
	0x74: {"name": "invoke-virtual/range", "length": 5},
	0x75: {"name": "invoke-super/range", "length": 5},
	0x76: {"name": "invoke-direct/range", "length": 5},
	0x77: {"name": "invoke-static/range", "length": 5},
	0x78: {"name": "invoke-interface/range", "length": 5},
	0x79: {"name": "None", "length": 0},
	0x7a: {"name": "None", "length": 0},
	0x7b: {"name": "neg-int", "length": 1},
	0x7c: {"name": "not-int", "length": 1},
	0x7d: {"name": "neg-long", "length": 1},
	0x7e: {"name": "not-long", "length": 1},
	0x7f: {"name": "neg-float", "length": 1},
	0x80: {"name": "neg-double", "length": 1},
	0x81: {"name": "int-to-long", "length": 1},
	0x82: {"name": "int-to-float", "length": 1},
	0x83: {"name": "int-to-double", "length": 1},
	0x84: {"name": "long-to-int", "length": 1},
	0x85: {"name": "long-to-float", "length": 1},
	0x86: {"name": "long-to-double", "length": 1},
	0x87: {"name": "float-to-int", "length": 1},
	0x88: {"name": "float-to-long", "length": 1},
	0x89: {"name": "float-to-double", "length": 1},
	0x8a: {"name": "double-to-int", "length": 1},
	0x8b: {"name": "double-to-long", "length": 1},
	0x8c: {"name": "double-to-float", "length": 1},
	0x8d: {"name": "int-to-byte", "length": 1},
	0x8e: {"name": "int-to-char", "length": 1},
	0x8f: {"name": "int-to-short", "length": 1},
	0x90: {"name": "add-int", "length": 3},
	0x91: {"name": "sub-int", "length": 3},
	0x92: {"name": "mul-int", "length": 3},
	0x93: {"name": "div-int", "length": 3},
	0x94: {"name": "rem-int", "length": 3},
	0x95: {"name": "and-int", "length": 3},
	0x96: {"name": "or-int", "length": 3},
	0x97: {"name": "xor-int", "length": 3},
	0x98: {"name": "shl-int", "length": 3},
	0x99: {"name": "shr-int", "length": 3},
	0x9a: {"name": "ushr-int", "length": 3},
	0x9b: {"name": "add-long", "length": 3},
	0x9c: {"name": "sub-long", "length": 3},
	0x9d: {"name": "mul-long", "length": 3},
	0x9e: {"name": "div-long", "length": 3},
	0x9f: {"name": "rem-long", "length": 3},
	0xa0: {"name": "and-long", "length": 3},
	0xa1: {"name": "or-long", "length": 3},
	0xa2: {"name": "xor-long", "length": 3},
	0xa3: {"name": "shl-long", "length": 3},
	0xa4: {"name": "shr-long", "length": 3},
	0xa5: {"name": "ushr-long", "length": 3},
	0xa6: {"name": "add-float", "length": 3},
	0xa7: {"name": "sub-float", "length": 3},
	0xa8: {"name": "mul-float", "length": 3},
	0xa9: {"name": "div-float", "length": 3},
	0xaa: {"name": "rem-float", "length": 3},
	0xab: {"name": "add-double", "length": 3},
	0xac: {"name": "sub-double", "length": 3},
	0xad: {"name": "mul-double", "length": 3},
	0xae: {"name": "div-double", "length": 3},
	0xaf: {"name": "rem-double", "length": 3},
	0xb0: {"name": "add-int/2addr", "length": 1},
	0xb1: {"name": "sub-int/2addr", "length": 1},
	0xb2: {"name": "mul-int/2addr", "length": 1},
	0xb3: {"name": "div-int/2addr", "length": 1},
	0xb4: {"name": "rem-int/2addr", "length": 1},
	0xb5: {"name": "and-int/2addr", "length": 1},
	0xb6: {"name": "or-int/2addr", "length": 1},
	0xb7: {"name": "xor-int/2addr", "length": 1},
	0xb8: {"name": "shl-int/2addr", "length": 1},
	0xb9: {"name": "shr-int/2addr", "length": 1},
	0xba: {"name": "ushr-int/2addr", "length": 1},
	0xbb: {"name": "add-long/2addr", "length": 1},
	0xbc: {"name": "sub-long/2addr", "length": 1},
	0xbd: {"name": "mul-long/2addr", "length": 1},
	0xbe: {"name": "div-long/2addr", "length": 1},
	0xbf: {"name": "rem-long/2addr", "length": 1},
	0xc0: {"name": "and-long/2addr", "length": 1},
	0xc1: {"name": "or-long/2addr", "length": 1},
	0xc2: {"name": "xor-long/2addr", "length": 1},
	0xc3: {"name": "shl-long/2addr", "length": 1},
	0xc4: {"name": "shr-long/2addr", "length": 1},
	0xc5: {"name": "ushr-long/2addr", "length": 1},
	0xc6: {"name": "add-float/2addr", "length": 1},
	0xc7: {"name": "sub-float/2addr", "length": 1},
	0xc8: {"name": "mul-float/2addr", "length": 1},
	0xc9: {"name": "div-float/2addr", "length": 1},
	0xca: {"name": "rem-float/2addr", "length": 1},
	0xcb: {"name": "add-double/2addr", "length": 1},
	0xcc: {"name": "sub-double/2addr", "length": 1},
	0xcd: {"name": "mul-double/2addr", "length": 1},
	0xce: {"name": "div-double/2addr", "length": 1},
	0xcf: {"name": "rem-double/2addr", "length": 1},
	0xd0: {"name": "add-int/lit16", "length": 3},
	0xd1: {"name": "sub-int/lit16", "length": 3},
	0xd2: {"name": "mul-int/lit16", "length": 3},
	0xd3: {"name": "div-int/lit16", "length": 3},
	0xd4: {"name": "rem-int/lit16", "length": 3},
	0xd5: {"name": "and-int/lit16", "length": 3},
	0xd6: {"name": "or-int/lit16", "length": 3},
	0xd7: {"name": "xor-int/lit16", "length": 3},
	0xd8: {"name": "add-int/lit8", "length": 3},
	0xd9: {"name": "sub-int/lit8", "length": 3},
	0xda: {"name": "mul-int/lit8", "length": 3},
	0xdb: {"name": "div-int/lit8", "length": 3},
	0xdc: {"name": "rem-int/lit8", "length": 3},
	0xdd: {"name": "and-int/lit8", "length": 3},
	0xde: {"name": "or-int/lit8", "length": 3},
	0xdf: {"name": "xor-int/lit8", "length": 3},
	0xe0: {"name": "shl-int/lit8", "length": 3},
	0xe1: {"name": "shr-int/lit8", "length": 3},
	0xe2: {"name": "ushr-int/lit8", "length": 3},
	0xe3: {"name": "None", "length": 0},
	0xe4: {"name": "None", "length": 0},
	0xe5: {"name": "None", "length": 0},
	0xe6: {"name": "None", "length": 0},
	0xe7: {"name": "None", "length": 0},
	0xe8: {"name": "None", "length": 0},
	0xe9: {"name": "None", "length": 0},
	0xea: {"name": "None", "length": 0},
	0xeb: {"name": "None", "length": 0},
	0xec: {"name": "None", "length": 0},
	0xed: {"name": "None", "length": 0},
	0xee: {"name": "execute-inline", "length": 5},
	0xef: {"name": "None", "length": 0},
	0xf0: {"name": "invoke-direct-empty", "length": 5},
	0xf1: {"name": "None", "length": 0},
	0xf2: {"name": "iget-quick", "length": 3},
	0xf3: {"name": "iget-wide-quick", "length": 3},
	0xf4: {"name": "iget-object-quick", "length": 3},
	0xf5: {"name": "iput-quick", "length": 3},
	0xf6: {"name": "iput-wide-quick", "length": 3},
	0xf7: {"name": "iput-object-quick", "length": 3},
	0xf8: {"name": "invoke-virtual-quick", "length": 5},
	0xf9: {"name": "invoke-virtual-quick/range", "length": 5},
	0xfa: {"name": "invoke-super-quick", "length": 5},
	0xfb: {"name": "invoke-super-quick/range", "length": 5},
	0xfc: {"name": "None", "length": 0},
	0xfd: {"name": "None", "length": 0},
	0xfe: {"name": "None", "length": 0},
	0xff: {"name": "None", "length": 0}
}

RegisterNames = [
	"v0", # I believe 0 == v0
	"v1",
	"v2",
	"v3",
	"v4",
	"v5",
	"v8", # last one I saw that seems to map "X" to vX - but it makes sense to go to v15 since 0xF is max
	"v9",
	"v10", # 0xa
	"v11", # 0xB
	"v12", # 0xC
	"v13", # 0xD
	"v14", # 0xE
	"v15",  # 0xF

	# EXTENDED registers
	"v16",
	"v17",
	"v18",
	"v19",
	"v20",
	"v21",
	"v22",
	"v23",
	"v24",
	"v25",

]

# used for perform_get_instruction_text
OperandTokens = [
	lambda value: [], # NOP
	lambda value: [InstructionTextToken(RegisterToken, RegisterNames[value & 0xF]),
		InstructionTextToken(TextToken, ", "),
		InstructionTextToken(RegisterToken, RegisterNames[value >> 4])], # MOVE

	lambda value: [], # TODO: implement MOVE_FROM16

	# MOVE_16
	lambda value: [
		#InstructionTextToken(RegisterToken, RegisterNames[value & 0xFF]), # maybe?  - FAIL: (value >> 8), (value >> 16)
		#InstructionTextToken(TextToken, ", "),
		#InstructionTextToken(RegisterToken, RegisterNames[value >> 8])
		], # TODO: implement

	lambda value: [], # TODO: implement MOVE_WIDE
	lambda value: [], # TODO: implement MOVE_WIDE_FROM_16
	lambda value: [], # TODO: implement MOVE_WIDE_16
	lambda value: [], # TODO: implement MOVE_OBJECT
	lambda value: [], # TODO: MOVE_OBJECT_FROM_16

	# MOVE_OBJECT_16
	lambda value: [], # NONE

	# MOVE_RESULT
	lambda value: [], # NONE

	# MOVE_RESULT_WIDE
	lambda value: [], # NONE

	# MOVE_RESULT_OBJECT
	lambda value: [], # NONE

	# MOVE_EXCEPTION
	lambda value: [], # NONE

	# RETURN_VOID
	lambda value: [], # NONE

	# RETURN
	lambda value: [], # NONE

	# RETURN_WIDE
	lambda value: [], # NONE

	# RETURN_OBJECT
	lambda value: [], # NONE

	# CONST_4
	lambda value: [], # NONE

	# CONST_16 - OK AFAIK
	# [00 0A][00] => const/16 v0, 10   - I believe this is true
	lambda value: [
		#InstructionTextToken(RegisterToken, RegisterNames[value & 0xFF]), # maybe?  - FAIL: (value >> 8), (value >> 16)
		#InstructionTextToken(TextToken, ", "),
		#InstructionTextToken(PossibleAddressToken, "%i" % (value >> 8), value)
		], # 16 bit constant

	lambda value: [], # CONST
	lambda value: [], # CONST_HIGH16
	lambda value: [], # CONST_WIDE16
	lambda value: [], # CONST_WIDE32
	lambda value: [], # CONST_WIDE
	lambda value: [], # CONST_WIDE_HIGH16
	lambda value: [], # CONST_STRING
	lambda value: [], # CONST_STRING_JUMBO
	lambda value: [], # CONST_CLASS
	lambda value: [], # MONITOR_ENTER
	lambda value: [], # MONITOR_EXIT
	lambda value: [], # CHECK_CAST
	lambda value: [], # INSTANCE_OF
	lambda value: [], # ARRAY_LENGTH
	lambda value: [], # NEW_INSTANCE

	# NEW_ARRAY
	# https://source.android.com/devices/tech/dalvik/dex-format.html # look at Value formats
	lambda value: [
		#InstructionTextToken(RegisterToken, RegisterNames[(value >> 16) & 0xF]),
		#InstructionTextToken(TextToken, ", "),
		#InstructionTextToken(RegisterToken, RegisterNames[value >> 20]),
		#InstructionTextToken(TextToken, ", "),
		#InstructionTextToken(TextToken, "unimplemented") # https://source.android.com/devices/tech/dalvik/dex-format.html # look at Value formats, AFAIK this is relevant
														# example "0x19", this may be pulling it from the "field_ids" section
		],

	lambda value: [], # FILLED_NEW_ARRAY
	lambda value: [], # FILLED_NEW_ARRAY_RANGE
	lambda value: [
		InstructionTextToken(RegisterToken, RegisterNames[(value >> 32)]),
		InstructionTextToken(TextToken, ", "),
		InstructionTextToken(TextToken, "unimplemented") # array_data_offset
		], # FILL_ARRAY_DATA - seems working

	lambda value: [], # THROW

	lambda value: [], # GOTO
	lambda value: [], # GOTO_16
	lambda value: [], # GOTO_32

	lambda value: [], # PACKED_SWITCH
	lambda value: [], # SPARSE_SWITCH

	lambda value: [], # 0x2D CMPL_FLOAT
	lambda value: [], # CMPG_FLOAT
	lambda value: [], # CMPL_DOUBLE
	lambda value: [], # CMPG_DOUBLE
	lambda value: [], # CMP_LONG

	lambda value: [], # 0x32 IF_EQ
	lambda value: [], # IF_NE
	lambda value: [], # IF_LT
	lambda value: [], # IF_GE
	lambda value: [], # IF_GT
	lambda value: [], # IF_LE
	lambda value: [], # IF_EQZ
	lambda value: [], # IF_NEZ
	lambda value: [], # IF_LTZ
	lambda value: [], # IF_GEZ
	lambda value: [], # IF_GTZ
	lambda value: [], # IF_LEZ

	lambda value: [], # 0x3E UNUSED_3E
	lambda value: [], # UNUSED_3F
	lambda value: [], # UNUSED_40
	lambda value: [], # UNUSED_41
	lambda value: [], # UNUSED_42
	lambda value: [], # UNUSED_43

	lambda value: [], # 0x44 AGET
	lambda value: [], # AGET_WIDE
	lambda value: [], # AGET_OBJECT
	lambda value: [], # AGET_BOOLEAN
	lambda value: [], # AGET_BYTE
	lambda value: [], # AGET_CHAR
	lambda value: [], # AGET_SHORT

	lambda value: [], # 0x4B APUT
	lambda value: [], # APUT_WIDE
	lambda value: [], # APUT_OBJECT
	lambda value: [], # APUT_BOOLEAN
	lambda value: [], # APUT_BYTE
	lambda value: [], # APUT_CHAR
	lambda value: [], # APUT_SHORT

	lambda value: [], # 0x52 IGET
	lambda value: [], # IGET_WIDE
	lambda value: [], # IGET_OBJECT
	lambda value: [], # IGET_BOOLEAN
	lambda value: [], # IGET_BYTE
	lambda value: [], # IGET_CHAR
	lambda value: [], # IGET_SHORT

	lambda value: [], # 0x5A IPUT
	lambda value: [], # IPUT_WIDE
	lambda value: [], # IPUT_OBJECT
	lambda value: [], # IPUT_BOOLEAN
	lambda value: [], # IPUT_BYTE
	lambda value: [], # IPUT_CHAR
	lambda value: [], # IPUT_SHORT

	lambda value: [], # 0x60 SGET
	lambda value: [], # SGET_WIDE
	lambda value: [], # SGET_OBJECT
	lambda value: [], # SGET_BOOLEAN
	lambda value: [], # SGET_BYTE
	lambda value: [], # SGET_CHAR
	lambda value: [], # SGET_SHORT

	lambda value: [], # 0x67 SPUT

	# FIXME: not working - not right index?
	lambda value: [InstructionTextToken(RegisterToken, RegisterNames[(value >> 16)]), # not sure if it's 16 or 20
		InstructionTextToken(TextToken, ", "),
		InstructionTextToken(TextToken, "unimplemented") #  field_id - this specifies the entry number in the field id table
		], # SPUT_WIDE

	lambda value: [], # SPUT_OBJECT

	# FIXME: this is not working - this must not be the right index in OperandTokens
	lambda value: [InstructionTextToken(RegisterToken, RegisterNames[(value >> 16)]), # not sure if it's 16 or 20
		InstructionTextToken(TextToken, ", "),
		InstructionTextToken(TextToken, "unimplemented") #  field_id - this specifies the entry number in the field id table
		], # 0x6A SPUT_BOOLEAN

	lambda value: [], # SPUT_BYTE
	lambda value: [], # SPUT_CHAR
	lambda value: [], # SPUT_SHORT
	lambda value: [], # INVOKE_VIRTUAL
	lambda value: [], # INVOKE_SUPER
	lambda value: [], # INVOKE_DIRECT
	lambda value: [], # INVOKE_STATIC

	# FIXME: I DO NOT TRUST THIS....
	lambda value: [
		# The invocation parameter list encoding is somewhat weird.
		# Starting if parameter number > 4 and parameter number % 4 == 1, the 5th (9th, etc.) parameter is encoded on the 4 lowest bit of the byte immediately following the instruction.
		# Curiously, this encoding is not used in case of 1 parameter, in this case an entire 16 bit word is added after the method index of which only 4 bit is used to encode
 		# the single parameter while the lowest 4 bit of the byte following the instruction byte is left unused.

		#InstructionTextToken(TextToken, "{"),
		#InstructionTextToken(RegisterToken, RegisterNames[value & 0xF00]), # FIXME: ERROR HERE
		#InstructionTextToken(TextToken, ", "),
		#InstructionTextToken(RegisterToken, RegisterNames[value & 0xF000]),
		#InstructionTextToken(TextToken, ", "),
		#InstructionTextToken(RegisterToken, RegisterNames[value & 0xF]),
		#InstructionTextToken(TextToken, ", "),
		#InstructionTextToken(RegisterToken, RegisterNames[value & 0xF0]),
		#InstructionTextToken(TextToken, "}"),
		#InstructionTextToken(TextToken, ", "),
		#InstructionTextToken(TextToken, "unimplemented"), # methodtocall - it's probably an offset to a method list

		], # INVOKE_INTERFACE

	lambda value: [], # UNUSED_73
	lambda value: [], # INVOKE_VIRTUAL_RANGE
	lambda value: [], # INVOKE_SUPER_RANGE
	lambda value: [], # INVOKE_DIRECT_RANGE
	lambda value: [], # INVOKE_STATIC_RANGE
	lambda value: [], # INVOKE_INTERFACE_RANGE
	lambda value: [], # UNUSED_79
	lambda value: [], # UNUSED_7A
	lambda value: [], # NEG_INT
	lambda value: [], # NOT_INT
	lambda value: [], # NEG_LONG
	lambda value: [], # NOT_LONG
	lambda value: [], # NEG_FLOAT
	lambda value: [], # NEG_DOUBLE
	lambda value: [], # INT_TO_LONG
	lambda value: [], # INT_TO_FLOAT
	lambda value: [], # INT_TO_DOUBLE
	lambda value: [], # LONG_TO_INT
	lambda value: [], # LONG_TO_FLOAT
	lambda value: [], # LONG_TO_DOUBLE
	lambda value: [], # FLOAT_TO_INT
	lambda value: [], # FLOAT_TO_LONG
	lambda value: [], # FLOAT_TO_DOUBLE
	lambda value: [], # DOUBLE_TO_INT
	lambda value: [], # DOUBLE_TO_LONG
	lambda value: [], # DOUBLE_TO_FLOAT
	lambda value: [], # INT_TO_BYTE
	lambda value: [], # INT_TO_CHAR
	lambda value: [], # INT_TO_SHORT
	lambda value: [], # ADD_INT
	lambda value: [], # SUB_INT
	lambda value: [], # MUL_INT
	lambda value: [], # DIV_INT
	lambda value: [], # REM_INT
	lambda value: [], # AND_INT
	lambda value: [], # OR_INT
	lambda value: [], # XOR_INT
	lambda value: [], # SHL_INT
	lambda value: [], # SHR_INT
	lambda value: [], # USHR_INT
	lambda value: [], # ADD_LONG
	lambda value: [], # SUB_LONG
	lambda value: [], # MUL_LONG
	lambda value: [], # DIV_LONG
	lambda value: [], # REM_LONG
	lambda value: [], # AND_LONG
	lambda value: [], # OR_LONG
	lambda value: [], # XOR_LONG
	lambda value: [], # SHL_LONG
	lambda value: [], # SHR_LONG
	lambda value: [], # USHR_LONG
	lambda value: [], # ADD_FLOAT
	lambda value: [], # SUB_FLOAT
	lambda value: [], # MUL_FLOAT
	lambda value: [], # DIV_FLOAT
	lambda value: [], # REM_FLOAT
	lambda value: [], # ADD_DOUBLE
	lambda value: [], # SUB_DOUBLE
	lambda value: [], # MUL_DOUBLE
	lambda value: [], # DIV_DOUBLE
	lambda value: [], # REM_DOUBLE
	lambda value: [], # ADD_INT_2ADDR
	lambda value: [], # SUB_INT_2ADDR
	lambda value: [], # MUL_INT_2ADDR
	lambda value: [], # DIV_INT_2ADDR
	lambda value: [], # REM_INT_2ADDR
	lambda value: [], # AND_INT_2ADDR
	lambda value: [], # OR_INT_2ADDR
	lambda value: [], # XOR_INT_2ADDR
	lambda value: [], # SHL_INT_2ADDR
	lambda value: [], # SHR_INT_2ADDR
	lambda value: [], # USHR_INT_2ADDR
	lambda value: [], # ADD_LONG_2ADDR
	lambda value: [], # SUB_LONG_2ADDR
	lambda value: [], # MUL_LONG_2ADDR
	lambda value: [], # DIV_LONG_2ADDR
	lambda value: [], # REM_LONG_2ADDR
	lambda value: [], # AND_LONG_2ADDR
	lambda value: [], # OR_LONG_2ADDR
	lambda value: [], # XOR_LONG_2ADDR
	lambda value: [], # SHL_LONG_2ADDR
	lambda value: [], # SHR_LONG_2ADDR
	lambda value: [], # USHR_LONG_2ADDR
	lambda value: [], # ADD_FLOAT_2ADDR
	lambda value: [], # SUB_FLOAT_2ADDR
	lambda value: [], # MUL_FLOAT_2ADDR
	lambda value: [], # DIV_FLOAT_2ADDR
	lambda value: [], # REM_FLOAT_2ADDR
	lambda value: [], # ADD_DOUBLE_2ADDR
	lambda value: [], # SUB_DOUBLE_2ADDR
	lambda value: [], # MUL_DOUBLE_2ADDR
	lambda value: [], # DIV_DOUBLE_2ADDR
	lambda value: [], # REM_DOUBLE_2ADDR
	lambda value: [], # ADD_INT_LIT16
	lambda value: [], # SUB_INT_LIT16
	lambda value: [], # MUL_INT_LIT16
	lambda value: [], # DIV_INT_LIT16
	lambda value: [], # REM_INT_LIT16
	lambda value: [], # AND_INT_LIT16
	lambda value: [], # OR_INT_LIT16
	lambda value: [], # XOR_INT_LIT16
	lambda value: [], # ADD_INT_LIT8
	lambda value: [], # SUB_INT_LIT8
	lambda value: [], # MUL_INT_LIT8
	lambda value: [], # DIV_INT_LIT8
	lambda value: [], # REM_INT_LIT8
	lambda value: [], # AND_INT_LIT8
	lambda value: [], # OR_INT_LIT8
	lambda value: [], # XOR_INT_LIT8
	lambda value: [], # SHL_INT_LIT8
	lambda value: [], # SHR_INT_LIT8
	lambda value: [], # USHR_INT_LIT8
	lambda value: [], # UNUSED_E3
	lambda value: [], # UNUSED_E4
	lambda value: [], # UNUSED_E5
	lambda value: [], # UNUSED_E6
	lambda value: [], # UNUSED_E7
	lambda value: [], # UNUSED_E8
	lambda value: [], # UNUSED_E9
	lambda value: [], # UNUSED_EA
	lambda value: [], # UNUSED_EB
	lambda value: [], # UNUSED_EC
	lambda value: [], # UNUSED_ED
	lambda value: [], # EXECUTE_INLINE
	lambda value: [], # UNUSED_EF
	lambda value: [], # INVOKE_DIRECT_EMPTY
	lambda value: [], # UNUSED_F1
	lambda value: [], # IGET_QUICK
	lambda value: [], # IGET_WIDE_QUICK
	lambda value: [], # IGET_OBJECT_QUICK
	lambda value: [], # IPUT_QUICK
	lambda value: [], # IPUT_WIDE_QUICK
	lambda value: [], # IPUT_OBJECT_QUICK
	lambda value: [], # INVOKE_VIRTUAL_QUICK
	lambda value: [], # INVOKE_VIRTUAL_QUICK_RANGE
	lambda value: [], # INVOKE_SUPER_QUICK
	lambda value: [], # INVOKE_SUPER_QUICK_RANGE
	lambda value: [], # UNUSED_FC
	lambda value: [], # UNUSED_FD
	lambda value: [], # UNUSED_FE
	lambda value: [] # UNUSED_FF

]

InstructionIL = {
}

class DEXViewUpdateNotification(BinaryDataNotification):
	def __init__(self, view):
		self.view = view


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
		"v0": RegisterInfo("v0", 1), # TODO
		"v1": RegisterInfo("v1", 1), # TODO
		"v2": RegisterInfo("v2", 1), # TODO
		"v3": RegisterInfo("v3", 1), # TODO
		"v4": RegisterInfo("v4", 1), # TODO
		"v5": RegisterInfo("v5", 1), # TODO
		"v6": RegisterInfo("v6", 1), # TODO
		"v7": RegisterInfo("v7", 1), # TODO
		"v8": RegisterInfo("v8", 1), # TODO
		"v9": RegisterInfo("v9", 1), # TODO
		"v10": RegisterInfo("v10", 1), # 0xA
		"v11": RegisterInfo("v11", 1), # 0xB
		"v12": RegisterInfo("v12", 1), # 0xC
		"v13": RegisterInfo("v13", 1), # 0xD
		"v14": RegisterInfo("v14", 1), # 0xE
		"v15": RegisterInfo("v15", 1), # 0xF

		# extended:
		# see the reg loop below this list

		# TODO: are parameter registers different than local registers (v0-v5)?
		"p0": RegisterInfo("p0", 1), # TODO
		"p1": RegisterInfo("p1", 1), # TODO
		"p2": RegisterInfo("p2", 1), # TODO

		"r13": RegisterInfo("r13", 1) # stack pointer (SP), which isn't used in dalvik
		# TODO: more
	}
	for reg in ["v16","v17","v18","v19","v20","v21","v22","v23","v24","v25"]:
		regs[reg] = RegisterInfo(reg, 1)

	stack_pointer = "r13" # TODO - no stack in dalvik? - techically R13 or SP, FIXME: this shouldn't be required by binja
	flags = ["c", "z", "i", "d", "b", "v", "s"] # TODO
	flag_write_types = ["*", "czs", "zvs", "zs"] # TODO

	#def __init__(self):
		#bv.my_test2() # "bv" not defined..
		#BinaryViewType["DEX"].my_test2()
		#print dir(self) # just for debug


	def decode_instruction(self, data, addr):
		if len(data) < 1:
			return None, None, None, None
		opcode = ord(data[0])
		fn = dex_decode[opcode][3]

		#BinaryViewType["DEX"].my_test2()
		#bv.my_test2()
		# shouldn't be required?
		#if opcode >= len(InstructionNames): # was "InstructionNames"
		#	return None, None, None, None

		instr = Instruction[opcode]["name"] # was "InstructionNames[opcode]"
		if instr is None:
			return None, None, None, None

		operand = opcode # InstructionOperandTypes[opcode] # TODO - FIXME: pretty sure this will be fine..

		length = 1 + Instruction[opcode]["length"] # was OperandLengths[operand]
		#log(2, "decode_instruction - opcode: %s, operand: %s, length: %s" % (str(opcode), str(operand), str(length)))

		if len(data) < length:
			return None, None, None, None

		if Instruction[opcode]["length"] == 0: # was OperandLengths[operand]
			value = None
		#elif operand == REL:
		#	value = (addr + 2 + struct.unpack("b", data[1])[0]) & 0xffff
		elif Instruction[opcode]["length"] == 1: # was OperandLengths[operand]
			value = ord(data[1])
		else:
			value = struct.unpack("<H", data[1:3])[0]

		# len(data) == 16, why??
		#log(2, "decode_instruction, len(data): %i" % len(data))

		#print data.encode('hex')

		#value = None # for the NOP
		return instr, operand, length, value

	# first one called
	def perform_get_instruction_info(self, data, addr):
		#log(2, "perform_get_instruction_info")

		instr, operand, length, value = self.decode_instruction(data, addr)
		if instr is None:
			return None

		result = InstructionInfo()
		result.length = length

		# function return
		if instr in ["return-void", "return", "return-wide", "return-object"]:
			result.add_branch(FunctionReturn)

		# TODO: implement unconditional jumps
		#elif instr in ["goto", "goto/16", "goto/32"]:
			# how is data handled?
			#d = struct.unpack("<h", data[1:3])[0]

			# Examples:
			# 	28F0 - goto 0005 // -0010    # how do they go from 0xF0 to 5? it's signed...
			#			Jumps to current position-16 words (hex 10). 0005 is the label of the target instruction.
			#	2900 0FFE - goto/16 002f // -01f1
			#			Jumps to the current position-1F1H words. 002F is the label of the target instruction.
			#if instr == "goto/16":
				# FIXME: verify...
			#	offset = struct.unpack("<h", data[1:3])[0]# AFAIK....

			#	target_addr = addr + offset # AFAIK....

			#	result.add_branch(UnconditionalBranch, target_addr)


		# TODO: implement conditional jumps
		elif instr in ["if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le", "if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"]:
			pass

		# TODO: implement calls
		elif instr in ["invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface",
			"invoke-virtual/range", "invoke-super/range", "invoke-direct/range", "invoke-static/range", "invoke-interface-range",
			"invoke-direct-empty", "invoke-virtual-quick", "invoke-virtual-quick/range", "invoke-super-quick", "invoke-super-quick/range"]:
			# time to implement branch/jump/whatever...
			pass

		#
		# TODO: implement jumps and other oddities
		#

		return result

	def perform_get_instruction_text(self, data, addr):
		# NOTE: value is an "int"
		# FIXME: rename instr to opcode?
		instr, operand, length, value = self.decode_instruction(data, addr)
		if instr is None:
			return None

		# FIXME: data may be too short - how is data gotten?
		# FIXME: it's returning too small a chunk of "data

		#try:
		op = ord(data[0]) # is this really the op (opcode)? the first byte that indicates the "function" to be performed?

		fn = dex_decode[op][3]
		start = len(data) # I'm not sure why this isn't just passed as "dex_length"

		try:
			# FIXME: dex_object is not defined
			val = func_point[fn](self, data, start/2) # FIXME TODO: how can I pass the dex_object...
														# this "self" needs to contain: get_string_by_id, getmethodname, etc..
			results = []
			val = val[2:] # the 2nd arg we're skipping is the opcode one which my code already does

			for idx, item in enumerate(val):
				if item in RegisterNames:
					results += [InstructionTextToken(RegisterToken, item)]
				else:
					results += [InstructionTextToken(TextToken, item)]

				if idx < len(val) - 1:
					results += [InstructionTextToken(TextToken, ", ")]


			# FIXME: current crash
			#log(2, "perform_get_instruction_text is about to mess with tokens")

			tokens = []
			tokens.append(InstructionTextToken(TextToken, "%-20s " % instr)) # FIXME: error? this is "move" for example??
			tokens += results #OperandTokens[operand](value) # FIXME error: the "value" is returned from decode_instructions
			return tokens, length

		except:
			log_error(traceback.format_exc())
			log(3, "addr: %x" % addr) # are we out of bounds?
			log(3, "len(data): %i" % len(data))
			log(3, "op: %s, len: %i, data: %s" % (hex(op), len(data), data.encode("hex"))) # what is "data" type

			pass

# see NESView Example
# pretty sure this is triggered when we do the "write" call...
# https://github.com/JesusFreke/smali/wiki/Registers
class DEXView(BinaryView, dex_parser):
	name = "DEX"
	long_name = "Dalvik Executable"

	# data == BinaryView datatype
	def __init__(self, data):
		# print "DEXView::__init__"

		BinaryView.__init__(self, data.file) # FIXME: is len(data.file.raw) right?
		self.data = data # FIXME: is this what we can do DexFile() on?
		self.notification = DEXViewUpdateNotification(self)
		self.data.register_notification(self.notification)

		raw_binary_length = len(data.file.raw)
		raw_binary = data.read(0, raw_binary_length)

		# TODO: check if this works
		global dex_file
		dex_file = dex_parser(self, raw_binary) # FIXME: is there a way to avoid re-analysis if it's been cached
		self.dex = dex_file

		# BinaryViewType["DEX"].dex_obj = self.dex # does nothing
		#self.dex = dex_parser.__init__(self, self, raw_binary)

	@classmethod
	def is_valid_for_data(self, data):
		#print "DEXView::is_valid_for_data"

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
			#self.add_entry_point(Architecture['dex'].standalone_platform, self.perform_get_entry_point())

			return True
		except:
			log_error(traceback.format_exc())
			return False

	# FIXME
	#def perform_is_valid_offset(self, addr):
	#	if (addr >= 0x8000) and (addr < 0x10000):
	#			return True
	#	return False

	def perform_read(self, addr, length):
		# for now...
		return self.data.read(addr, length)

	# FIXME
	#def perform_write(self, addr, value):
	#	pass

	# FIXME
	#def perform_get_start(self):
	   #print("[perform_get_start]") # NOTE: seems to infinite loop (for both 0 or 1 return, haven't tested others)
	#   return 0

	# FIXME
	def perform_get_length(self):
		return 0x10000 # FIXME: wrong

	def perform_is_executable(self):
		return True

	def my_test(self):
		print "yay worked"

	@classmethod
	def my_test2(self):
		log(3, "yay worked")

	# FIXME
	#def perform_get_entry_point(self):
		# complicated because this is called without self really existing
		#   * not really sure what self provides...

class DEXViewBank(DEXView):
	name = "DEX"
	long_name = "Dalvik Executable"

	def __init__(self, data):
		DEXView.__init__(self, data)

DEXViewBank.register()
DEX.register()


# Architecture.register

'''
from pprint import pprint
pprint(dir(binaryninja.BinaryViewType["DEX"]))

'''
