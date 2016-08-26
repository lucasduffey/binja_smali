from binaryninja import *
from dexFile import DexFile
import struct
import traceback
import hashlib # to validate SHA1 signature
import zlib # to validate adler32 checksum
import os

DEX_MAGIC = "dex\x0a035\x00"

'''
OPCODES NEEDED
* B3
'''


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
# https://source.android.com/devices/tech/dalvik/instruction-formats.html
# http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html

# TODO: verify accuracy - http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html
# the "None" ones - are ones I didn't feel like copy-pasting
InstructionNames = [
	"nop",
	"move", "move/from16", "move/16", "move-wide", "move-wide/from16", "move-wide/16", "move-object", # 0x00
	"move-object/from16", "move-object/16", "move-result", "move-result-wide", "move-result-object", "move-exception", "return-void", "return", # 0x8
	"return-wide", "return-object",
	"const/4", "const/16", "const", "const/high16", "const-wide/16", "const-wide/32", # 0x10
	"const-wide", "const-wide/high16", "const-string", "const-string-jumbo", "const-class", "monitor-enter", "monitor-exit", "check-cast", # 0x18
	"instance-of", "array-length", "new-instance",

	"new-array", "filled-new-array", "filled-new-array-range ", "fill-array-data",  # 0x26 - verified

	"throw",

	"goto", "goto/16", "goto/32"
	"packed-switch", "sparse-switch",
	"cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double", "cmp-long",
	"if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le", "if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez",
	None, None, None, None, None, None, # unused 0x3e - 0x43
	"aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte", "aget-char", "aget-short",
	"aput", "aput-wide", "aput-object", "aput-boolean", "aput-byte", "aput-char", "aput-short",

	"iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte", "iget-char", "iget-short",
	"iput", "iput-wide", "iput-object", "iput-boolean", "iput-byte", "iput-char", "iput-short",

	"sget", "sget-wide", "sget-object", "sget-boolean", "sget-byte", "sget-char", "sget-short",
	"sput", "sput-wide", "sput-object", "sput-boolean", "sput-byte", "sput-char", "sput-short",

	"invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface",
	None, # unused 0x73
	"invoke-virtual/range", "invoke-super/range", "invoke-direct/range", "invoke-static/range", "invoke-interface/range",
	None, None, # unused 0x79 - 0x7a
	"neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double",
	"int-to-long", "int-to-float", "int-to-double",
	"long-to-int", "long-to-float", "long-to-double",
	"float-to-int", "float-to-long", "float-to-double",
	"double-to-int", "dobule-to-long", "double-to-float",
	"int-to-byte", "int-to-char", "int-to-short",

	"add-int", "sub-int", "mul-int", "div-int", "rem-int", "and-int", "or-int", "xor-int", "shl-int", "shr-int", "ushr-int",
	"add-long", "sub-long", "mul-long", "div-long", "rem-long", "and-long", "or-long", "xor-long", "shl-long", "shr-long", "ushr-long",
	"add-float", "sub-float", "mul-float", "div-float", "rem-float",
	"add-double", "sub-double", "mul-double", "div-double", "rem-double",
	"add-int/2addr", "sub-int/2addr", "mul-int/2addr", "div-int/2addr", "rem-int/2addr", "and-int/2addr", "or-int/2addr", "xor-int/2addr", "shl-int/2addr", "shr-int/2addr", "ushr-int/2addr",

	"add-long/2addr","sub-long/2addr","mul-long/2addr","div-long/2addr","rem-long/2addr","and-long/2addr","or-long/2addr","xor-long/2addr","shl-long/2addr","shr-long/2addr","ushr-long/2addr",
	"add-float/2addr", "sub-float/2addr", "mul-float/2addr", "div-float/2addr", "rem-float/2addr",
	"add-double/2addr", "sub-double/2addr", "mul-double/2addr", "div-double/2addr", "rem-double/2addr",
	"add-int/lit16", "sub-int/lit16", "mul-int/lit16", "div-int/lit16", "rem-int/lit16", "and-int/lit16", "or-int/lit16", "xor-int/lit16",
	"add-int/lit8", "sub-int/lit8", "mul-int/lit8", "div-int/lit8", "rem-int/lit8", "and-int/lit8", "or-int/lit8", "xor-int/lit8", "shl-int/lit8", "shr-int/lit8", "ushr-int/lit8",
	None,None,None,None,None,None,None,None,None,None,None,
	"execute-inline",
	None,
	"invoke-direct-empty",
	None,
	"iget-quick", "iget-wide-quick", "iget-object-quick","iput-quick", "iput-wide-quick", "iput-object-quick",
	"invoke-virtual-quick", "invoke-virtual-quick/range","invoke-super-quick", "invoke-super-quick/range",
	None,None,None,None
]

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

NONE = 0
MOVE = 1
MOVE_FROM16 = 2
MOVE_16 = 3
MOVE_WIDE = 4
MOVE_WIDE_FROM_16 = 5
MOVE_WIDE_16 = 6
MOVE_OBJECT = 7
MOVE_OBJECT_FROM_16 = 8
MOVE_OBJECT_16 = 9
MOVE_RESULT = 10
MOVE_RESULT_WIDE = 11
MOVE_RESULT_OBJECT = 12
MOVE_EXCEPTION = 13
RETURN_VOID = 14
RETURN = 15
RETURN_WIDE = 16
RETURN_OBJECT = 17
CONST_4 = 18
CONST_16 = 19
CONST = 20
CONST_HIGH16 = 21
CONST_WIDE16 = 22
CONST_WIDE32 = 23
CONST_WIDE = 0x18
CONST_WIDE_HIGH16 = 0x19
CONST_STRING = 0x1A
CONST_STRING_JUMBO = 0x1B
CONST_CLASS = 0x1C
MONITOR_ENTER = 0x1D
MONITOR_EXIT = 0x1E
CHECK_CAST = 0x1F
INSTANCE_OF = 020
ARRAY_LENGTH = 0x21
NEW_INSTANCE = 0x22
NEW_ARRAY = 0x23
FILLED_NEW_ARRAY = 0x24
FILLED_NEW_ARRAY_RANGE = 0x25
FILL_ARRAY_DATA = 0x26
THROW = 0x27
GOTO = 0x28
PACKED_SWITCH = 0x29
SPARSE_SWITCH = 0x2a
CMPL_FLOAT = 0x2b
CMPG_FLOAT = 0x2c
CMPL_DOUBLE = 0x2d
CMPG_DOUBLE = 0x2e
CMP_LONG = 0x2f
IF_EQ = 0x30
IF_NE = 0x31
IF_LT = 0x32
IF_GE = 0x33
IF_GT = 0x34
IF_LE = 0x35
IF_EQZ = 0x36
IF_NEZ = 0x37
IF_LTZ = 0x38
IF_GEZ = 0x39
IF_GTZ = 0x3a
IF_LEZ = 0x3b
UNUSED_3E = 0x3c
UNUSED_3F = 0x3d
UNUSED_40 = 0x3e
UNUSED_41 = 0x3f
UNUSED_42 = 0x40
UNUSED_43 = 0x41
AGET = 0x42
AGET_WIDE = 0x43
AGET_OBJECT = 0x44
AGET_BOOLEAN = 0x45
AGET_BYTE = 0x46
AGET_CHAR = 0x47
AGET_SHORT = 0x48
APUT = 0x49
APUT_WIDE = 0x4a
APUT_OBJECT = 0x4b
APUT_BOOLEAN = 0x4c
APUT_BYTE = 0x4d
APUT_CHAR = 0x4e
APUT_SHORT = 0x4f
IGET = 0x50
IGET_WIDE = 0x51
IGET_OBJECT = 0x52
IGET_BOOLEAN = 0x53
IGET_BYTE = 0x54
IGET_CHAR = 0x55
IGET_SHORT = 0x56
IPUT = 0x57
IPUT_WIDE = 0x58
IPUT_OBJECT = 0x59
IPUT_BOOLEAN = 0x5a
IPUT_BYTE = 0x5b
IPUT_CHAR = 0x5c
IPUT_SHORT = 0x5d
SGET = 0x5e
SGET_WIDE = 0x5f
SGET_OBJECT = 0x60
SGET_BOOLEAN = 0x61
SGET_BYTE = 0x62
SGET_CHAR = 0x63
SGET_SHORT = 0x64
SPUT = 0x65
SPUT_WIDE = 0x66
SPUT_OBJECT = 0x67
SPUT_BOOLEAN = 0x68
SPUT_BYTE = 0x69
SPUT_CHAR = 0x6a
SPUT_SHORT = 0x6b
INVOKE_VIRTUAL = 0x6c
INVOKE_SUPER = 0x6d
INVOKE_DIRECT = 0x6e
INVOKE_STATIC = 0x6f
INVOKE_INTERFACE = 0x70
UNUSED_73 = 0x71
INVOKE_VIRTUAL_RANGE = 0x72
INVOKE_SUPER_RANGE = 0x73
INVOKE_DIRECT_RANGE = 0x74
INVOKE_STATIC_RANGE = 0x75
INVOKE_INTERFACE_RANGE = 0x76
UNUSED_79 = 0x77
UNUSED_7A = 0x78
NEG_INT = 0x79
NOT_INT = 0x7a
NEG_LONG = 0x7b
NOT_LONG = 0x7c
NEG_FLOAT = 0x7d
NEG_DOUBLE = 0x7e
INT_TO_LONG = 0x7f
INT_TO_FLOAT = 0x80
INT_TO_DOUBLE = 0x81
LONG_TO_INT = 0x82
LONG_TO_FLOAT = 0x83
LONG_TO_DOUBLE = 0x84
FLOAT_TO_INT = 0x85
FLOAT_TO_LONG = 0x86
FLOAT_TO_DOUBLE = 0x87
DOUBLE_TO_INT = 0x88
DOUBLE_TO_LONG = 0x89
DOUBLE_TO_FLOAT = 0x8a
INT_TO_BYTE = 0x8b
INT_TO_CHAR = 0x8c
INT_TO_SHORT = 0x8d
ADD_INT = 0x8e
SUB_INT = 0x8f
MUL_INT = 0x90
DIV_INT = 0x91
REM_INT = 0x92
AND_INT = 0x93
OR_INT = 0x94
XOR_INT = 0x95
SHL_INT = 0x96
SHR_INT = 0x97
USHR_INT = 0x98
ADD_LONG = 0x99
SUB_LONG = 0x9a
MUL_LONG = 0x9b
DIV_LONG = 0x9c
REM_LONG = 0x9d
AND_LONG = 0x9e
OR_LONG = 0x9f
XOR_LONG = 0xa0
SHL_LONG = 0xa1
SHR_LONG = 0xa2
USHR_LONG = 0xa3
ADD_FLOAT = 0xa4
SUB_FLOAT = 0xa5
MUL_FLOAT = 0xa6
DIV_FLOAT = 0xa7
REM_FLOAT = 0xa8
ADD_DOUBLE = 0xa9
SUB_DOUBLE = 0xaa
MUL_DOUBLE = 0xab
DIV_DOUBLE = 0xac
REM_DOUBLE = 0xad
ADD_INT_2ADDR = 0xae
SUB_INT_2ADDR = 0xaf
MUL_INT_2ADDR = 0xb0
DIV_INT_2ADDR = 0xb1
REM_INT_2ADDR = 0xb2
AND_INT_2ADDR = 0xb3
OR_INT_2ADDR = 0xb4
XOR_INT_2ADDR = 0xb5
SHL_INT_2ADDR = 0xb6
SHR_INT_2ADDR = 0xb7
USHR_INT_2ADDR = 0xb8
ADD_LONG_2ADDR = 0xb9
SUB_LONG_2ADDR = 0xba
MUL_LONG_2ADDR = 0xbb
DIV_LONG_2ADDR = 0xbc
REM_LONG_2ADDR = 0xbd
AND_LONG_2ADDR = 0xbe
OR_LONG_2ADDR = 0xbf
XOR_LONG_2ADDR = 0xc0
SHL_LONG_2ADDR = 0xc1
SHR_LONG_2ADDR = 0xc2
USHR_LONG_2ADDR = 0xc3
ADD_FLOAT_2ADDR = 0xc4
SUB_FLOAT_2ADDR = 0xc5
MUL_FLOAT_2ADDR = 0xc6
DIV_FLOAT_2ADDR = 0xc7
REM_FLOAT_2ADDR = 0xc8
ADD_DOUBLE_2ADDR = 0xc9
SUB_DOUBLE_2ADDR = 0xca
MUL_DOUBLE_2ADDR = 0xcb
DIV_DOUBLE_2ADDR = 0xcc
REM_DOUBLE_2ADDR = 0xcd
ADD_INT_LIT16 = 0xce
SUB_INT_LIT16 = 0xcf
MUL_INT_LIT16 = 0xd0
DIV_INT_LIT16 = 0xd1
REM_INT_LIT16 = 0xd2
AND_INT_LIT16 = 0xd3
OR_INT_LIT16 = 0xd4
XOR_INT_LIT16 = 0xd5
ADD_INT_LIT8 = 0xd6
SUB_INT_LIT8 = 0xd7
MUL_INT_LIT8 = 0xd8
DIV_INT_LIT8 = 0xd9
REM_INT_LIT8 = 0xda
AND_INT_LIT8 = 0xdb
OR_INT_LIT8 = 0xdc
XOR_INT_LIT8 = 0xdd
SHL_INT_LIT8 = 0xde
SHR_INT_LIT8 = 0xdf
USHR_INT_LIT8 = 0xe0
UNUSED_E3 = 0xe1
UNUSED_E4 = 0xe2
UNUSED_E5 = 0xe3
UNUSED_E6 = 0xe4
UNUSED_E7 = 0xe5
UNUSED_E8 = 0xe6
UNUSED_E9 = 0xe7
UNUSED_EA = 0xe8
UNUSED_EB = 0xe9
UNUSED_EC = 0xea
UNUSED_ED = 0xeb
EXECUTE_INLINE = 0xec
UNUSED_EF = 0xed
INVOKE_DIRECT_EMPTY = 0xee
UNUSED_F1 = 0xef
IGET_QUICK = 0xf0
IGET_WIDE_QUICK = 0xf1
IGET_OBJECT_QUICK = 0xf2
IPUT_QUICK = 0xf3
IPUT_WIDE_QUICK = 0xf4
IPUT_OBJECT_QUICK = 0xf5
INVOKE_VIRTUAL_QUICK = 0xf6
INVOKE_VIRTUAL_QUICK_RANGE = 0xf7
INVOKE_SUPER_QUICK = 0xf8
INVOKE_SUPER_QUICK_RANGE = 0xf9
UNUSED_FC = 0xfa
UNUSED_FD = 0xfb
UNUSED_FE = 0xfc
UNUSED_FF = 0xfd



InstructionOperandTypes = [
	NONE, MOVE,

	# FIXME TODO
	MOVE_FROM16,
	MOVE_16,
	MOVE_WIDE,
	MOVE_WIDE_FROM_16,
	MOVE_WIDE_16,
	MOVE_OBJECT,
	MOVE_OBJECT_FROM_16,
	MOVE_OBJECT_16,
	MOVE_RESULT,
	MOVE_RESULT_WIDE,
	MOVE_RESULT_OBJECT,
	MOVE_EXCEPTION,
	RETURN_VOID,
	RETURN,
	RETURN_WIDE,
	RETURN_OBJECT,
	CONST_4,
	CONST_16,
	CONST,
	CONST_HIGH16,
	CONST_WIDE16,
	CONST_WIDE32,
	CONST_WIDE,
	CONST_WIDE_HIGH16,
	CONST_STRING,
	CONST_STRING_JUMBO,
	CONST_CLASS,
	MONITOR_ENTER,
	MONITOR_EXIT,
	CHECK_CAST,
	INSTANCE_OF,
	ARRAY_LENGTH,
	NEW_INSTANCE,
	NEW_ARRAY,
	FILLED_NEW_ARRAY,
	FILLED_NEW_ARRAY_RANGE,
	FILL_ARRAY_DATA,
	THROW,
	GOTO,

	PACKED_SWITCH,
	SPARSE_SWITCH,
	CMPL_FLOAT,
	CMPG_FLOAT,
	CMPL_DOUBLE,
	CMPG_DOUBLE,
	CMP_LONG,
	IF_EQ,
	IF_NE,
	IF_LT,
	IF_GE,
	IF_GT,
	IF_LE,
	IF_EQZ,
	IF_NEZ,
	IF_LTZ,
	IF_GEZ,
	IF_GTZ,
	IF_LEZ,
	UNUSED_3E,
	UNUSED_3F,
	UNUSED_40,
	UNUSED_41,
	UNUSED_42,
	UNUSED_43,
	AGET,
	AGET_WIDE,
	AGET_OBJECT,
	AGET_BOOLEAN,
	AGET_BYTE,
	AGET_CHAR,
	AGET_SHORT,
	APUT,
	APUT_WIDE,
	APUT_OBJECT,
	APUT_BOOLEAN,
	APUT_BYTE,
	APUT_CHAR,
	APUT_SHORT,
	IGET,
	IGET_WIDE,
	IGET_OBJECT,
	IGET_BOOLEAN,
	IGET_BYTE,
	IGET_CHAR,
	IGET_SHORT,
	IPUT,
	IPUT_WIDE,
	IPUT_OBJECT,
	IPUT_BOOLEAN,
	IPUT_BYTE,
	IPUT_CHAR,
	IPUT_SHORT,
	SGET,
	SGET_WIDE,
	SGET_OBJECT,
	SGET_BOOLEAN,
	SGET_BYTE,
	SGET_CHAR,
	SGET_SHORT,
	SPUT,
	SPUT_WIDE,
	SPUT_OBJECT,
	SPUT_BOOLEAN,
	SPUT_BYTE,
	SPUT_CHAR,
	SPUT_SHORT,
	INVOKE_VIRTUAL,
	INVOKE_SUPER,
	INVOKE_DIRECT,
	INVOKE_STATIC,
	INVOKE_INTERFACE,
	UNUSED_73,
	INVOKE_VIRTUAL_RANGE,
	INVOKE_SUPER_RANGE,
	INVOKE_DIRECT_RANGE,
	INVOKE_STATIC_RANGE,
	INVOKE_INTERFACE_RANGE,
	UNUSED_79,
	UNUSED_7A,
	NEG_INT,
	NOT_INT,
	NEG_LONG,
	NOT_LONG,
	NEG_FLOAT,
	NEG_DOUBLE,
	INT_TO_LONG,
	INT_TO_FLOAT,
	INT_TO_DOUBLE,
	LONG_TO_INT,
	LONG_TO_FLOAT,
	LONG_TO_DOUBLE,
	FLOAT_TO_INT,
	FLOAT_TO_LONG,
	FLOAT_TO_DOUBLE,
	DOUBLE_TO_INT,
	DOUBLE_TO_LONG,
	DOUBLE_TO_FLOAT,
	INT_TO_BYTE,
	INT_TO_CHAR,
	INT_TO_SHORT,
	ADD_INT,
	SUB_INT,
	MUL_INT,
	DIV_INT,
	REM_INT,
	AND_INT,
	OR_INT,
	XOR_INT,
	SHL_INT,
	SHR_INT,
	USHR_INT,
	ADD_LONG,
	SUB_LONG,
	MUL_LONG,
	DIV_LONG,
	REM_LONG,
	AND_LONG,
	OR_LONG,
	XOR_LONG,
	SHL_LONG,
	SHR_LONG,
	USHR_LONG,
	ADD_FLOAT,
	SUB_FLOAT,
	MUL_FLOAT,
	DIV_FLOAT,
	REM_FLOAT,
	ADD_DOUBLE,
	SUB_DOUBLE,
	MUL_DOUBLE,
	DIV_DOUBLE,
	REM_DOUBLE,
	ADD_INT_2ADDR,
	SUB_INT_2ADDR,
	MUL_INT_2ADDR,
	DIV_INT_2ADDR,
	REM_INT_2ADDR,
	AND_INT_2ADDR,
	OR_INT_2ADDR,
	XOR_INT_2ADDR,
	SHL_INT_2ADDR,
	SHR_INT_2ADDR,
	USHR_INT_2ADDR,
	ADD_LONG_2ADDR,
	SUB_LONG_2ADDR,
	MUL_LONG_2ADDR,
	DIV_LONG_2ADDR,
	REM_LONG_2ADDR,
	AND_LONG_2ADDR,
	OR_LONG_2ADDR,
	XOR_LONG_2ADDR,
	SHL_LONG_2ADDR,
	SHR_LONG_2ADDR,
	USHR_LONG_2ADDR,
	ADD_FLOAT_2ADDR,
	SUB_FLOAT_2ADDR,
	MUL_FLOAT_2ADDR,
	DIV_FLOAT_2ADDR,
	REM_FLOAT_2ADDR,
	ADD_DOUBLE_2ADDR,
	SUB_DOUBLE_2ADDR,
	MUL_DOUBLE_2ADDR,
	DIV_DOUBLE_2ADDR,
	REM_DOUBLE_2ADDR,
	ADD_INT_LIT16,
	SUB_INT_LIT16,
	MUL_INT_LIT16,
	DIV_INT_LIT16,
	REM_INT_LIT16,
	AND_INT_LIT16,
	OR_INT_LIT16,
	XOR_INT_LIT16,
	ADD_INT_LIT8,
	SUB_INT_LIT8,
	MUL_INT_LIT8,
	DIV_INT_LIT8,
	REM_INT_LIT8,
	AND_INT_LIT8,
	OR_INT_LIT8,
	XOR_INT_LIT8,
	SHL_INT_LIT8,
	SHR_INT_LIT8,
	USHR_INT_LIT8,
	UNUSED_E3,
	UNUSED_E4,
	UNUSED_E5,
	UNUSED_E6,
	UNUSED_E7,
	UNUSED_E8,
	UNUSED_E9,
	UNUSED_EA,
	UNUSED_EB,
	UNUSED_EC,
	UNUSED_ED,
	EXECUTE_INLINE,
	UNUSED_EF,
	INVOKE_DIRECT_EMPTY,
	UNUSED_F1,
	IGET_QUICK,
	IGET_WIDE_QUICK,
	IGET_OBJECT_QUICK,
	IPUT_QUICK,
	IPUT_WIDE_QUICK,
	IPUT_OBJECT_QUICK,
	INVOKE_VIRTUAL_QUICK,
	INVOKE_VIRTUAL_QUICK_RANGE,
	INVOKE_SUPER_QUICK,
	INVOKE_SUPER_QUICK_RANGE,
	UNUSED_FC,
	UNUSED_FD,
	UNUSED_FE,
	UNUSED_FF,

	# FIXME TODO
	NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE,
]

OperandLengths = [
	0, # NONE - nop is either '00' or '0000' - not 100% certain
	1, # MOVE - TODO: validate/verify

	# TODO - verify
	2, # MOVE_FROM16
	2, # MOVE_16
	2, # MOVE_WIDE
	2, # MOVE_WIDE_FROM_16
	2, # MOVE_WIDE_16
	1, # MOVE_OBJECT
	2, # MOVE_OBJECT_FROM_16
	2, # MOVE_OBJECT_16
	1, # MOVE_RESULT
	1, # MOVE_RESULT_WIDE
	1, # MOVE_RESULT_OBJECT
	1, # MOVE_EXCEPTION
	1, # RETURN_VOID
	1, # RETURN
	1, # RETURN_WIDE
	1, # RETURN_OBJECT
	1, # CONST_4
	3, # CONST_16 - pretty sure
	3, # CONST
	2, # CONST_HIGH16
	2, # CONST_WIDE16
	5, # CONST_WIDE32,
	7, # CONST_WIDE,
	3, # CONST_WIDE_HIGH16,
	3, # CONST_STRING,
	3, # CONST_STRING_JUMBO,
	3, # CONST_CLASS,
	1, # MONITOR_ENTER,
	1, # MONITOR_EXIT,
	3, # CHECK_CAST,
	3, # INSTANCE_OF,
	1, # ARRAY_LENGTH,
	3, # NEW_INSTANCE,
	3, # NEW_ARRAY,
	5, # FILLED_NEW_ARRAY,
	5, # FILLED_NEW_ARRAY_RANGE
	5, # FILLED_ARRAY_DATA
	1, # THROW
	1, # GOTO

	5, # PACKED_SWITCH
	5, # SPARSE_SWITCH
	3, # CMPL_FLOAT
	3, # CMPG_FLOAT
	3, # CMPL_DOUBLE
	3, # CMPG_DOUBLE
	3, # CMP_LONG
	3, # IF_EQ
	3, # IF_NE
	3, # IF_LT
	3, # IF_GE
	3, # IF_GT
	3, # IF_LE
	3, # IF_EQZ
	3, # IF_NEZ
	3, # IF_LTZ
	3, # IF_GEZ
	3, # IF_GTZ
	3, # IF_LEZ

	0, # UNUSED_3E
	0, # UNUSED_3F
	0, # UNUSED_40
	0, # UNUSED_41
	0, # UNUSED_42
	0, # UNUSED_43

	3, # AGET
	3, # AGET_WIDE
	3, # AGET_OBJECT
	3, # AGET_BOOLEAN
	3, # AGET_BYTE
	3, # AGET_CHAR
	3, # AGET_SHORT
	3, # APUT
	3, # APUT_WIDE
	3, # APUT_OBJECT
	3, # APUT_BOOLEAN
	3, # APUT_BYTE
	3, # APUT_CHAR
	3, # APUT_SHORT

	3, # IGET - FIXME - correct??
	3, # IGET_WIDE
	3, # IGET_OBJECT
	3, # IGET_BOOLEAN
	3, # IGET_BYTE
	3, # IGET_CHAR
	3, # IGET_SHORT
	3, # IPUT
	3, # IPUT_WIDE
	3, # IPUT_OBJECT
	3, # IPUT_BOOLEAN
	3, # IPUT_BYTE
	3, # IPUT_CHAR
	3, # IPUT_SHORT
	3, # SGET
	3, # SGET_WIDE
	3, # SGET_OBJECT
	3, # SGET_BOOLEAN
	3, # SGET_BYTE
	3, # SGET_CHAR
	3, # SGET_SHORT
	3, # SPUT
	3, # SPUT_WIDE
	3, # SPUT_OBJECT
	3, # SPUT_BOOLEAN
	3, # SPUT_BYTE
	3, # SPUT_CHAR
	3, # SPUT_SHORT

	# TODO
	5, # INVOKE_VIRTUAL
	5, # INVOKE_SUPER
	5, # INVOKE_DIRECT
	5, # INVOKE_STATIC
	5, # INVOKE_INTERFACE

	0, # UNUSED_73

	5, # INVOKE_VIRTUAL_RANGE
	5, # INVOKE_SUPER_RANGE
	5, # INVOKE_DIRECT_RANGE
	5, # INVOKE_STATIC_RANGE
	5, # INVOKE_INTERFACE_RANGE

	0, # UNUSED_79
	0, # UNUSED_7A

	1, # NEG_INT
	1, # NOT_INT
	1, # NEG_LONG
	1, # NOT_LONG
	1, # NEG_FLOAT
	1, # NEG_DOUBLE
	1, # INT_TO_LONG
	1, # INT_TO_FLOAT
	1, # INT_TO_DOUBLE
	1, # LONG_TO_INT
	1, # LONG_TO_FLOAT
	1, # LONG_TO_DOUBLE
	1, # FLOAT_TO_INT
	1, # FLOAT_TO_LONG
	1, # FLOAT_TO_DOUBLE
	1, # DOUBLE_TO_INT
	1, # DOUBLE_TO_LONG
	1, # DOUBLE_TO_FLOAT
	1, # INT_TO_BYTE
	1, # INT_TO_CHAR
	1, # INT_TO_SHORT

	3, # ADD_INT
	3, # SUB_INT
	3, # MUL_INT
	3, # DIV_INT
	3, # REM_INT
	3, # AND_INT
	3, # OR_INT
	3, # XOR_INT
	3, # SHL_INT
	3, # SHR_INT
	3, # USHR_INT
	3, # ADD_LONG
	3, # SUB_LONG
	3, # MUL_LONG
	3, # DIV_LONG
	3, # REM_LONG
	3, # AND_LONG
	3, # OR_LONG
	3, # XOR_LONG
	3, # SHL_LONG
	3, # SHR_LONG
	3, # USHR_LONG
	3, # ADD_FLOAT
	3, # SUB_FLOAT
	3, # MUL_FLOAT
	3, # DIV_FLOAT
	3, # REM_FLOAT
	3, # ADD_DOUBLE
	3, # SUB_DOUBLE
	3, # MUL_DOUBLE
	3, # DIV_DOUBLE
	3, # REM_DOUBLE

	1, # ADD_INT_2ADDR
	1, # SUB_INT_2ADDR
	1, # MUL_INT_2ADDR
	1, # DIV_INT_2ADDR
	1, # REM_INT_2ADDR
	1, # AND_INT_2ADDR
	1, # OR_INT_2ADDR
	1, # XOR_INT_2ADDR
	1, # SHL_INT_2ADDR
	1, # SHR_INT_2ADDR
	1, # USHR_INT_2ADDR
	1, # ADD_LONG_2ADDR
	1, # SUB_LONG_2ADDR
	1, # MUL_LONG_2ADDR
	1, # DIV_LONG_2ADDR
	1, # REM_LONG_2ADDR
	1, # AND_LONG_2ADDR
	1, # OR_LONG_2ADDR
	1, # XOR_LONG_2ADDR
	1, # SHL_LONG_2ADDR
	1, # SHR_LONG_2ADDR
	1, # USHR_LONG_2ADDR
	1, # ADD_FLOAT_2ADDR
	1, # SUB_FLOAT_2ADDR
	1, # MUL_FLOAT_2ADDR
	1, # DIV_FLOAT_2ADDR
	1, # REM_FLOAT_2ADDR
	1, # ADD_DOUBLE_2ADDR
	1, # SUB_DOUBLE_2ADDR
	1, # MUL_DOUBLE_2ADDR
	1, # DIV_DOUBLE_2ADDR
	1, # REM_DOUBLE_2ADDR

	3, # ADD_INT_LIT16
	3, # SUB_INT_LIT16
	3, # MUL_INT_LIT16
	3, # DIV_INT_LIT16
	3, # REM_INT_LIT16
	3, # AND_INT_LIT16
	3, # OR_INT_LIT16
	3, # XOR_INT_LIT16
	3, # ADD_INT_LIT8
	3, # SUB_INT_LIT8
	3, # MUL_INT_LIT8
	3, # DIV_INT_LIT8
	3, # REM_INT_LIT8
	3, # AND_INT_LIT8
	3, # OR_INT_LIT8
	3, # XOR_INT_LIT8
	3, # SHL_INT_LIT8
	3, # SHR_INT_LIT8
	3, # USHR_INT_LIT8

	0, # UNUSED_E3
	0, # UNUSED_E4
	0, # UNUSED_E5
	0, # UNUSED_E6
	0, # UNUSED_E7
	0, # UNUSED_E8
	0, # UNUSED_E9
	0, # UNUSED_EA
	0, # UNUSED_EB
	0, # UNUSED_EC
	0, # UNUSED_ED

	5, # EXECUTE_INLINE
	0, # UNUSED_EF
	5, # INVOKE_DIRECT_EMPTY
	0, # UNUSED_F1

	3, # IGET_QUICK
	3, # IGET_WIDE_QUICK
	3, # IGET_OBJECT_QUICK
	3, # IPUT_QUICK
	3, # IPUT_WIDE_QUICK
	3, # IPUT_OBJECT_QUICK

	5, # INVOKE_VIRTUAL_QUICK
	5, # INVOKE_VIRTUAL_QUICK_RANGE
	5, # INVOKE_SUPER_QUICK
	5, # INVOKE_SUPER_QUICK_RANGE

	0, # UNUSED_FC
	0, # UNUSED_FD
	0, # UNUSED_FE
	0 # UNUSED_FF
]

# used for perform_get_instruction_text
OperandTokens = [
	lambda value: [], # NONE
	lambda value: [InstructionTextToken(RegisterToken, RegisterNames[value & 0xF]),
		InstructionTextToken(TextToken, ", "),
		InstructionTextToken(RegisterToken, RegisterNames[value >> 4])], # MOVE

	# MOVE_FROM16,
	lambda value: [], # TODO: actually implement....

	# MOVE_16
	lambda value: [InstructionTextToken(RegisterToken, RegisterNames[value & 0xFF]), # maybe?  - FAIL: (value >> 8), (value >> 16)
		InstructionTextToken(TextToken, ", "),
		InstructionTextToken(RegisterToken, RegisterNames[value >> 8])],

	# MOVE_WIDE
	lambda value: [], # NONE

	# MOVE_WIDE_FROM_16
	lambda value: [], # NONE

	# MOVE_WIDE_16
	lambda value: [], # NONE

	# MOVE_OBJECT
	lambda value: [], # NONE

	# MOVE_OBJECT_FROM_16
	lambda value: [], # NONE

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

	# CONST_16
	lambda value: [], # NONE

	# CONST
	lambda value: [], # NONE

	# CONST_HIGH16
	lambda value: [], # NONE

	# CONST_WIDE16
	lambda value: [], # NONE

	# CONST_WIDE32
	lambda value: [], # NONE

	# CONST_WIDE
	lambda value: [], # NONE

	# CONST_WIDE_HIGH16
	lambda value: [], # NONE

	# CONST_STRING
	lambda value: [], # NONE

	# CONST_STRING_JUMBO
	lambda value: [], # NONE

	# CONST_CLASS
	lambda value: [], # NONE

	# MONITOR_ENTER
	lambda value: [], # NONE

	# MONITOR_EXIT
	lambda value: [], # NONE

	# CHECK_CAST
	lambda value: [], # NONE

	# INSTANCE_OF
	lambda value: [], # NONE

	# ARRAY_LENGTH
	lambda value: [], # NONE

	# NEW_INSTANCE
	lambda value: [], # NONE

	# NEW_ARRAY
	lambda value: [], # NONE

	# FILLED_NEW_ARRAY
	lambda value: [], # NONE

	# FILLED_NEW_ARRAY_RANGE
	lambda value: [], # NONE

	# FILLED_ARRAY_DATA
	lambda value: [], # NONE

	# THROW
	lambda value: [], # NONE

	# GOTO
	lambda value: [] # NONE
]
# hack to make it work for now
#for i in range(0x28, 0xFF):
#	OperandTokens[i] = []

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

	def decode_instruction(self, data, addr):
		if len(data) < 1:
			return None, None, None, None
		opcode = ord(data[0])

		# temp hack - will be elimated when I fully populate InstructionNames list
		if opcode >= len(InstructionNames):
			return None, None, None, None

		instr = InstructionNames[opcode]
		if instr is None:
			return None, None, None, None

		operand = InstructionOperandTypes[opcode] # TODO

		length = 1 + OperandLengths[operand] # TODO
		#log(2, "decode_instruction - opcode: %s, operand: %s, length: %s" % (str(opcode), str(operand), str(length)))

		if len(data) < length:
			return None, None, None, None

		if OperandLengths[operand] == 0:
			value = None
		#elif operand == REL:
		#	value = (addr + 2 + struct.unpack("b", data[1])[0]) & 0xffff
		elif OperandLengths[operand] == 1:
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

		#
		# TODO: implement jumps and other oddities
		#

		return result

	def perform_get_instruction_text(self, data, addr):
		instr, operand, length, value = self.decode_instruction(data, addr)
		if instr is None:
			return None

		# I don't think we control "InstructionTextToken"


		if operand == 3:
			print "value: ", value # it's the bytes
			print "type(value): ", type(value) # type "int"

			print "================"
			print "value >> 2: ", (value >> 2)
			print "value >> 4: ", (value >> 4)
			print "value >> 6: ", (value >> 6)
			print "value >> 8: ", (value >> 8) # pretty sure this is supposed to be first one..
			print "================"


		# FIXME: current crash
		#log(2, "perform_get_instruction_text is about to mess with tokens")
		tokens = []
		tokens.append(InstructionTextToken(TextToken, "%-7s " % instr.replace("@", ""))) # FIXME: error? this is "move" for example??
		tokens += OperandTokens[operand](value) # FIXME error: the "value" is returned from decode_instructions

		return tokens, length


		#print "================"
		#print "tokens: ", tokens
		#print "================"

		#log(2, "perform_get_instruction_text finished messing with tokens")



# see NESView Example
# pretty sure this is triggered when we do the "write" call...
# https://github.com/JesusFreke/smali/wiki/Registers
class DEXView(BinaryView):
	name = "DEX"
	long_name = "Dalvik Executable"

	# data == BinaryView datatype
	def __init__(self, data):
		print "DEXView::__init__"
		BinaryView.__init__(self, data.file) # FIXME: is len(data.file.raw) right?

		self.data = data # FIXME: is this what we can do DexFile() on?

		raw_binary_length = len(data.file.raw)
		raw_binary = data.read(0, raw_binary_length)

		self.dex_file = DexFile(raw_binary, raw_binary_length) # how do I make sure this has access to BinaryView... (to read from it)

		self.notification = DEXViewUpdateNotification(self) # TODO
		self.data.register_notification(self.notification)

		self.dex_file.print_metadata() # for some reason this is getting regisered with "raw" view??

		# self.map_list() - either I coded wrong, or not all apks support map_list...

		# map_off

		method_list = self.dex_file.method_ids() # this will be used to get the method names :) TODO # FIXME: method_list also provides class_idx, proto_idx
		string_list = self.dex_file.string_ids() # FIXME: cache the results

		# map_list - is literally the best way to do stuff...
		# self.dex_file.map_list() # it's called in dex_file init routine
		#print self.dex_file.strings # WORKING YAY


		for code_item in self.dex_file.codes:
			data.create_user_function(Architecture['dex'].standalone_platform, code_item["insns_off"])

		# TODO: method_idx_diff

		#log(2, "found string: " + string)


		# FIXME: it's not populating the functions...
		# FIXME: TODO - might be easier to get all the code from the mapping...
		log(3, "self.dex_file.class_defs() count: %i" % len(self.dex_file.class_defs())) # 123 for the example

		for class_def in self.dex_file.class_defs():  # this line seems ok - I read class_defs source as well
			#log(2, "class_def instance")

			assert type(class_def["class_data_off"]) == int

			#print "len(raw_binary): ", len(raw_binary) # seems good
			#print "class_de["class_data_off"]: ", class_def["class_data_off"]

			# FIXME: class_def["class_data_off"] is clearly wrong
			assert class_def["class_data_off"] < raw_binary_length

			'''
			class_data_item_obj = self.dex_file.class_data_item(raw_binary, raw_binary_length, class_def["class_data_off"]) # this line seems correct, TODO: check the actual "class_data_item" function

			# create function for each direct_method
			for direct_method in class_data_item_obj.direct_methods():
				assert direct_method["code_off"] < raw_binary_length

				#log(2, "direct_method instance")
				#print "direct_method code_off: ", direct_method["code_off"]
				#print "direct_method raw_binary_length: ", raw_binary_length

				# FIXME: code_off is offset to code_item struct, not dex
				code_item_list = class_data_item_obj.code_item(direct_method["code_off"])
				method_idx_diff = direct_method["method_idx_diff"]
				string_idx = method_list[method_idx_diff]["name_idx"]

				#print "len(string_list): ", len(string_list), " method_idx_diff: ", method_idx_diff
				method_name = string_list[string_idx] # FIXME: this is index to "method_ids"


				# direct_method.code_off - there's no way to pass "insns_size" to binja???
				data.create_user_function(Architecture['dex'].standalone_platform, code_item_list["insns_off"]) # FIXME: failing

				fn = data.get_function_at(Architecture['dex'].standalone_platform, code_item_list["insns_off"])
				#log(3, str(method_name))
				fn.name = method_name

				# FIXME: method_list also provides class_idx, proto_idx

			# create function for each virtual_method
			for virtual_method in class_data_item_obj.virtual_methods():
				print "virtual_method code_off:", virtual_method["code_off"]

				# FIXME: code_off is offset to code_item struct, not dex
				code_item_list = class_data_item_obj.code_item(virtual_method["code_off"])
				method_idx_diff = virtual_method["method_idx_diff"] # FIXME: this is index to "method_ids"
				string_idx = method_list[method_idx_diff]["name_idx"]

				#print "len(string_list): ", len(string_list), " method_idx_diff: ", method_idx_diff
				method_name = string_list[string_idx]

				# virtual_method.code_off - there's no way to pass "insns_size" to binja???
				data.create_user_function(Architecture['dex'].standalone_platform, code_item_list["insns_off"]) # FIXME: failing


				fn = data.get_function_at(Architecture['dex'].standalone_platform, code_item_list["insns_off"])
				#log(3, str(method_name))
				fn.name = method_name

				# FIXME: method_list also provides class_idx, proto_idx
			'''
			#print "" # for debugging only, improve readability


		# this might be a better way to do it. Just create functions
		#data.create_user_function(Architecture['dex'].standalone_platform, 0) # FAILURE TO CREATE VIEW..

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
	#def perform_write(self, addr, value):
	#	pass

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
		# complicated because this is called without self really existing
		#   * not really sure what self provides...

		#self.data = data # FIXME: is this what we can do DexFile() on?

		# FOLLOWING CODE DOENS'T WORK..
		#binary_blob_length = len(self.data.raw)
		#binary_blob = self.data.file.read(0, binary_blob_length)
		#tmp = DexFile(binary_blob, binary_blob_length) # how do I make sure this has access to BinaryView... (to read from it)

		#dataOff = tmp.dataOff()
		#fileSize = len(self.data.file.raw) # TODO: is this checking size of APK, or size of dex...

		#print "dexView::perform_get_entry_point: ", dataOff, "hex(dataOff): ", hex(dataOff), ", file size: ", fileSize

		#assert dataOff <= fileSize

		#return dataOff

		# return 0 for now, since perform_get_entry_point gets called before __init__ it overcomplicates some stuff...
		return int(0) # for some reason I frequently get "0x0 isn't valid entry point"..

print("dexView - for real")
print("test against classes2.dex - because there is actually dex code..")
class DEXViewBank(DEXView):
	name = "DEX"
	long_name = "Dalvik Executable"

	def __init__(self, data):
		DEXView.__init__(self, data)

DEXViewBank.register()
DEX.register()


# Architecture.register
