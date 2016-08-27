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
MOVE_RESULT = 0xA
MOVE_RESULT_WIDE = 0xB
MOVE_RESULT_OBJECT = 0xC
MOVE_EXCEPTION = 0xD
RETURN_VOID = 0xE
RETURN = 0xF
RETURN_WIDE = 0x10
RETURN_OBJECT = 0x11
CONST_4 = 0x12
CONST_16 = 0x13
CONST = 0x14
CONST_HIGH16 = 0x15 # verified
CONST_WIDE16 = 0x16
CONST_WIDE32 = 0x17
CONST_WIDE = 0x18
CONST_WIDE_HIGH16 = 0x19
CONST_STRING = 0x1A # verified
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
THROW = 0x27 # verified
GOTO = 0x28
GOTO_16 = 0x29
GOTO_32 = 0x2A
PACKED_SWITCH = 0x2B
SPARSE_SWITCH = 0x2C
CMPL_FLOAT = 0x2D
CMPG_FLOAT = 0x2E
CMPL_DOUBLE = 0x2F
CMPG_DOUBLE = 0x30
CMP_LONG = 0x31
IF_EQ = 0x32 # verified
IF_NE = 0x33
IF_LT = 0x34
IF_GE = 0x35
IF_GT = 0x36
IF_LE = 0x37
IF_EQZ = 0x38
IF_NEZ = 0x39
IF_LTZ = 0x3A
IF_GEZ = 0x3B
IF_GTZ = 0x3C
IF_LEZ = 0x3D
UNUSED_3E = 0x3E
UNUSED_3F = 0x3F
UNUSED_40 = 0x40
UNUSED_41 = 0x41
UNUSED_42 = 0x42
UNUSED_43 = 0x43
AGET = 0x44 # verified
AGET_WIDE = 0x45
AGET_OBJECT = 0x46
AGET_BOOLEAN = 0x47
AGET_BYTE = 0x48
AGET_CHAR = 0x49
AGET_SHORT = 0x4A
APUT = 0x4B # verified
APUT_WIDE = 0x4C
APUT_OBJECT = 0x4D
APUT_BOOLEAN = 0x4E
APUT_BYTE = 0x4F
APUT_CHAR = 0x50
APUT_SHORT = 0x51
IGET = 0x52 # verified
IGET_WIDE = 0x53
IGET_OBJECT = 0x54
IGET_BOOLEAN = 0x55
IGET_BYTE = 0x56
IGET_CHAR = 0x57
IGET_SHORT = 0x58
IPUT = 0x59 # verified
IPUT_WIDE = 0x5A
IPUT_OBJECT = 0x5B
IPUT_BOOLEAN = 0x5C
IPUT_BYTE = 0x5D
IPUT_CHAR = 0x5E
IPUT_SHORT = 0x5F
SGET = 0x60 # verified
SGET_WIDE = 0x5f
SGET_OBJECT = 0x60
SGET_BOOLEAN = 0x61
SGET_BYTE = 0x62
SGET_CHAR = 0x63
SGET_SHORT = 0x64
SPUT = 0x66 # verified
SPUT_WIDE = 0x68 # verified
SPUT_OBJECT = 0x69 # verified
SPUT_BOOLEAN = 0x6A # verified
SPUT_BYTE = 0x6B
SPUT_CHAR = 0x6C
SPUT_SHORT = 0x6D
INVOKE_VIRTUAL = 0x6E
INVOKE_SUPER = 0x6F
INVOKE_DIRECT = 0x70
INVOKE_STATIC = 0x71
INVOKE_INTERFACE = 0x72
UNUSED_73 = 0x73
INVOKE_VIRTUAL_RANGE = 0x74
INVOKE_SUPER_RANGE = 0x75
INVOKE_DIRECT_RANGE = 0x76
INVOKE_STATIC_RANGE = 0x77
INVOKE_INTERFACE_RANGE = 0x78
UNUSED_79 = 0x79
UNUSED_7A = 0x7A
NEG_INT = 0x7B
NOT_INT = 0x7C
NEG_LONG = 0x7D
NOT_LONG = 0x7E
NEG_FLOAT = 0x7F
NEG_DOUBLE = 0x80
INT_TO_LONG = 0x81
INT_TO_FLOAT = 0x82
INT_TO_DOUBLE = 0x83
LONG_TO_INT = 0x84
LONG_TO_FLOAT = 0x85
LONG_TO_DOUBLE = 0x86
FLOAT_TO_INT = 0x87
FLOAT_TO_LONG = 0x88
FLOAT_TO_DOUBLE = 0x89
DOUBLE_TO_INT = 0x8A
DOUBLE_TO_LONG = 0x8B
DOUBLE_TO_FLOAT = 0x8C
INT_TO_BYTE = 0x8D
INT_TO_CHAR = 0x8E
INT_TO_SHORT = 0x8F
ADD_INT = 0x90
SUB_INT = 0x91
MUL_INT = 0x92
DIV_INT = 0x93
REM_INT = 0x94
AND_INT = 0x95
OR_INT = 0x96
XOR_INT = 0x97
SHL_INT = 0x98
SHR_INT = 0x99
USHR_INT = 0x9A
ADD_LONG = 0x9B
SUB_LONG = 0x9C
MUL_LONG = 0x9D
DIV_LONG = 0x9E
REM_LONG = 0x9F # verified
AND_LONG = 0xA0
OR_LONG = 0xA1
XOR_LONG = 0xA2
SHL_LONG = 0xa3
SHR_LONG = 0xa4
USHR_LONG = 0xa5
ADD_FLOAT = 0xa6
SUB_FLOAT = 0xa7
MUL_FLOAT = 0xa8
DIV_FLOAT = 0xa9
REM_FLOAT = 0xAA # verified
ADD_DOUBLE = 0xaB
SUB_DOUBLE = 0xaC
MUL_DOUBLE = 0xaD
DIV_DOUBLE = 0xaE
REM_DOUBLE = 0xaF
ADD_INT_2ADDR = 0xB0 # verified
SUB_INT_2ADDR = 0xB1
MUL_INT_2ADDR = 0xb2
DIV_INT_2ADDR = 0xb3
REM_INT_2ADDR = 0xb4
AND_INT_2ADDR = 0xb5
OR_INT_2ADDR = 0xb6
XOR_INT_2ADDR = 0xb7
SHL_INT_2ADDR = 0xb8
SHR_INT_2ADDR = 0xb9
USHR_INT_2ADDR = 0xbA
ADD_LONG_2ADDR = 0xbB
SUB_LONG_2ADDR = 0xbC
MUL_LONG_2ADDR = 0xbD
DIV_LONG_2ADDR = 0xbE
REM_LONG_2ADDR = 0xbF
AND_LONG_2ADDR = 0xC0
OR_LONG_2ADDR = 0xC1
XOR_LONG_2ADDR = 0xc2
SHL_LONG_2ADDR = 0xc3
SHR_LONG_2ADDR = 0xc4
USHR_LONG_2ADDR = 0xc5
ADD_FLOAT_2ADDR = 0xc6
SUB_FLOAT_2ADDR = 0xc7
MUL_FLOAT_2ADDR = 0xc8
DIV_FLOAT_2ADDR = 0xc9
REM_FLOAT_2ADDR = 0xcA
ADD_DOUBLE_2ADDR = 0xcB
SUB_DOUBLE_2ADDR = 0xcC
MUL_DOUBLE_2ADDR = 0xcD
DIV_DOUBLE_2ADDR = 0xcE
REM_DOUBLE_2ADDR = 0xcF
ADD_INT_LIT16 = 0xD0
SUB_INT_LIT16 = 0xD1
MUL_INT_LIT16 = 0xd2
DIV_INT_LIT16 = 0xd3
REM_INT_LIT16 = 0xd4
AND_INT_LIT16 = 0xd5
OR_INT_LIT16 = 0xd6
XOR_INT_LIT16 = 0xd7
ADD_INT_LIT8 = 0xd8
SUB_INT_LIT8 = 0xd9
MUL_INT_LIT8 = 0xdA
DIV_INT_LIT8 = 0xdB
REM_INT_LIT8 = 0xdC
AND_INT_LIT8 = 0xdD
OR_INT_LIT8 = 0xdE
XOR_INT_LIT8 = 0xdF
SHL_INT_LIT8 = 0xE0 # verified
SHR_INT_LIT8 = 0xE1
USHR_INT_LIT8 = 0xe2
UNUSED_E3 = 0xe3
UNUSED_E4 = 0xe4
UNUSED_E5 = 0xe5
UNUSED_E6 = 0xe6
UNUSED_E7 = 0xe7
UNUSED_E8 = 0xe8
UNUSED_E9 = 0xe9
UNUSED_EA = 0xEA
UNUSED_EB = 0xEB
UNUSED_EC = 0xEC
UNUSED_ED = 0xED
EXECUTE_INLINE = 0xEE
UNUSED_EF = 0xEF
INVOKE_DIRECT_EMPTY = 0xF0
UNUSED_F1 = 0xF1
IGET_QUICK = 0xf2
IGET_WIDE_QUICK = 0xf3
IGET_OBJECT_QUICK = 0xf4
IPUT_QUICK = 0xf5
IPUT_WIDE_QUICK = 0xf6
IPUT_OBJECT_QUICK = 0xf7
INVOKE_VIRTUAL_QUICK = 0xf8
INVOKE_VIRTUAL_QUICK_RANGE = 0xf9
INVOKE_SUPER_QUICK = 0xFA # verified
INVOKE_SUPER_QUICK_RANGE = 0xFB
UNUSED_FC = 0xFC
UNUSED_FD = 0xFD
UNUSED_FE = 0xFE
UNUSED_FF = 0xFF



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
	3, # GOTO_16
	3, # GOTO_32

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
	lambda value: [], # NOP
	lambda value: [InstructionTextToken(RegisterToken, RegisterNames[value & 0xF]),
		InstructionTextToken(TextToken, ", "),
		InstructionTextToken(RegisterToken, RegisterNames[value >> 4])], # MOVE

	lambda value: [], # TODO: implement MOVE_FROM16

	# MOVE_16
	lambda value: [InstructionTextToken(RegisterToken, RegisterNames[value & 0xFF]), # maybe?  - FAIL: (value >> 8), (value >> 16)
		InstructionTextToken(TextToken, ", "),
		InstructionTextToken(RegisterToken, RegisterNames[value >> 8])], # TODO: implement

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
	lambda value: [InstructionTextToken(RegisterToken, RegisterNames[value & 0xFF]), # maybe?  - FAIL: (value >> 8), (value >> 16)
		InstructionTextToken(TextToken, ", "),
		InstructionTextToken(PossibleAddressToken, "%i" % (value >> 8), value)], # 16 bit constant

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
	# https://source.android.com/devices/tech/dalvik/dex-format.html # look at Value formats
	lambda value: [InstructionTextToken(RegisterToken, RegisterNames[(value >> 16) & 0xF]),
		InstructionTextToken(TextToken, ", "),
		InstructionTextToken(RegisterToken, RegisterNames[value >> 20]),
		InstructionTextToken(TextToken, ", "),
		InstructionTextToken(TextToken, "undefined") # https://source.android.com/devices/tech/dalvik/dex-format.html # look at Value formats, AFAIK this is relevant
														# example "0x19", this may be pulling it from the "field_ids" section
		],

	# FILLED_NEW_ARRAY
	lambda value: [], # NONE

	# FILLED_NEW_ARRAY_RANGE
	lambda value: [], # NONE

	# FILLED_ARRAY_DATA
	lambda value: [], # NONE

	# THROW
	lambda value: [], # NONE

	# GOTO
	lambda value: [], # NONE

	lambda value: [], # PACKED_SWITCH
	lambda value: [], # SPARSE_SWITCH
	lambda value: [], # CMPL_FLOAT
	lambda value: [], # CMPG_FLOAT
	lambda value: [], # CMPL_DOUBLE
	lambda value: [], # CMPG_DOUBLE
	lambda value: [], # CMP_LONG
	lambda value: [], # IF_EQ
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
	lambda value: [], # UNUSED_3E
	lambda value: [], # UNUSED_3F
	lambda value: [], # UNUSED_40
	lambda value: [], # UNUSED_41
	lambda value: [], # UNUSED_42
	lambda value: [], # UNUSED_43
	lambda value: [], # AGET
	lambda value: [], # AGET_WIDE
	lambda value: [], # AGET_OBJECT
	lambda value: [], # AGET_BOOLEAN
	lambda value: [], # AGET_BYTE
	lambda value: [], # AGET_CHAR
	lambda value: [], # AGET_SHORT
	lambda value: [], # APUT
	lambda value: [], # APUT_WIDE
	lambda value: [], # APUT_OBJECT
	lambda value: [], # APUT_BOOLEAN
	lambda value: [], # APUT_BYTE
	lambda value: [], # APUT_CHAR
	lambda value: [], # APUT_SHORT
	lambda value: [], # IGET
	lambda value: [], # IGET_WIDE
	lambda value: [], # IGET_OBJECT
	lambda value: [], # IGET_BOOLEAN
	lambda value: [], # IGET_BYTE
	lambda value: [], # IGET_CHAR
	lambda value: [], # IGET_SHORT
	lambda value: [], # IPUT
	lambda value: [], # IPUT_WIDE
	lambda value: [], # IPUT_OBJECT
	lambda value: [], # IPUT_BOOLEAN
	lambda value: [], # IPUT_BYTE
	lambda value: [], # IPUT_CHAR
	lambda value: [], # IPUT_SHORT
	lambda value: [], # SGET
	lambda value: [], # SGET_WIDE
	lambda value: [], # SGET_OBJECT
	lambda value: [], # SGET_BOOLEAN
	lambda value: [], # SGET_BYTE
	lambda value: [], # SGET_CHAR
	lambda value: [], # SGET_SHORT
	lambda value: [], # SPUT
	lambda value: [], # SPUT_WIDE
	lambda value: [], # SPUT_OBJECT
	lambda value: [], # SPUT_BOOLEAN
	lambda value: [], # SPUT_BYTE
	lambda value: [], # SPUT_CHAR
	lambda value: [], # SPUT_SHORT
	lambda value: [], # INVOKE_VIRTUAL
	lambda value: [], # INVOKE_SUPER
	lambda value: [], # INVOKE_DIRECT
	lambda value: [], # INVOKE_STATIC
	lambda value: [], # INVOKE_INTERFACE
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
# hack to make it work for now
#for i in range(0x28, 0xFF):
#	OperandTokens[i] = []

InstructionIL = {
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

		# function return
		if instr in ["return-void", "return", "return-wide", "return-object"]:
			result.add_branch(FunctionReturn)

		# TODO: implement unconditional jumps
		elif instr in ["goto", "goto/16", "goto/32"]:
			# how is data handled?
			#d = struct.unpack("<h", data[1:3])[0]

			# Examples:
			# 	28F0 - goto 0005 // -0010    # how do they go from 0xF0 to 5? it's signed...
			#			Jumps to current position-16 words (hex 10). 0005 is the label of the target instruction.
			#	2900 0FFE - goto/16 002f // -01f1
			#			Jumps to the current position-1F1H words. 002F is the label of the target instruction.
			if instr == "goto/16":
				# FIXME: verify...
				offset = struct.unpack("<h", data[1:3])[0]# AFAIK....
				target_addr = data.addr + offset # AFAIK....

				result.add_branch(UnconditionalBranch, target_addr)


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
		instr, operand, length, value = self.decode_instruction(data, addr)
		if instr is None:
			return None

		if operand == 3:
			print "value: ", value # it's the bytes
			print "type(value): ", type(value) # type "int"

			print "================"
			print "value >> 2: ", (value >> 2)
			print "value >> 4: ", (value >> 4)
			print "value >> 6: ", (value >> 6)
			print "value >> 8: ", (value >> 8) # pretty sure this is supposed to be first one..
			print "================"


		#if operand == 0x13:
			#log(2, str(hex(value)) + ": " + str(value))


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
			# might be useful
			# 	* code_item["registers_size"] - the number of registers used by this code
			# 	* code_item["ins_size"] - the number of words of incoming arguments to the method that this code is for
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
