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
# lenths excludes opcode length?
	0x0: {"name": "nop", "length": 0},
	0x1: {"name": "move", "length": 1},
	0x2: {"name": "move/from16", "length": 2},
	0x3: {"name": "move/16", "length": 5}, # 3 => 5
	0x4: {"name": "move-wide", "length": 2},
	0x5: {"name": "move-wide/from16", "length": 3}, # 2 => 3
	0x6: {"name": "move-wide/16", "length": 4}, # 3 => 4
	0x7: {"name": "move-object", "length": 1},
	0x8: {"name": "move-object/from16", "length": 3}, # 2 => 3
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
	0x1b: {"name": "const-string-jumbo", "length": 5}, # 31C - it's the only 31C
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
	0x2a: {"name": "goto/32", "length": 5}, # 3 => 5
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

InstructionIL = {}

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

		op = ord(data[0])

		result = InstructionInfo()
		result.length = length

		# function return
		if instr in ["return-void", "return", "return-wide", "return-object"]:
			result.add_branch(FunctionReturn)

		elif instr in ["goto", "goto/16", "goto/32"]:
			# "goto" 10T - parse_FMT10T
			# "goto/16" 20T
			# "goto/32" 30T

			fn = dex_decode[op][3]
			val = func_point[fn](self, data[1:], addr)[2] # this might be the thing to jump to.. index out of range???

			val = int(val, 16)
			val = int(val)
			#log(2, "val: %x" % val)
			#log(2, data.encode("hex"))
			#log(2, data[1].encode("hex"))

			result.add_branch(UnconditionalBranch, val)

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
		raw_binary = data.read(0, raw_binary_length) # TODO: eliminate this step...

		# TODO: check if this works
		#global dex_file
		self.dex = dex_parser(self, raw_binary) # FIXME: is there a way to avoid re-analysis if it's been cached
		 #= dex_file

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
