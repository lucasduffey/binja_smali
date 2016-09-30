from binaryninja import *
from dexFile import *
from dexParser import *
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
		fn = instruction[opcode]["format_idx"]

		#BinaryViewType["DEX"].my_test2()
		#bv.my_test2()
		# shouldn't be required?
		#if opcode >= len(InstructionNames): # was "InstructionNames"
		#	return None, None, None, None

		instr = instruction[opcode]["name"] # was "InstructionNames[opcode]"
		if instr is None:
			return None, None, None, None

		# XXX FIXME operand != opcode BAD
		operand = opcode # InstructionOperandTypes[opcode] # TODO - FIXME: pretty sure this will be fine..

		# XXX: length may be wrong...
		length = 1 + instruction[opcode]["length"] # was OperandLengths[operand]
		#log(2, "decode_instruction - opcode: %s, operand: %s, length: %s" % (str(opcode), str(operand), str(length)))

		if len(data) < length:
			return None, None, None, None

		if instruction[opcode]["length"] == 0: # was OperandLengths[operand], XXX: I messed with it again...
			value = None
		#elif operand == REL:
		#	value = (addr + 2 + struct.unpack("b", data[1])[0]) & 0xffff
		elif instruction[opcode]["length"] == 1: # was OperandLengths[operand]
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

		# is op the same as operand???
		op = ord(data[0])

		result = InstructionInfo()
		result.length = length

		# function return
		if instr in ["return-void", "return", "return-wide", "return-object"]:
			result.add_branch(FunctionReturn)

		# NOTE: ALWAYS GIVE func_point the raw data, it calculates offsets....
		elif instr in ["goto", "goto/16", "goto/32"]:
			# "goto" 10T - parse_FMT10T
			# "goto/16" 20T
			# "goto/32" 30T

			fn = instruction[op]["format_idx"]
			if fn != 5: # XXX - fix this...
				#log(2, "fn: %i" % fn) # "5"
				dest_addr = func_point[fn](self, data, addr)[2]
				dest_addr = int(dest_addr)

				result.add_branch(UnconditionalBranch, dest_addr)

		# TODO: implement conditional jumps

		# fmt22t: "if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"  # returns tuple of 5 items
		elif instr in ["if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"]:
			fn = instruction[op]["format_idx"]
			results = func_point[fn](self, data, addr) # FIXME: "dest_addr" is not correct

			reg1 = results[2] # this is register... not a string....
			reg2 = results[3] # this is register... not a string....
			dest_addr = int(results[4])

			# if reg1 == reg2: branch
			result.add_branch(TrueBranch, dest_addr)
			result.add_branch(FalseBranch, addr + 4) # +4 AFAIK??

		# fmt21t: "if-eqz", "if-ltz", "if-gez", "if-gtz", "if-lez  # returns tuple of 3 items
		elif instr in ["if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"]:
			fn = instruction[op]["format_idx"]
			results = func_point[fn](self, data, addr) # FIXME: "dest_addr" is not correct

			reg1 = results[2]
			dest_addr = int(results[3])

			# if reg1 is 0: branch to addr
			result.add_branch(TrueBranch, dest_addr)
			result.add_branch(FalseBranch, addr + 4) # +4 AFAIK??

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

		fn = instruction[op]["format_idx"]
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

				elif "@" in item:
					results += [InstructionTextToken(TextToken, item)]

				else:
					results += [InstructionTextToken(IntegerToken, item)] # FIXME: probably wrong...

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


	# error if we don't have
	def perform_get_instruction_low_level_il(self, data, addr, il):
		return None
