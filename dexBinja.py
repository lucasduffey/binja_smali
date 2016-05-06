from binaryninja import *
import struct
import traceback
import os

# style guideline: https://google.github.io/styleguide/pyguide.html
# export PYTHONPATH=$PYTHONPATH:$HOME/binaryninja/python

# https://source.android.com/devices/tech/dalvik/dalvik-bytecode.html
InstructionNames = [
	'''
        "brk", "ora", None, None, None, "ora", "asl", None, # 0x00
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
]

# FIXME TODO
class DEX(Architecture):
	name = "??"
	address_size = 2 # TODO
        default_int_size = 1 # TODO
        regs = {
                "a": RegisterInfo("a", 1), # TODO
                "x": RegisterInfo("x", 1), # TODO
                "y": RegisterInfo("y", 1), # TODO
                "s": RegisterInfo("s", 1) # TODO
        }
        stack_pointer = "s" # TODO
        flags = ["c", "z", "i", "d", "b", "v", "s"] # TODO
        flag_write_types = ["*", "czs", "zvs", "zs"] # TODO

	def decode_instruction(self, data, addr):
		pass



# see NESView Example
class DEXView(BinaryView):
        name = "DEX"
        long_name = "android DEX"

        def __init__(self, data):
                BinaryView.__init__(self, data.file)
                self.data = data
                self.notification = DEXViewUpdateNotification(self) # TODO
                self.data.register_notification(self.notification)

	@classmethod
        def is_valid_for_data(self, data):
                hdr = data.read(0, 16)
                if len(hdr) < 16:
                        return False
                # magic - https://en.wikipedia.org/wiki/List_of_file_signatures
                if hdr[0:4] != "PK\x03\x04": # zip file formats (zip, jar, odt, docx, apk, etc..}
                        return False
                return True


	def init(self):
		try:
			# TODO: look at NES.py
				
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
                return 0
	

	# FIXME
        def perform_get_length(self):
                return 0x10000

        def perform_is_executable(self):
                return True

	# FIXME
        def perform_get_entry_point(self):
                #return struct.unpack("<H", str(self.perform_read(0xfffc, 2)))[0] # FIXME: being triggered
                return struct.unpack("<H", "APPLE")[0] # FIXME: being triggered


'''
# this would be easier with UI plugins

# I'll need to carve out the dex code


'''

print("dexBinja")
class DEXViewBank(DEXView):
	name = "DEX"
	long_name = "android DEX"

	def __init__(self, data):
		DEXView.__init__(self, data)
		

DEXViewBank.register()

#DEX.register() # TODO


# Architecture.register
