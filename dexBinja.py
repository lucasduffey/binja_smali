from binaryninja import *
import struct
import traceback
import os

# style guideline: https://google.github.io/styleguide/pyguide.html
# 010Editor: https://github.com/strazzere/010Editor-stuff/blob/master/Templates/DEXTemplate.bt
# export PYTHONPATH=$PYTHONPATH:$HOME/binaryninja/python

# https://source.android.com/devices/tech/dalvik/dalvik-bytecode.html

'''
./dalvik/libdex/DexFile.h

./dalvik/libdex/InstrUtils.h
./dalvik/libdex/DexDebugInfo.h
./dalvik/libdex/DexCatch.h
./dalvik/libdex/DexClass.h
./dalvik/libdex/DexOpcodes.h
./dalvik/libdex/ZipArchive.h
./dalvik/libdex/SysUtil.h
./dalvik/libdex/OptInvocation.h
./dalvik/libdex/CmdUtils.h
./dalvik/libdex/DexUtf.h
./dalvik/libdex/DexOptData.h
./dalvik/libdex/Leb128.h
./dalvik/libdex/DexDataMap.h
./dalvik/libdex/DexProto.h
./art/dexdump/dexdump.h
./art/runtime/dex_file-inl.h
./art/runtime/dex_instruction.h
./art/runtime/dex_method_iterator.h
./art/runtime/dex_file_verifier.h
./art/runtime/dex_instruction_utils.h
./art/runtime/dex_cache_resolved_classes.h
./art/runtime/dex_instruction-inl.h
./art/runtime/utils/dex_cache_arrays_layout.h
./art/runtime/utils/dex_cache_arrays_layout-inl.h
./art/runtime/dex_instruction_list.h
./art/runtime/dex_instruction_visitor.h
./art/runtime/dex_file.h
./art/runtime/mirror/dex_cache-inl.h
./art/runtime/mirror/dex_cache.h
./art/compiler/dex/quick/dex_file_to_method_inliner_map.h
./art/compiler/dex/quick/dex_file_method_inliner.h
./art/compiler/dex/dex_to_dex_compiler.h
./art/compiler/dex/quick_compiler_callbacks.h
./art/compiler/dex/verification_results.h
./art/compiler/dex/verified_method.h
./art/compiler/dex/compiler_enums.h
./art/compiler/optimizing/dex_cache_array_fixups_arm.h
./art/compiler/utils/test_dex_file_builder.h
./art/compiler/driver/dex_compilation_unit.h

'''

InstructionNames = [
	'''
	'''
]


# sizes of fields
DexFile = {
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
			"pRegisterMapPool": 8, # void*
'''
			
			baseAddr # so this is at position 249 or 250
			overhead
'''
}

class DEXViewUpdateNotification(BinaryDataNotification):
        def __init__(self, view):
                self.view = view

        # FIXME: don't trust - pulled from NES.py
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
        long_name = "Dalvik Executable"

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
                if hdr[0:8] != "dex\x0a035\x00": # dex file format
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

                return struct.unpack("<H", "APPLE")[0] # FIXME: I believe it's a ptr @ 249, need to use self.perform_read
							# I'm Betting ptr @ 250 to be even..
							# in my classes2.dex in tmp that ptr is 0x98e3 - this might be wrong


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
		

DEXViewBank.register()

#DEX.register() # TODO


# Architecture.register
