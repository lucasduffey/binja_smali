# special thanks to yanfeng.wyf (https://github.com/ondreji/dex_parser/blob/master/dex.py)
from binaryninja import *
import struct

# https://source.android.com/devices/tech/dalvik/instruction-formats.html
FMT10T = 0
FMT10X = 1
FMT11N = 2
FMT11X = 3
FMT12X = 4
FMT20T = 5
FMT21C = 6
FMT21H = 7
FMT21S = 8
FMT21T = 9
FMT22B = 10
FMT22C = 11
FMT22S = 12
FMT22T = 13
FMT22X = 14
FMT23X = 15
FMT30T = 16
FMT31C = 17
FMT31I = 18
FMT31T = 19
FMT32X = 20
FMT35C = 21
FMT3RC = 22
FMT51L = 23

# unnecessary ATM
fmt_list = ['fmt10t', 'fmt10x', 'fmt11n', 'fmt11x', 'fmt12x', 'fmt20t', 'fmt21c', 'fmt21h',
 'fmt21s', 'fmt21t', 'fmt22b', 'fmt22c', 'fmt22s', 'fmt22t', 'fmt22x', 'fmt23x',
 'fmt30t', 'fmt31c', 'fmt31i', 'fmt31t', 'fmt32x', 'fmt35c', 'fmt3rc', 'fmt51l']


'''
# read from "android dex opcodes" google spreadsheet
for line in open("data").readlines():
	opcode, instructionName, operandLength = line.rstrip().split("\t")
	print  "%s: {\"name\": \"%s\", \"length\": \"%s\"}," % (opcode, instructionName, operandLength)
'''

# https://source.android.com/devices/tech/dalvik/instruction-formats.html
# XXX: rename "instruction_count" to "count" or "length"??
# XXX: length vs insruction_count - fix it...
instruction = {
	0x0: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'nop', 'format': 'fmt10x'},
	0x1: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'move', 'format': 'fmt12x'},
	0x2: {'length': 3, 'format_idx': 14, 'instruction_count': 2, 'name': 'move/from16', 'format': 'fmt22x'},
	0x3: {'length': 5, 'format_idx': 20, 'instruction_count': 3, 'name': 'move/16', 'format': 'fmt32x'},
	0x4: {'length': 2, 'format_idx': 4, 'instruction_count': 1, 'name': 'move-wide', 'format': 'fmt12x'},
	0x5: {'length': 3, 'format_idx': 14, 'instruction_count': 2, 'name': 'move-wide/from16', 'format': 'fmt22x'},
	0x6: {'length': 5, 'format_idx': 20, 'instruction_count': 3, 'name': 'move-wide/16', 'format': 'fmt32x'},
	0x7: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'move-object', 'format': 'fmt12x'},
	0x8: {'length': 3, 'format_idx': 14, 'instruction_count': 2, 'name': 'move-object/from16', 'format': 'fmt22x'},
	0x9: {'length': 5, 'format_idx': 20, 'instruction_count': 3, 'name': 'move-object/16', 'format': 'fmt32x'},
	0xa: {'length': 1, 'format_idx': 3, 'instruction_count': 1, 'name': 'move-result', 'format': 'fmt11x'},
	0xb: {'length': 1, 'format_idx': 3, 'instruction_count': 1, 'name': 'move-result-wide', 'format': 'fmt11x'},
	0xc: {'length': 1, 'format_idx': 3, 'instruction_count': 1, 'name': 'move-result-object', 'format': 'fmt11x'},
	0xd: {'length': 1, 'format_idx': 3, 'instruction_count': 1, 'name': 'move-exception', 'format': 'fmt11x'},
	0xe: {'length': 1, 'format_idx': 1, 'instruction_count': 1, 'name': 'return-void', 'format': 'fmt10x'},
	0xf: {'length': 1, 'format_idx': 3, 'instruction_count': 1, 'name': 'return', 'format': 'fmt11x'},
	0x10: {'length': 1, 'format_idx': 3, 'instruction_count': 1, 'name': 'return-wide', 'format': 'fmt11x'},
	0x11: {'length': 1, 'format_idx': 3, 'instruction_count': 1, 'name': 'return-object', 'format': 'fmt11x'},
	0x12: {'length': 1, 'format_idx': 2, 'instruction_count': 1, 'name': 'const/4', 'format': 'fmt11n'},
	0x13: {'length': 3, 'format_idx': 8, 'instruction_count': 2, 'name': 'const/16', 'format': 'fmt21s'},
	0x14: {'length': 5, 'format_idx': 18, 'instruction_count': 3, 'name': 'const', 'format': 'fmt31i'},
	0x15: {'length': 2, 'format_idx': 7, 'instruction_count': 2, 'name': 'const/high16', 'format': 'fmt21h'},
	0x16: {'length': 3, 'format_idx': 8, 'instruction_count': 2, 'name': 'const-wide/16', 'format': 'fmt21s'},
	0x17: {'length': 5, 'format_idx': 18, 'instruction_count': 3, 'name': 'const-wide/32', 'format': 'fmt31i'},
	0x18: {'length': 7, 'format_idx': 23, 'instruction_count': 5, 'name': 'const-wide', 'format': 'fmt51l'},
	0x19: {'length': 3, 'format_idx': 7, 'instruction_count': 2, 'name': 'const-wide/high16', 'format': 'fmt21h'},
	0x1a: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'const-string', 'format': 'fmt21c'},
	0x1b: {'length': 5, 'format_idx': 17, 'instruction_count': 3, 'name': 'const-string/jumbo', 'format': 'fmt31c'},
	0x1c: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'const-class', 'format': 'fmt21c'},
	0x1d: {'length': 1, 'format_idx': 3, 'instruction_count': 1, 'name': 'monitor-enter', 'format': 'fmt11x'},
	0x1e: {'length': 1, 'format_idx': 3, 'instruction_count': 1, 'name': 'monitor-exit', 'format': 'fmt11x'},
	0x1f: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'check-cast', 'format': 'fmt21c'},
	0x20: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'instance-of', 'format': 'fmt22c'},
	0x21: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'array-length', 'format': 'fmt12x'},
	0x22: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'new-instance', 'format': 'fmt21c'},
	0x23: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'new-array', 'format': 'fmt22c'},
	0x24: {'length': 5, 'format_idx': 21, 'instruction_count': 3, 'name': 'filled-new-array', 'format': 'fmt35c'},
	0x25: {'length': 5, 'format_idx': 22, 'instruction_count': 3, 'name': 'filled-new-array/range', 'format': 'fmt3rc'},
	0x26: {'length': 5, 'format_idx': 19, 'instruction_count': 3, 'name': 'fill-array-data', 'format': 'fmt31t'},
	0x27: {'length': 1, 'format_idx': 3, 'instruction_count': 1, 'name': 'throw', 'format': 'fmt11x'},
	0x28: {'length': 1, 'format_idx': 0, 'instruction_count': 1, 'name': 'goto', 'format': 'fmt10t'},
	0x29: {'length': 3, 'format_idx': 5, 'instruction_count': 2, 'name': 'goto/16', 'format': 'fmt20t'},
	0x2a: {'length': 5, 'format_idx': 16, 'instruction_count': 3, 'name': 'goto/32', 'format': 'fmt30t'},
	0x2b: {'length': 5, 'format_idx': 19, 'instruction_count': 3, 'name': 'packed-switch', 'format': 'fmt31t'},
	0x2c: {'length': 5, 'format_idx': 19, 'instruction_count': 3, 'name': 'sparse-switch', 'format': 'fmt31t'},
	0x2d: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'cmpl-float', 'format': 'fmt23x'},
	0x2e: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'cmpg-float', 'format': 'fmt23x'},
	0x2f: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'cmpl-double', 'format': 'fmt23x'},
	0x30: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'cmpg-double', 'format': 'fmt23x'},
	0x31: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'cmp-long', 'format': 'fmt23x'},
	0x32: {'length': 3, 'format_idx': 13, 'instruction_count': 2, 'name': 'if-eq', 'format': 'fmt22t'},
	0x33: {'length': 3, 'format_idx': 13, 'instruction_count': 2, 'name': 'if-ne', 'format': 'fmt22t'},
	0x34: {'length': 3, 'format_idx': 13, 'instruction_count': 2, 'name': 'if-lt', 'format': 'fmt22t'},
	0x35: {'length': 3, 'format_idx': 13, 'instruction_count': 2, 'name': 'if-ge', 'format': 'fmt22t'},
	0x36: {'length': 3, 'format_idx': 13, 'instruction_count': 2, 'name': 'if-gt', 'format': 'fmt22t'},
	0x37: {'length': 3, 'format_idx': 13, 'instruction_count': 2, 'name': 'if-le', 'format': 'fmt22t'},
	0x38: {'length': 3, 'format_idx': 9, 'instruction_count': 2, 'name': 'if-eqz', 'format': 'fmt21t'},
	0x39: {'length': 3, 'format_idx': 9, 'instruction_count': 2, 'name': 'if-nez', 'format': 'fmt21t'},
	0x3a: {'length': 3, 'format_idx': 9, 'instruction_count': 2, 'name': 'if-ltz', 'format': 'fmt21t'},
	0x3b: {'length': 3, 'format_idx': 9, 'instruction_count': 2, 'name': 'if-gez', 'format': 'fmt21t'},
	0x3c: {'length': 3, 'format_idx': 9, 'instruction_count': 2, 'name': 'if-gtz', 'format': 'fmt21t'},
	0x3d: {'length': 3, 'format_idx': 9, 'instruction_count': 2, 'name': 'if-lez', 'format': 'fmt21t'},
	0x3e: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0x3f: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0x40: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0x41: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0x42: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0x43: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0x44: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aget', 'format': 'fmt23x'},
	0x45: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aget-wide', 'format': 'fmt23x'},
	0x46: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aget-object', 'format': 'fmt23x'},
	0x47: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aget-boolean', 'format': 'fmt23x'},
	0x48: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aget-byte', 'format': 'fmt23x'},
	0x49: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aget-char', 'format': 'fmt23x'},
	0x4a: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aget-short', 'format': 'fmt23x'},
	0x4b: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aput', 'format': 'fmt23x'},
	0x4c: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aput-wide', 'format': 'fmt23x'},
	0x4d: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aput-object', 'format': 'fmt23x'},
	0x4e: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aput-boolean', 'format': 'fmt23x'},
	0x4f: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aput-byte', 'format': 'fmt23x'},
	0x50: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aput-shar', 'format': 'fmt23x'},
	0x51: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'aput-short', 'format': 'fmt23x'},
	0x52: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iget', 'format': 'fmt22c'},
	0x53: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iget-wide', 'format': 'fmt22c'},
	0x54: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iget-object', 'format': 'fmt22c'},
	0x55: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iget-boolean', 'format': 'fmt22c'},
	0x56: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iget-byte', 'format': 'fmt22c'},
	0x57: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iget-char', 'format': 'fmt22c'},
	0x58: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iget-short', 'format': 'fmt22c'},
	0x59: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iput', 'format': 'fmt22c'},
	0x5a: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iput-wide', 'format': 'fmt22c'},
	0x5b: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iput-object', 'format': 'fmt22c'},
	0x5c: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iput-boolean', 'format': 'fmt22c'},
	0x5d: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iput-byte', 'format': 'fmt22c'},
	0x5e: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iput-char', 'format': 'fmt22c'},
	0x5f: {'length': 3, 'format_idx': 11, 'instruction_count': 2, 'name': 'iput-short', 'format': 'fmt22c'},
	0x60: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sget', 'format': 'fmt21c'},
	0x61: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sget-wide', 'format': 'fmt21c'},
	0x62: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sget-object', 'format': 'fmt21c'},
	0x63: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sget-boolean', 'format': 'fmt21c'},
	0x64: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sget-byte', 'format': 'fmt21c'},
	0x65: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sget-char', 'format': 'fmt21c'},
	0x66: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sget-short', 'format': 'fmt21c'},
	0x67: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sput', 'format': 'fmt21c'},
	0x68: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sput-wide', 'format': 'fmt21c'},
	0x69: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sput-object', 'format': 'fmt21c'},
	0x6a: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sput-boolean', 'format': 'fmt21c'},
	0x6b: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sput-byte', 'format': 'fmt21c'},
	0x6c: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sput-char', 'format': 'fmt21c'},
	0x6d: {'length': 3, 'format_idx': 6, 'instruction_count': 2, 'name': 'sput-short', 'format': 'fmt21c'},
	0x6e: {'length': 5, 'format_idx': 21, 'instruction_count': 3, 'name': 'invoke-virtual', 'format': 'fmt35c'},
	0x6f: {'length': 5, 'format_idx': 21, 'instruction_count': 3, 'name': 'invoke-super', 'format': 'fmt35c'},
	0x70: {'length': 5, 'format_idx': 21, 'instruction_count': 3, 'name': 'invoke-direct', 'format': 'fmt35c'},
	0x71: {'length': 5, 'format_idx': 21, 'instruction_count': 3, 'name': 'invoke-static', 'format': 'fmt35c'},
	0x72: {'length': 5, 'format_idx': 21, 'instruction_count': 3, 'name': 'invoke-interface', 'format': 'fmt35c'},
	0x73: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0x74: {'length': 5, 'format_idx': 22, 'instruction_count': 3, 'name': 'invoke-virtual/range', 'format': 'fmt3rc'},
	0x75: {'length': 5, 'format_idx': 22, 'instruction_count': 3, 'name': 'invoke-super/range', 'format': 'fmt3rc'},
	0x76: {'length': 5, 'format_idx': 22, 'instruction_count': 3, 'name': 'invoke-direct/range', 'format': 'fmt3rc'},
	0x77: {'length': 5, 'format_idx': 22, 'instruction_count': 3, 'name': 'invoke-static/range', 'format': 'fmt3rc'},
	0x78: {'length': 5, 'format_idx': 22, 'instruction_count': 3, 'name': 'invoke-interface/range', 'format': 'fmt3rc'},
	0x79: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0x7a: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0x7b: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'neg-int', 'format': 'fmt12x'},
	0x7c: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'not-int', 'format': 'fmt12x'},
	0x7d: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'neg-long', 'format': 'fmt12x'},
	0x7e: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'not-long', 'format': 'fmt12x'},
	0x7f: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'neg-float', 'format': 'fmt12x'},
	0x80: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'neg-double', 'format': 'fmt12x'},
	0x81: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'int-to-long', 'format': 'fmt12x'},
	0x82: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'int-to-float', 'format': 'fmt12x'},
	0x83: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'int-to-double', 'format': 'fmt12x'},
	0x84: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'long-to-int', 'format': 'fmt12x'},
	0x85: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'long-to-float', 'format': 'fmt12x'},
	0x86: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'long-to-double', 'format': 'fmt12x'},
	0x87: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'float-to-int', 'format': 'fmt12x'},
	0x88: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'float-to-long', 'format': 'fmt12x'},
	0x89: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'float-to-double', 'format': 'fmt12x'},
	0x8a: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'double-to-int', 'format': 'fmt12x'},
	0x8b: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'double-to-long', 'format': 'fmt12x'},
	0x8c: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'double-to-float', 'format': 'fmt12x'},
	0x8d: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'int-to-byte', 'format': 'fmt12x'},
	0x8e: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'int-to-char', 'format': 'fmt12x'},
	0x8f: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'int-to-short', 'format': 'fmt12x'},
	0x90: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'add-int', 'format': 'fmt23x'},
	0x91: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'sub-int', 'format': 'fmt23x'},
	0x92: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'mul-int', 'format': 'fmt23x'},
	0x93: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'div-int', 'format': 'fmt23x'},
	0x94: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'rem-int', 'format': 'fmt23x'},
	0x95: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'and-int', 'format': 'fmt23x'},
	0x96: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'or-int', 'format': 'fmt23x'},
	0x97: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'xor-int', 'format': 'fmt23x'},
	0x98: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'shl-int', 'format': 'fmt23x'},
	0x99: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'shr-int', 'format': 'fmt23x'},
	0x9a: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'ushr-int', 'format': 'fmt23x'},
	0x9b: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'add-long', 'format': 'fmt23x'},
	0x9c: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'sub-long', 'format': 'fmt23x'},
	0x9d: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'mul-long', 'format': 'fmt23x'},
	0x9e: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'div-long', 'format': 'fmt23x'},
	0x9f: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'rem-long', 'format': 'fmt23x'},
	0xa0: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'and-long', 'format': 'fmt23x'},
	0xa1: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'or-long', 'format': 'fmt23x'},
	0xa2: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'xor-long', 'format': 'fmt23x'},
	0xa3: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'shl-long', 'format': 'fmt23x'},
	0xa4: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'shr-long', 'format': 'fmt23x'},
	0xa5: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'ushr-long', 'format': 'fmt23x'},
	0xa6: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'add-float', 'format': 'fmt23x'},
	0xa7: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'sub-float', 'format': 'fmt23x'},
	0xa8: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'mul-float', 'format': 'fmt23x'},
	0xa9: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'div-float', 'format': 'fmt23x'},
	0xaa: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'rem-float', 'format': 'fmt23x'},
	0xab: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'add-double', 'format': 'fmt23x'},
	0xac: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'sub-double', 'format': 'fmt23x'},
	0xad: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'mul-double', 'format': 'fmt23x'},
	0xae: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'div-double', 'format': 'fmt23x'},
	0xaf: {'length': 3, 'format_idx': 15, 'instruction_count': 2, 'name': 'rem-double', 'format': 'fmt23x'},
	0xb0: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'add-int/2addr', 'format': 'fmt12x'},
	0xb1: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'sub-int/2addr', 'format': 'fmt12x'},
	0xb2: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'mul-int/2addr', 'format': 'fmt12x'},
	0xb3: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'div-int/2addr', 'format': 'fmt12x'},
	0xb4: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'rem-int/2addr', 'format': 'fmt12x'},
	0xb5: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'and-int/2addr', 'format': 'fmt12x'},
	0xb6: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'or-int/2addr', 'format': 'fmt12x'},
	0xb7: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'xor-int/2addr', 'format': 'fmt12x'},
	0xb8: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'shl-int/2addr', 'format': 'fmt12x'},
	0xb9: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'shr-int/2addr', 'format': 'fmt12x'},
	0xba: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'ushr-int/2addr', 'format': 'fmt12x'},
	0xbb: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'add-long/2addr', 'format': 'fmt12x'},
	0xbc: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'sub-long/2addr', 'format': 'fmt12x'},
	0xbd: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'mul-long/2addr', 'format': 'fmt12x'},
	0xbe: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'div-long/2addr', 'format': 'fmt12x'},
	0xbf: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'rem-long/2addr', 'format': 'fmt12x'},
	0xc0: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'and-long/2addr', 'format': 'fmt12x'},
	0xc1: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'or-long/2addr', 'format': 'fmt12x'},
	0xc2: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'xor-long/2addr', 'format': 'fmt12x'},
	0xc3: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'shl-long/2addr', 'format': 'fmt12x'},
	0xc4: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'shr-long/2addr', 'format': 'fmt12x'},
	0xc5: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'ushr-long/2addr', 'format': 'fmt12x'},
	0xc6: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'add-float/2addr', 'format': 'fmt12x'},
	0xc7: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'sub-float/2addr', 'format': 'fmt12x'},
	0xc8: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'mul-float/2addr', 'format': 'fmt12x'},
	0xc9: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'div-float/2addr', 'format': 'fmt12x'},
	0xca: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'rem-float/2addr', 'format': 'fmt12x'},
	0xcb: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'add-double/2addr', 'format': 'fmt12x'},
	0xcc: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'sub-double/2addr', 'format': 'fmt12x'},
	0xcd: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'mul-double/2addr', 'format': 'fmt12x'},
	0xce: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'div-double/2addr', 'format': 'fmt12x'},
	0xcf: {'length': 1, 'format_idx': 4, 'instruction_count': 1, 'name': 'rem-double/2addr', 'format': 'fmt12x'},
	0xd0: {'length': 3, 'format_idx': 12, 'instruction_count': 2, 'name': 'add-int/lit16', 'format': 'fmt22s'},
	0xd1: {'length': 3, 'format_idx': 12, 'instruction_count': 2, 'name': 'rsub-int', 'format': 'fmt22s'},
	0xd2: {'length': 3, 'format_idx': 12, 'instruction_count': 2, 'name': 'mul-int/lit16', 'format': 'fmt22s'},
	0xd3: {'length': 3, 'format_idx': 12, 'instruction_count': 2, 'name': 'div-int/lit16', 'format': 'fmt22s'},
	0xd4: {'length': 3, 'format_idx': 12, 'instruction_count': 2, 'name': 'rem-int/lit16', 'format': 'fmt22s'},
	0xd5: {'length': 3, 'format_idx': 12, 'instruction_count': 2, 'name': 'and-int/lit16', 'format': 'fmt22s'},
	0xd6: {'length': 3, 'format_idx': 12, 'instruction_count': 2, 'name': 'or-int/lit16', 'format': 'fmt22s'},
	0xd7: {'length': 3, 'format_idx': 12, 'instruction_count': 2, 'name': 'xor-int/lit16', 'format': 'fmt22s'},
	0xd8: {'length': 3, 'format_idx': 10, 'instruction_count': 2, 'name': 'add-int/lit8', 'format': 'fmt22b'},
	0xd9: {'length': 3, 'format_idx': 10, 'instruction_count': 2, 'name': 'rsub-int/lit8', 'format': 'fmt22b'},
	0xda: {'length': 3, 'format_idx': 10, 'instruction_count': 2, 'name': 'mul-int/lit8', 'format': 'fmt22b'},
	0xdb: {'length': 3, 'format_idx': 10, 'instruction_count': 2, 'name': 'div-int/lit8', 'format': 'fmt22b'},
	0xdc: {'length': 3, 'format_idx': 10, 'instruction_count': 2, 'name': 'rem-int/lit8', 'format': 'fmt22b'},
	0xdd: {'length': 3, 'format_idx': 10, 'instruction_count': 2, 'name': 'and-int/lit8', 'format': 'fmt22b'},
	0xde: {'length': 3, 'format_idx': 10, 'instruction_count': 2, 'name': 'or-int/lit8', 'format': 'fmt22b'},
	0xdf: {'length': 3, 'format_idx': 10, 'instruction_count': 2, 'name': 'xor-int/lit8', 'format': 'fmt22b'},
	0xe0: {'length': 3, 'format_idx': 10, 'instruction_count': 2, 'name': 'shl-int/lit8', 'format': 'fmt22b'},
	0xe1: {'length': 3, 'format_idx': 10, 'instruction_count': 2, 'name': 'shr-int/lit8', 'format': 'fmt22b'},
	0xe2: {'length': 3, 'format_idx': 10, 'instruction_count': 2, 'name': 'ushr-int/lit8', 'format': 'fmt22b'},
	0xe3: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xe4: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xe5: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xe6: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xe7: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xe8: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xe9: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xea: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xeb: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xec: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xed: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xee: {'length': 5, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xef: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xf0: {'length': 5, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xf1: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xf2: {'length': 3, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xf3: {'length': 3, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xf4: {'length': 3, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xf5: {'length': 3, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xf6: {'length': 3, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xf7: {'length': 3, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xf8: {'length': 5, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xf9: {'length': 5, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xfa: {'length': 5, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xfb: {'length': 5, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xfc: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xfd: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xfe: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'},
	0xff: {'length': 0, 'format_idx': 1, 'instruction_count': 1, 'name': 'unused', 'format': 'fmt10x'}
}

def parse_FMT10X(dex_object, buf, offset):
	op = ord(buf[0])
	return (instruction[op]["instruction_count"], instruction[op]["name"])

# op +AA
def parse_FMT10T(dex_object, buf, offset):
	op = ord(buf[0])
	val, = struct.unpack_from("b", buf, 1)
	AA = "%i" % (offset + val)

	return (instruction[op]["instruction_count"], instruction[op]["name"], AA)

# op vA, #+B
def parse_FMT11N(dex_object, buf, offset):
	op = ord(buf[0])
	vA = "v%d" % (ord(buf[1]) & 0xf)
	B = "%d" % ((ord(buf[1]) >> 4) & 0xf)

	return (instruction[op]["instruction_count"], instruction[op]["name"], vA, B)

# op vAA
def parse_FMT11X(dex_object, buf, offset):
	op = ord(buf[0])
	vAA = "v%d" % ord(buf[1])

	return (instruction[op]["instruction_count"], instruction[op]["name"], vAA)

# op vA, vB
def parse_FMT12X(dex_object, buf, offset):
	op = ord(buf[0])
	vA = "v%d" % (ord(buf[1]) & 0x0f)
	vB = "v%d" % ((ord(buf[1]) >> 4) & 0xf)

	return (instruction[op]["instruction_count"], instruction[op]["name"], vA, vB)

# op +AAAA
def parse_FMT20T(dex_object, buf, offset):
	op = ord(buf[0])
	v, = struct.unpack_from("h", buf, 2)
	AAAA = instruction[op]["name"],"%i"%(v+offset)

	return (instruction[op]["instruction_count"], AAAA)

# op vAA, type@BBBB
# op vAA, field@BBBB
# op vAA, string@BBBB
def parse_FMT21C(dex_object, buf, offset):
	op = ord(buf[0]) # IS THIS RIGHT?
	vAA = "v%d" % ord(buf[1])

	v, = struct.unpack_from("H", buf, 2)
	arg1 = "@%d" % v # XXX- is this "BBBB"

	if op == 0x1a:
		# FIXME: need to figure out how to get dex_object properly
		arg1 = "unimplemented"
		if "string_table" in globals(): # XXX: implement string_table
			arg1 = "\"%s\"" % string_table[v] # was dex_object.get_string_by_id(v)
		#arg1 = "\"%s\"" % dex_file.get_string_by_id(v) # can't get this working

	elif op in [0x1c,0x1f,0x22]:
		# FIXME: need to figure out how to get dex_object properly
		#arg1 = "type@%s"%dex_object.get_type_name(v) # FIXME: replace with get_type_name_by_id?
		arg1 = "type@unimplemented"
	else:
		# FIXME: need to figure out how to get dex_object properly
		arg1 = "field@unimplemented"
		#arg1 = "field@%s  //%s" % (dex_object.getfieldname(v),dex_object.getfieldfullname(v))
	return (instruction[op]["instruction_count"], instruction[op]["name"], vAA, arg1)

# op vAA, #+BBBB0000
# op vAA, #+BBBB000000000000
def parse_FMT21H(dex_object, buf, offset):
	op = ord(buf[0])
	vAA = "v%d" % ord(buf[1])

	v, = struct.unpack_from("H", buf, 2)

	if ord(buf[1]) == 0x19:
		arg1 = "@%d000000000000" % v
	else:
		arg1 = "@%d0000" % v
	return (instruction[op]["instruction_count"], instruction[op]["name"], vAA, arg1)

# op vAA, #+BBBB
def parse_FMT21S(dex_object, buf, offset):
	op = ord(buf[0])
	vAA = "v%d" % ord(buf[1])

	v, = struct.unpack_from("H", buf, 2)
	arg1 = "%d" % v

	return (instruction[op]["instruction_count"], instruction[op]["name"], vAA, arg1)

# op vAA, +BBBB
def parse_FMT21T(dex_object, buf, offset):
	op = ord(buf[0])
	vAA = "v%d" % ord(buf[1])

	v, = struct.unpack_from("h", buf, 2)

	arg1 = "%i" % (offset+v)
	return (instruction[op]["instruction_count"], instruction[op]["name"], vAA, arg1)

# op vAA, vBB, #+CC
def parse_FMT22B(dex_object, buf, offset):
	op = ord(buf[0])
	cc,bb, = struct.unpack_from("Bb", buf, 2)

	vAA = "v%d" % ord(buf[1])
	vBB = "v%d" % bb # XXX - is this right?

	return (instruction[op]["instruction_count"], instruction[op]["name"], vAA, vBB, "%d" % cc)

# op vA, vB, type@CCCC
# op vA, vB, field@CCCC
def parse_FMT22C(dex_object, buf, offset):
	op = ord(buf[0])
	vA = "v%d" % (ord(buf[1]) & 0xf)
	vB = "v%d" % ((ord(buf[1]) >> 4) & 0xf)

	cccc, = struct.unpack_from("H", buf, 2)

	if op == 0x20 or op == 0x23:
		# FIXME: need to figure out how to get dex_object properly
		#prefix="type@%s"%(dex_object.get_type_name(cccc))
		prefix = "type@unimplemented"

	else:
		# FIXME: need to figure out how to get dex_object properly
		#prefix="field@%s  //%s"%(dex_object.getfieldname(cccc),dex_object.getfieldfullname(cccc))
		prefix = "field@unimplemented"

	return (instruction[op]["instruction_count"], instruction[op]["name"], vA, vB, "%s" % prefix)

# op vA, vB, #+CCCC
def parse_FMT22S(dex_object, buf, offset):
	op = ord(buf[0])
	vA = "v%d" % (ord(buf[1]) & 0xf)
	vB = "v%d" % ((ord(buf[1]) >> 4) & 0xf)

	cccc, = struct.unpack_from("h", buf, 2)

	return (instruction[op]["instruction_count"], instruction[op]["name"], vA, vB,"%d" % cccc)

# op vA, vB, +CCCC
def parse_FMT22T(dex_object, buf, offset):
	op = ord(buf[0])
	vA = "v%d" % (ord(buf[1]) & 0xf)
	vB = "v%d" % ((ord(buf[1]) >> 4) & 0xf)

	cccc, = struct.unpack_from("h", buf, 2)

	return (instruction[op]["instruction_count"], instruction[op]["name"], vA, vB, "%i" % (offset + cccc))

# op vAA, vBBBB
def parse_FMT22X(dex_object, buf, offset):
	op = ord(buf[0])
	vAA = "v%d" % ord(buf[1])
	vBBBB, = struct.unpack_from("h", buf, 2)

	return (instruction[op]["instruction_count"], instruction[op]["name"], vAA, "v%d" % vBBBB)

# op vAA, vBB, vCC
def parse_FMT23X(dex_object, buf, offset):
	op = ord(buf[0])
	vAA = "v%d" % ord(buf[1])
	vCC,vBB, = struct.unpack_from("Bb", buf, 2)

	return (instruction[op]["instruction_count"], instruction[op]["name"], vAA, "v%d" % vBB, "v%d" % vCC)

# op +AAAAAAAA
def parse_FMT30T(dex_object, buf, offset):
	op = ord(buf[0])
	AAAAAAAA, = struct.unpack_from("i", buf, 2)

	return instruction[op]["instruction_count"], instruction[op]["name"], "%i" % (AAAAAAAA + offset)

# op vAA, string@BBBBBBBB
def parse_FMT31C(dex_object, buf, offset):
	op = ord(buf[0])
	vAA = "v%d" % ord(buf[1])

	BBBBBBBB, = struct.unpack_from("I", buf, 2)

	return (instruction[op]["instruction_count"], instruction[op]["name"], vAA, "%d" % BBBBBBBB) # this used to have a "+" prefix

# op vAA, #+BBBBBBBB
def parse_FMT31I(dex_object, buf, offset):
	op = ord(buf[0])
	vAA = "v%d" % ord(buf[1])
	BBBBBBBB, = struct.unpack_from("I", buf, 2)

	return (instruction[op]["instruction_count"], instruction[op]["name"], vAA, "%d" % BBBBBBBB)

# op vAA, +BBBBBBBB
def parse_FMT31T(dex_object, buf, offset):
	op = ord(buf[0])
	vAA = "v%d" % ord(buf[1])
	BBBBBBBB, = struct.unpack_from("i", buf, 2)

	return (instruction[op]["instruction_count"], instruction[op]["name"], vAA, "string@%d" % BBBBBBBB)

# requires buffer of at least 4 bytes
# GREPME - seems to be the only function with problems..
# op vAAAA, vBBBB
def parse_FMT32X(dex_object, buf, offset):
	op = ord(buf[0])
	vAAAA,vBBBB, = struct.unpack_from("hh", buf, 2) # I'm missing a single byte of data..

	return (instruction[op]["instruction_count"], instruction[op]["name"], "v%d" % vAAAA, "v%d" % vBBBB)

# in the "func_point" function list, directly called by "perform_get_instruction_text(self, blah..)"
def parse_FMT35C(dex_object, buf, offset):
	op = ord(buf[0])

	A = ord(buf[1]) >> 4
	G = ord(buf[1]) & 0xf
	D = ord(buf[4]) >> 4
	C = ord(buf[4]) & 0xf
	F = ord(buf[5]) >> 4
	E = ord(buf[5]) & 0xf
	bbbb, = struct.unpack_from("H", buf, 2)

	# FIXME: figure out how to pass "dex_object"
	if op == 0x24:
		prefix = "type@unimplemented"

		if "string_table" in globals(): # XXX
			prefix = "type@%s" % string_table[bbbb] # was dex_object.get_string_by_id(bbbb)

	else:
		#prefix = "meth@%s  //%s"%(dex_object.get_method_name(bbbb), dex_object.getmethodfullname(bbbb,True)) # FIXME: getmethodfullname isn't inheirited by dexView stuff
		prefix = "meth@unimplemented"

	if A == 5:
		return (instruction[op]["instruction_count"], instruction[op]["name"], "v%d"%C, "v%d"%D, "v%d"%E, "v%d"%F, "v%d"%G, "%s" % (prefix))
	elif A == 4:
		return (instruction[op]["instruction_count"], instruction[op]["name"], "v%d"%C, "v%d"%D, "v%d"%E, "v%d"%F, "%s" % (prefix))
	elif A == 3:
		return (instruction[op]["instruction_count"], instruction[op]["name"], "v%d"%C, "v%d"%D, "v%d"%E, "%s" % (prefix))
	elif A == 2:
		return (instruction[op]["instruction_count"], instruction[op]["name"], "v%d"%C, "v%d"%D, "%s" % (prefix))
	elif A == 1:
		return (instruction[op]["instruction_count"], instruction[op]["name"], "v%d"%C, "%s" % (prefix))
	elif A == 0:
		return (instruction[op]["instruction_count"], instruction[op]["name"], "%s" % (prefix))
	else:
		return (instruction[op]["instruction_count"], "error .......")
	return (instruction[op]["instruction_count"], instruction[op]["name"], "v%d"%C, "v%d"%D, "v%d"%E, "v%d"%F, "v%d"%G, "%s" % (prefix))

# XXX - pretty sure this is wrong
def parse_FMT3RC(dex_object, buf, offset):
	op = ord(buf[0])

	return (instruction[op]["instruction_count"], instruction[op]["name"])

# op vAA, #+BBBBBBBBBBBBBBBB
def parse_FMT51L(dex_object, buf, offset):
	op = ord(buf[0])
	vAA = "v%d" % ord(buf[1])

	if len(buf) < 10:
		return (1, "")
	bb = struct.unpack_from("q", buf, 2)

	return (instruction[op]["instruction_count"], instruction[op]["name"], vAA, "%d" % bb)

func_point = [parse_FMT10T, parse_FMT10X, parse_FMT11N, parse_FMT11X, parse_FMT12X, parse_FMT20T, parse_FMT21C, parse_FMT21H, parse_FMT21S, parse_FMT21T, parse_FMT22B, parse_FMT22C, parse_FMT22S, parse_FMT22T, parse_FMT22X, parse_FMT23X, parse_FMT30T, parse_FMT31C, parse_FMT31I, parse_FMT31T, parse_FMT32X, parse_FMT35C, parse_FMT3RC, parse_FMT51L]
