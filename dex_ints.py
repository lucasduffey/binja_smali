#! /usr/bin/python
# -*- coding: utf8 -*-
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
# original author: yanfeng.wyf (wuyanfeng@yeah.net)
from binaryninja import *

import struct
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

list1 = ['fmt10t', 'fmt10x', 'fmt11n', 'fmt11x', 'fmt12x', 'fmt20t', 'fmt21c', 'fmt21h',
 'fmt21s', 'fmt21t', 'fmt22b', 'fmt22c', 'fmt22s', 'fmt22t', 'fmt22x', 'fmt23x',
 'fmt30t', 'fmt31c', 'fmt31i', 'fmt31t', 'fmt32x', 'fmt35c', 'fmt3rc', 'fmt51l']

def parse_FMT10X(dex_object, buffer, offset):
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1])

# "goto"
def parse_FMT10T(dex_object, buffer, offset):
	val, = struct.unpack_from("b", buffer, 1)
	#val = int(val)
	#offset = int(offset)
	# FIXME: is offset correct?

	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1], "%i" % (offset+val)) # used to be %04x, FIXME: maybe do "%i" instead

def parse_FMT11N(dex_object, buffer, offset):
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%(ord(buffer[1])&0xf),"%d"%((ord(buffer[1])>>4)&0xf))

def parse_FMT11X(dex_object, buffer, offset):
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]))

def parse_FMT12X(dex_object, buffer, offset):
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%(ord(buffer[1])&0x0f),"v%d"%((ord(buffer[1])>>4)&0xf))

def parse_FMT20T(dex_object, buffer, offset):
	v, = struct.unpack_from("h",buffer,2)
	#v = int(v)
	#offset = int(offset)
	# TODO: is v an int...???

	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"%i"%(v+offset))  # used to be %04x, FIXME: maybe do "%i" instead

def parse_FMT21C(dex_object, buffer, offset):
	val = ord(buffer[0])

	v, = struct.unpack_from("H",buffer,2)
	arg1 = "@%d"%v
	if val == 0x1a:
		# FIXME: need to figure out how to get dex_object properly
		arg1 = "unimplemented"
		if "string_table" in globals():
			arg1 = "\"%s\"" % string_table[v] # was dex_object.get_string_by_id(v)
		#arg1 = "\"%s\"" % dex_file.get_string_by_id(v) # can't get this working

	elif val in [0x1c,0x1f,0x22]:
		# FIXME: need to figure out how to get dex_object properly
		#arg1 = "type@%s"%dex_object.get_type_name(v) # FIXME: replace with get_type_name_by_id?
		arg1 = "type@unimplemented"
	else:
		# FIXME: need to figure out how to get dex_object properly
		arg1 = "field@unimplemented"
		#arg1 = "field@%s  //%s" % (dex_object.getfieldname(v),dex_object.getfieldfullname(v))
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),arg1)

def parse_FMT21H(dex_object, buffer, offset):
	v, = struct.unpack_from("H",buffer,2)
	if ord(buffer[1]) == 0x19:
		arg1 = "@%d000000000000" % v
	else:
		arg1 = "@%d0000" % v
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),arg1)

def parse_FMT21S(dex_object, buffer, offset):
	v, = struct.unpack_from("H",buffer,2)
	arg1 = "%d"%v 
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]), arg1)

def parse_FMT21T(dex_object, buffer, offset):
	v, = struct.unpack_from("h",buffer,2)
	arg1 = "%i" % (offset+v)
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1], "v%d"%ord(buffer[1]), arg1)

def parse_FMT22B(dex_object, buffer, offset):
	cc,bb,=struct.unpack_from("Bb",buffer,2)
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),"v%d"%bb,"%d"%cc)

def parse_FMT22C(dex_object, buffer, offset):
	cccc,=struct.unpack_from("H",buffer,2)

	if ord(buffer[0]) == 0x20 or ord(buffer[0]) == 0x23:
		# FIXME: need to figure out how to get dex_object properly
		#prefix="type@%s"%(dex_object.get_type_name(cccc))
		prefix="type@unimplemented"
		pass
	else:
		# FIXME: need to figure out how to get dex_object properly
		#prefix="field@%s  //%s"%(dex_object.getfieldname(cccc),dex_object.getfieldfullname(cccc))
		prefix="field@unimplemented"
		pass

	bb = ord(buffer[1]) >> 4
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1], "v%d"%(ord(buffer[1])&0xf),"v%d"%((ord(buffer[1])>>4)&0xf),"%s"%prefix)

def parse_FMT22S(dex_object, buffer, offset):
	bb = ord(buffer[1])>>4
	cccc,=struct.unpack_from("h",buffer,2)
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1], "v%d"%(ord(buffer[1])&0xf),"v%d"%((ord(buffer[1])>>4)&0xf),"%d"%cccc)

def parse_FMT22T(dex_object, buf, offset):
	bb = ord(buf[1])>>4
	cccc,=struct.unpack_from("h",buf,2)
	return (dex_decode[ord(buf[0])][4], dex_decode[ord(buf[0])][1], "v%d"%(ord(buf[1])&0xf), "v%d"%((ord(buf[1])>>4)&0xf), "%i" % (offset + cccc))

def parse_FMT22X(dex_object, buffer, offset):
	v, = struct.unpack_from("h",buffer,2)
	arg1 = "v%d"%v
	return ( dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1], "v%d"%ord(buffer[1]),arg1)

def parse_FMT23X(dex_object, buffer, offset):
	cc,bb,=struct.unpack_from("Bb",buffer,2)
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1], "v%d"%ord(buffer[1]),"v%d"%bb,"v%d"%cc)

# why is this returning +-?
def parse_FMT30T(dex_object, buffer, offset):
	aaaaaaaa,=struct.unpack_from("i",buffer,2)
	#aaaaaaaa = int(aaaaaaaa)
	#offset = int(offset)

	return dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1], "%i" % (aaaaaaaa+offset) # this used to have a "+" prefix

def parse_FMT31C(dex_object, buffer, offset):
	bbbbbbbb,=struct.unpack_from("I",buffer,2)
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1], "v%d"%ord(buffer[1]),"%d"%bbbbbbbb) # this used to have a "+" prefix

def parse_FMT31I(dex_object, buffer, offset):
	bbbbbbbb,=struct.unpack_from("I",buffer,2)
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1], "v%d"%ord(buffer[1]),"%d" % bbbbbbbb)

def parse_FMT31T(dex_object, buffer, offset):
	bbbbbbbb,=struct.unpack_from("i",buffer,2)
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1], "v%d"%ord(buffer[1]),"string@%d" % bbbbbbbb)

# requires buffer of at least 4 bytes
# GREPME - seems to be the only function with problems..
def parse_FMT32X(dex_object, buf, offset):
	#print "len(buf): %i" % len(buf)

	aaaa,bbbb, = struct.unpack_from("hh", buf, 2) # I'm missing a single byte of data..
	return (dex_decode[ord(buf[0])][4], dex_decode[ord(buf[0])][1], "v%d" % aaaa, "v%d" % bbbb)

# in the "func_point" function list, directly called by "perform_get_instruction_text(self, blah..)"
def parse_FMT35C(dex_object, buffer, offset):
	#BinaryViewType["DEX"].my_test2()
	#DEXView.my_test2()

	A = ord(buffer[1]) >> 4
	G = ord(buffer[1]) & 0xf
	D = ord(buffer[4]) >> 4
	C = ord(buffer[4]) & 0xf
	F = ord(buffer[5]) >> 4
	E = ord(buffer[5]) & 0xf
	bbbb, = struct.unpack_from("H", buffer, 2)

	# FIXME: figure out how to pass "dex_object"
	if ord(buffer[0]) == 0x24:
		prefix="type@unimplemented"

		if "string_table" in globals():
			prefix = "type@%s" % string_table[bbbb] # was dex_object.get_string_by_id(bbbb)

	else:
		#prefix="meth@%s  //%s"%(dex_object.get_method_name(bbbb), dex_object.getmethodfullname(bbbb,True)) # FIXME: getmethodfullname isn't inheirited by dexView stuff
		prefix="meth@unimplemented"

	if A == 5:
		return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%C,"v%d"%D,"v%d"%E,"v%d"%F,"v%d"%G,"%s"%(prefix))
	elif A == 4:
		return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%C,"v%d"%D,"v%d"%E,"v%d"%F,"%s"%(prefix))
	elif A == 3:
		return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%C,"v%d"%D,"v%d"%E,"%s"%(prefix))
	elif A == 2:
		return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%C,"v%d"%D,"%s"%(prefix))
	elif A == 1:
		return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%C,"%s"%(prefix))
	elif A == 0:
		return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"%s"%(prefix))
	else:
		return (dex_decode[ord(buffer[0])][4],"error .......")
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%C,"v%d"%D,"v%d"%E,"v%d"%F,"v%d"%G,"%s"%(prefix))

def parse_FMT3RC(dex_object, buffer, offset):
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1])

def parse_FMT51L(dex_object, buffer, offset):
	if len(buffer) <10:
		return (1,"")
	bb = struct.unpack_from("q", buffer, 2)
	return (dex_decode[ord(buffer[0])][4], dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),"%d"%bb)

func_point = [parse_FMT10T, parse_FMT10X, parse_FMT11N, parse_FMT11X, parse_FMT12X, parse_FMT20T, parse_FMT21C, parse_FMT21H, parse_FMT21S, parse_FMT21T, parse_FMT22B, parse_FMT22C, parse_FMT22S, parse_FMT22T, parse_FMT22X, parse_FMT23X, parse_FMT30T, parse_FMT31C, parse_FMT31I, parse_FMT31T, parse_FMT32X, parse_FMT35C, parse_FMT3RC, parse_FMT51L]


# buffer is smali bytecode
# parse_instruction(
#	dex_object.m_content[self.insns:self.insns+self.insns_size*2],
#	self.insns # the offset to the code
#	dex_object
#	)
#
# buffer is the dex function code - the entire dex code for a specific function
# should only be called when running from command line
def parse_instruction(buffer, offset, dex_object):
	n = len(buffer)
	start = 0

	while start < n:
		if n == 1736:
			if LOGGING: print "start = %d" % start
		op = ord(buffer[start])
		if op == 0:
			type = ord(buffer[start+1])
			if type == 1:
				size, = struct.unpack_from("H", buffer, start+2)
				start += (size * 2 + 4) * 2
				continue
			elif type == 2:
				size, = struct.unpack_from("H", buffer, start+2)
				start += (size * 4 + 2) * 2
				continue
			elif type == 3:
				width, = struct.unpack_from("H", buffer, start+2)
				size, = struct.unpack_from("I", buffer, start+4)
				#width,size,=struct.unpack_from("HI",buffer,2+start)
				start += (8 + ((size*width+1)/2)*2)
				continue

		# does this get the initial "function" opcode?
		fn = dex_decode[op][3] # returns a variable like "FMT10X" which is an int - I think it indicates how it will be parsed
		val = func_point[fn](dex_object, buffer[start:], start/2)  # ONLY TIME dex_object is used
		str = ""
		m = 0
		for x in buffer[start:start+2*val[0]]: # index 0 is the number of instructions AFAIK?
			str += "%02x" % ord(x)
			m += 1
			if m % 2 == 0:
				str += " "

		if LOGGING: print "%08x: %-36s |%04x:" % (offset+start, str, start/2),
		m = 0
		for v in val[1:]:
			if m > 1:
				if LOGGING: print ",",
			if LOGGING: print v,
			m += 1
		if LOGGING: print ""
		start += 2*val[0]

# https://source.android.com/devices/tech/dalvik/instruction-formats.html
# ^ information about FMT 10x, etc..
dex_decode = {
# the last field is the total number of instructions
	0x0: (0x00,'nop','fmt10x',FMT10X,1),
	0x1: (0x01,'move','fmt12x',FMT12X,1),
	0x2: (0x02,'move/from16','fmt22x',FMT22X,2),
	0x3: (0x03,'move/16','fmt32x',FMT32X, 3), # FIXME
	0x4: (0x04,'move-wide','fmt12x',FMT12X,1),
	0x5: (0x05,'move-wide/from16','fmt22x',FMT22X,2),
	0x6: (0x06,'move-wide/16','fmt32x',FMT32X, 3), # FIXME
	0x7: (0x07,'move-object','fmt12x',FMT12X,1),
	0x8: (0x08,'move-object/from16','fmt22x',FMT22X,2),
	0x9: (0x09,'move-object/16','fmt32x',FMT32X,3), # FIXME
	0xa: (0x0a,'move-result','fmt11x',FMT11X,1),
	0xb: (0x0b,'move-result-wide','fmt11x',FMT11X,1),
	0xc: (0x0c,'move-result-object','fmt11x',FMT11X,1),
	0xd: (0x0d,'move-exception','fmt11x',FMT11X,1),
	0xe: (0x0e,'return-void','fmt10x',FMT10X,1),
	0xf: (0x0f,'return','fmt11x',FMT11X,1),
	0x10: (0x10,'return-wide','fmt11x',FMT11X,1),
	0x11: (0x11,'return-object','fmt11x',FMT11X,1),
	0x12: (0x12,'const/4','fmt11n',FMT11N,1),
	0x13: (0x13,'const/16','fmt21s',FMT21S,2),
	0x14: (0x14,'const','fmt31i',FMT31I,3),
	0x15: (0x15,'const/high16','fmt21h',FMT21H,2),
	0x16: (0x16,'const-wide/16','fmt21s',FMT21S,2),
	0x17: (0x17,'const-wide/32','fmt31i',FMT31I,3),
	0x18: (0x18,'const-wide','fmt51l',FMT51L,5),
	0x19: (0x19,'const-wide/high16','fmt21h',FMT21H,2),
	0x1a: (0x1a,'const-string','fmt21c',FMT21C,2),
	0x1b: (0x1b,'const-string/jumbo','fmt31c',FMT31C,3),
	0x1c: (0x1c,'const-class','fmt21c',FMT21C,2),
	0x1d: (0x1d,'monitor-enter','fmt11x',FMT11X,1),
	0x1e: (0x1e,'monitor-exit','fmt11x',FMT11X,1),
	0x1f: (0x1f,'check-cast','fmt21c',FMT21C,2),
	0x20: (0x20,'instance-of','fmt22c',FMT22C,2),
	0x21: (0x21,'array-length','fmt12x',FMT12X,1),
	0x22: (0x22,'new-instance','fmt21c',FMT21C,2),
	0x23: (0x23,'new-array','fmt22c',FMT22C,2),
	0x24: (0x24,'filled-new-array','fmt35c',FMT35C,3),
	0x25: (0x25,'filled-new-array/range','fmt3rc',FMT3RC,3),
	0x26: (0x26,'fill-array-data','fmt31t',FMT31T,3),
	0x27: (0x27,'throw','fmt11x',FMT11X,1),
	0x28: (0x28,'goto','fmt10t',FMT10T,1),
	0x29: (0x29,'goto/16','fmt20t',FMT20T,2),
	0x2a: (0x2a,'goto/32','fmt30t',FMT30T,3),
	0x2b: (0x2b,'packed-switch','fmt31t',FMT31T,3),
	0x2c: (0x2c,'sparse-switch','fmt31t',FMT31T,3),
	0x2d: (0x2d,'cmpl-float','fmt23x',FMT23X,2),
	0x2e: (0x2e,'cmpg-float','fmt23x',FMT23X,2),
	0x2f: (0x2f,'cmpl-double','fmt23x',FMT23X,2),
	0x30: (0x30,'cmpg-double','fmt23x',FMT23X,2),
	0x31: (0x31,'cmp-long','fmt23x',FMT23X,2),
	0x32: (0x32,'if-eq','fmt22t',FMT22T,2),
	0x33: (0x33,'if-ne','fmt22t',FMT22T,2),
	0x34: (0x34,'if-lt','fmt22t',FMT22T,2),
	0x35: (0x35,'if-ge','fmt22t',FMT22T,2),
	0x36: (0x36,'if-gt','fmt22t',FMT22T,2),
	0x37: (0x37,'if-le','fmt22t',FMT22T,2),
	0x38: (0x38,'if-eqz','fmt21t',FMT21T,2),
	0x39: (0x39,'if-nez','fmt21t',FMT21T,2),
	0x3a: (0x3a,'if-ltz','fmt21t',FMT21T,2),
	0x3b: (0x3b,'if-gez','fmt21t',FMT21T,2),
	0x3c: (0x3c,'if-gtz','fmt21t',FMT21T,2),
	0x3d: (0x3d,'if-lez','fmt21t',FMT21T,2),
	0x3e: (0x3e,'unused','fmt10x',FMT10X,1),
	0x3f: (0x3f,'unused','fmt10x',FMT10X,1),
	0x40: (0x40,'unused','fmt10x',FMT10X,1),
	0x41: (0x41,'unused','fmt10x',FMT10X,1),
	0x42: (0x42,'unused','fmt10x',FMT10X,1),
	0x43: (0x43,'unused','fmt10x',FMT10X,1),
	0x44: (0x44,'aget','fmt23x',FMT23X,2),
	0x45: (0x45,'aget-wide','fmt23x',FMT23X,2),
	0x46: (0x46,'aget-object','fmt23x',FMT23X,2),
	0x47: (0x47,'aget-boolean','fmt23x',FMT23X,2),
	0x48: (0x48,'aget-byte','fmt23x',FMT23X,2),
	0x49: (0x49,'aget-char','fmt23x',FMT23X,2),
	0x4a: (0x4a,'aget-short','fmt23x',FMT23X,2),
	0x4b: (0x4b,'aput','fmt23x',FMT23X,2),
	0x4c: (0x4c,'aput-wide','fmt23x',FMT23X,2),
	0x4d: (0x4d,'aput-object','fmt23x',FMT23X,2),
	0x4e: (0x4e,'aput-boolean','fmt23x',FMT23X,2),
	0x4f: (0x4f,'aput-byte','fmt23x',FMT23X,2),
	0x50: (0x50,'aput-shar','fmt23x',FMT23X,2),
	0x51: (0x51,'aput-short','fmt23x',FMT23X,2),
	0x52: (0x52,'iget','fmt22c',FMT22C,2),
	0x53: (0x53,'iget-wide','fmt22c',FMT22C,2),
	0x54: (0x54,'iget-object','fmt22c',FMT22C,2),
	0x55: (0x55,'iget-boolean','fmt22c',FMT22C,2),
	0x56: (0x56,'iget-byte','fmt22c',FMT22C,2),
	0x57: (0x57,'iget-char','fmt22c',FMT22C,2),
	0x58: (0x58,'iget-short','fmt22c',FMT22C,2),
	0x59: (0x59,'iput','fmt22c',FMT22C,2),
	0x5a: (0x5a,'iput-wide','fmt22c',FMT22C,2),
	0x5b: (0x5b,'iput-object','fmt22c',FMT22C,2),
	0x5c: (0x5c,'iput-boolean','fmt22c',FMT22C,2),
	0x5d: (0x5d,'iput-byte','fmt22c',FMT22C,2),
	0x5e: (0x5e,'iput-char','fmt22c',FMT22C,2),
	0x5f: (0x5f,'iput-short','fmt22c',FMT22C,2),
	0x60: (0x60,'sget','fmt21c',FMT21C,2),
	0x61: (0x61,'sget-wide','fmt21c',FMT21C,2),
	0x62: (0x62,'sget-object','fmt21c',FMT21C,2),
	0x63: (0x63,'sget-boolean','fmt21c',FMT21C,2),
	0x64: (0x64,'sget-byte','fmt21c',FMT21C,2),
	0x65: (0x65,'sget-char','fmt21c',FMT21C,2),
	0x66: (0x66,'sget-short','fmt21c',FMT21C,2),
	0x67: (0x67,'sput','fmt21c',FMT21C,2),
	0x68: (0x68,'sput-wide','fmt21c',FMT21C,2),
	0x69: (0x69,'sput-object','fmt21c',FMT21C,2),
	0x6a: (0x6a,'sput-boolean','fmt21c',FMT21C,2),
	0x6b: (0x6b,'sput-byte','fmt21c',FMT21C,2),
	0x6c: (0x6c,'sput-char','fmt21c',FMT21C,2),
	0x6d: (0x6d,'sput-short','fmt21c',FMT21C,2),
	0x6e: (0x6e,'invoke-virtual','fmt35c',FMT35C,3),
	0x6f: (0x6f,'invoke-super','fmt35c',FMT35C,3),
	0x70: (0x70,'invoke-direct','fmt35c',FMT35C,3),
	0x71: (0x71,'invoke-static','fmt35c',FMT35C,3),
	0x72: (0x72,'invoke-interface','fmt35c',FMT35C,3),
	0x73: (0x73,'unused','fmt10x',FMT10X,1),
	0x74: (0x74,'invoke-virtual/range','fmt3rc',FMT3RC,3),
	0x75: (0x75,'invoke-super/range','fmt3rc',FMT3RC,3),
	0x76: (0x76,'invoke-direct/range','fmt3rc',FMT3RC,3),
	0x77: (0x77,'invoke-static/range','fmt3rc',FMT3RC,3),
	0x78: (0x78,'invoke-interface/range','fmt3rc',FMT3RC,3),
	0x79: (0x79,'unused','fmt10x',FMT10X,1),
	0x7a: (0x7a,'unused','fmt10x',FMT10X,1),
	0x7b: (0x7b,'neg-int','fmt12x',FMT12X,1),
	0x7c: (0x7c,'not-int','fmt12x',FMT12X,1),
	0x7d: (0x7d,'neg-long','fmt12x',FMT12X,1),
	0x7e: (0x7e,'not-long','fmt12x',FMT12X,1),
	0x7f: (0x7f,'neg-float','fmt12x',FMT12X,1),
	0x80: (0x80,'neg-double','fmt12x',FMT12X,1),
	0x81: (0x81,'int-to-long','fmt12x',FMT12X,1),
	0x82: (0x82,'int-to-float','fmt12x',FMT12X,1),
	0x83: (0x83,'int-to-double','fmt12x',FMT12X,1),
	0x84: (0x84,'long-to-int','fmt12x',FMT12X,1),
	0x85: (0x85,'long-to-float','fmt12x',FMT12X,1),
	0x86: (0x86,'long-to-double','fmt12x',FMT12X,1),
	0x87: (0x87,'float-to-int','fmt12x',FMT12X,1),
	0x88: (0x88,'float-to-long','fmt12x',FMT12X,1),
	0x89: (0x89,'float-to-double','fmt12x',FMT12X,1),
	0x8a: (0x8a,'double-to-int','fmt12x',FMT12X,1),
	0x8b: (0x8b,'double-to-long','fmt12x',FMT12X,1),
	0x8c: (0x8c,'double-to-float','fmt12x',FMT12X,1),
	0x8d: (0x8d,'int-to-byte','fmt12x',FMT12X,1),
	0x8e: (0x8e,'int-to-char','fmt12x',FMT12X,1),
	0x8f: (0x8f,'int-to-short','fmt12x',FMT12X,1),
	0x90: (0x90,'add-int','fmt23x',FMT23X,2),
	0x91: (0x91,'sub-int','fmt23x',FMT23X,2),
	0x92: (0x92,'mul-int','fmt23x',FMT23X,2),
	0x93: (0x93,'div-int','fmt23x',FMT23X,2),
	0x94: (0x94,'rem-int','fmt23x',FMT23X,2),
	0x95: (0x95,'and-int','fmt23x',FMT23X,2),
	0x96: (0x96,'or-int','fmt23x',FMT23X,2),
	0x97: (0x97,'xor-int','fmt23x',FMT23X,2),
	0x98: (0x98,'shl-int','fmt23x',FMT23X,2),
	0x99: (0x99,'shr-int','fmt23x',FMT23X,2),
	0x9a: (0x9a,'ushr-int','fmt23x',FMT23X,2),
	0x9b: (0x9b,'add-long','fmt23x',FMT23X,2),
	0x9c: (0x9c,'sub-long','fmt23x',FMT23X,2),
	0x9d: (0x9d,'mul-long','fmt23x',FMT23X,2),
	0x9e: (0x9e,'div-long','fmt23x',FMT23X,2),
	0x9f: (0x9f,'rem-long','fmt23x',FMT23X,2),
	0xa0: (0xa0,'and-long','fmt23x',FMT23X,2),
	0xa1: (0xa1,'or-long','fmt23x',FMT23X,2),
	0xa2: (0xa2,'xor-long','fmt23x',FMT23X,2),
	0xa3: (0xa3,'shl-long','fmt23x',FMT23X,2),
	0xa4: (0xa4,'shr-long','fmt23x',FMT23X,2),
	0xa5: (0xa5,'ushr-long','fmt23x',FMT23X,2),
	0xa6: (0xa6,'add-float','fmt23x',FMT23X,2),
	0xa7: (0xa7,'sub-float','fmt23x',FMT23X,2),
	0xa8: (0xa8,'mul-float','fmt23x',FMT23X,2),
	0xa9: (0xa9,'div-float','fmt23x',FMT23X,2),
	0xaa: (0xaa,'rem-float','fmt23x',FMT23X,2),
	0xab: (0xab,'add-double','fmt23x',FMT23X,2),
	0xac: (0xac,'sub-double','fmt23x',FMT23X,2),
	0xad: (0xad,'mul-double','fmt23x',FMT23X,2),
	0xae: (0xae,'div-double','fmt23x',FMT23X,2),
	0xaf: (0xaf,'rem-double','fmt23x',FMT23X,2),
	0xb0: (0xb0,'add-int/2addr','fmt12x',FMT12X,1),
	0xb1: (0xb1,'sub-int/2addr','fmt12x',FMT12X,1),
	0xb2: (0xb2,'mul-int/2addr','fmt12x',FMT12X,1),
	0xb3: (0xb3,'div-int/2addr','fmt12x',FMT12X,1),
	0xb4: (0xb4,'rem-int/2addr','fmt12x',FMT12X,1),
	0xb5: (0xb5,'and-int/2addr','fmt12x',FMT12X,1),
	0xb6: (0xb6,'or-int/2addr','fmt12x',FMT12X,1),
	0xb7: (0xb7,'xor-int/2addr','fmt12x',FMT12X,1),
	0xb8: (0xb8,'shl-int/2addr','fmt12x',FMT12X,1),
	0xb9: (0xb9,'shr-int/2addr','fmt12x',FMT12X,1),
	0xba: (0xba,'ushr-int/2addr','fmt12x',FMT12X,1),
	0xbb: (0xbb,'add-long/2addr','fmt12x',FMT12X,1),
	0xbc: (0xbc,'sub-long/2addr','fmt12x',FMT12X,1),
	0xbd: (0xbd,'mul-long/2addr','fmt12x',FMT12X,1),
	0xbe: (0xbe,'div-long/2addr','fmt12x',FMT12X,1),
	0xbf: (0xbf,'rem-long/2addr','fmt12x',FMT12X,1),
	0xc0: (0xc0,'and-long/2addr','fmt12x',FMT12X,1),
	0xc1: (0xc1,'or-long/2addr','fmt12x',FMT12X,1),
	0xc2: (0xc2,'xor-long/2addr','fmt12x',FMT12X,1),
	0xc3: (0xc3,'shl-long/2addr','fmt12x',FMT12X,1),
	0xc4: (0xc4,'shr-long/2addr','fmt12x',FMT12X,1),
	0xc5: (0xc5,'ushr-long/2addr','fmt12x',FMT12X,1),
	0xc6: (0xc6,'add-float/2addr','fmt12x',FMT12X,1),
	0xc7: (0xc7,'sub-float/2addr','fmt12x',FMT12X,1),
	0xc8: (0xc8,'mul-float/2addr','fmt12x',FMT12X,1),
	0xc9: (0xc9,'div-float/2addr','fmt12x',FMT12X,1),
	0xca: (0xca,'rem-float/2addr','fmt12x',FMT12X,1),
	0xcb: (0xcb,'add-double/2addr','fmt12x',FMT12X,1),
	0xcc: (0xcc,'sub-double/2addr','fmt12x',FMT12X,1),
	0xcd: (0xcd,'mul-double/2addr','fmt12x',FMT12X,1),
	0xce: (0xce,'div-double/2addr','fmt12x',FMT12X,1),
	0xcf: (0xcf,'rem-double/2addr','fmt12x',FMT12X,1),
	0xd0: (0xd0,'add-int/lit16','fmt22s',FMT22S,2),
	0xd1: (0xd1,'rsub-int','fmt22s',FMT22S,2),
	0xd2: (0xd2,'mul-int/lit16','fmt22s',FMT22S,2),
	0xd3: (0xd3,'div-int/lit16','fmt22s',FMT22S,2),
	0xd4: (0xd4,'rem-int/lit16','fmt22s',FMT22S,2),
	0xd5: (0xd5,'and-int/lit16','fmt22s',FMT22S,2),
	0xd6: (0xd6,'or-int/lit16','fmt22s',FMT22S,2),
	0xd7: (0xd7,'xor-int/lit16','fmt22s',FMT22S,2),
	0xd8: (0xd8,'add-int/lit8','fmt22b',FMT22B,2),
	0xd9: (0xd9,'rsub-int/lit8','fmt22b',FMT22B,2),
	0xda: (0xda,'mul-int/lit8','fmt22b',FMT22B,2),
	0xdb: (0xdb,'div-int/lit8','fmt22b',FMT22B,2),
	0xdc: (0xdc,'rem-int/lit8','fmt22b',FMT22B,2),
	0xdd: (0xdd,'and-int/lit8','fmt22b',FMT22B,2),
	0xde: (0xde,'or-int/lit8','fmt22b',FMT22B,2),
	0xdf: (0xdf,'xor-int/lit8','fmt22b',FMT22B,2),
	0xe0: (0xe0,'shl-int/lit8','fmt22b',FMT22B,2),
	0xe1: (0xe1,'shr-int/lit8','fmt22b',FMT22B,2),
	0xe2: (0xe2,'ushr-int/lit8','fmt22b',FMT22B,2),
	0xe3: (0xe3,'unused','fmt10x',FMT10X,1),
	0xe4: (0xe4,'unused','fmt10x',FMT10X,1),
	0xe5: (0xe5,'unused','fmt10x',FMT10X,1),
	0xe6: (0xe6,'unused','fmt10x',FMT10X,1),
	0xe7: (0xe7,'unused','fmt10x',FMT10X,1),
	0xe8: (0xe8,'unused','fmt10x',FMT10X,1),
	0xe9: (0xe9,'unused','fmt10x',FMT10X,1),
	0xea: (0xea,'unused','fmt10x',FMT10X,1),
	0xeb: (0xeb,'unused','fmt10x',FMT10X,1),
	0xec: (0xec,'unused','fmt10x',FMT10X,1),
	0xed: (0xed,'unused','fmt10x',FMT10X,1),
	0xee: (0xee,'unused','fmt10x',FMT10X,1),
	0xef: (0xef,'unused','fmt10x',FMT10X,1),
	0xf0: (0xf0,'unused','fmt10x',FMT10X,1),
	0xf1: (0xf1,'unused','fmt10x',FMT10X,1),
	0xf2: (0xf2,'unused','fmt10x',FMT10X,1),
	0xf3: (0xf3,'unused','fmt10x',FMT10X,1),
	0xf4: (0xf4,'unused','fmt10x',FMT10X,1),
	0xf5: (0xf5,'unused','fmt10x',FMT10X,1),
	0xf6: (0xf6,'unused','fmt10x',FMT10X,1),
	0xf7: (0xf7,'unused','fmt10x',FMT10X,1),
	0xf8: (0xf8,'unused','fmt10x',FMT10X,1),
	0xf9: (0xf9,'unused','fmt10x',FMT10X,1),
	0xfa: (0xfa,'unused','fmt10x',FMT10X,1),
	0xfb: (0xfb,'unused','fmt10x',FMT10X,1),
	0xfc: (0xfc,'unused','fmt10x',FMT10X,1),
	0xfd: (0xfd,'unused','fmt10x',FMT10X,1),
	0xfe: (0xfe,'unused','fmt10x',FMT10X,1),
	0xff: (0xff,'unused','fmt10x',FMT10X,1)
}


if __name__ == "__main__":
	buffer="\x12\x01\x6a\x01\xc3\x00\x22\x00\x23\x00\x54\x31\x45\x00\x00\x00\x00\x00"
	if LOGGING: print parse_instruction(buffer)
