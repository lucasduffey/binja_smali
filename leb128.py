import struct

# https://source.android.com/devices/tech/dalvik/dex-format.html
def get_uleb128p1(data):
	byte_count, value = get_uleb128(data)
	value -= 1

	return byte_count, value

# https://github.com/ondreji/dex_parser/blob/master/leb128.py
def get_uleb128(content):
	value = 0
	for i in xrange(0,5):
		tmp = ord(content[i]) & 0x7f
		value = tmp << (i * 7) | value
		if (ord(content[i]) & 0x80) != 0x80:
			break
	if i == 4 and (tmp & 0xf0) != 0:
		print "parse a error uleb128 number"
		return -1
	return i+1, value

'''
# MINE: THIS MAY BE WRONG
def get_uleb128(data):
	total = 0
	found = False

	for i in xrange(5):
		value = ord(data[i])
		high_bit = (ord(data[i]) >> 7)

		# clear the high bit
		total += (value & 0x7f) << (i * 7) | total

		# this is the last byte, so break
		if high_bit == 0:
			found = True
			break

	if not found: # redundant to also check for "i == 4"?
		log(3, "invalid ULEB128")
		assert False

	return i+1, total
'''

# https://github.com/ondreji/dex_parser/blob/master/leb128.py
def get_sleb128(content):
	value = 0

	mask=[0xffffff80,0xffffc000,0xffe00000,0xf0000000,0]
	bitmask=[0x40,0x40,0x40,0x40,0x8]
	value = 0
	for i in xrange(0,5):
		tmp = ord(content[i]) & 0x7f
		value = tmp << (i * 7) | value
		if (ord(content[i]) & 0x80) != 0x80:
			if bitmask[i] & tmp:
				value |= mask[i]
			break
	if i == 4 and (tmp & 0xf0) != 0:
		print "parse a error uleb128 number"
		return -1
	buffer = struct.pack("I",value)
	value, =struct.unpack("i",buffer)
	return i+1, value

'''
# MINE: THIS MAY BE WRONG
def get_sleb128(data):
	total = 0
	found = False
	shift = 0

	# NOT SURE IF THIS IS RIGHT...
	for i in xrange(5):
		value = ord(data[i])
		high_bit = (ord(data[i]) >> 7)

		total |= (value & 0x7f) << shift
		shift += 7

		if high_bit == 0:
			found = True
			break

	if value & 0x40:
		total |= (-1) << shift

	if not found: # redundant to also check for "i == 4"?
		assert False

	return i+1, total
'''

# test cases
assert get_sleb128("\x00")[1] == 0
assert get_sleb128("\x01")[1] == 1
assert get_sleb128("\x7f")[1] == -1
assert get_sleb128("\x80\x7f")[1] == -128
