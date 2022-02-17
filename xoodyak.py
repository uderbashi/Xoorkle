'''
	Based on the paper: Xoodoo cookbook
	found at: https://eprint.iacr.org/2018/767.pdf
	C X.Y is reference to the paper at chapter X, subchapter Y
'''

# C 2 (Table 1), I randomly removed the bottom four constants so the lenth of the key would be the same as Sparkle
HASH_CONST = 0x00000058000000D000000060000000F000000038000001200000002C000001A0

def cyclic(plane, x, y):
	x = x % 4
	y = y % 8
	plane = plane[-y:] + plane[:-y]
	plane = [line[-x:] + line[:-x] for line in plane]
	return plane

def hex_not(n):
	'takes one hex value (4 bits) and gives its hex compliment'
	n = n % 0x10
	return (~n) % 0x10

def bitwise_not(plane):
	return [[hex_not(i) for i in line] for line in plane]

def bitwise_xor(plane1, plane2):
	return [[x^plane2[j][i] for i,x in enumerate(line)] for j,line in enumerate(plane1)]

def data2planes(data):
	hexes = []
	for i in range(96):
		hexes.append(data ^ (data & (~0xf)))
		data = data >> 4
	hexes.reverse()
	return [[[hexes[z*32 + y*4 + x] for x in range(4)] for y in range(8)] for z in range(3)]

def planes2data(planes):
	data = 0x0
	for plane in planes:
		for line in plane:
			for x in line:
				data = data << 4
				data |= x
	return data

def key2planes(key):
	planes = [[[0 for x in range(4)] for y in range(8)] for z in range(8)]

	for plane in planes:
		for line in plane:
			line[0] = key ^ (key & (~0xf))
			key = key >> 4

	return planes

def xoodyak_enc(in_data, key=None):
	'''
		Runs a round of xoodoo as explained in algorithm 1 C2

		Params:
		in_data (384-bit data): the input to be decrypted
		key (265-bit data): the key used for encryption, if left empty will use the defualt hash const

		Returns:
		data (348-bit data): the decrypted output
	'''
	# if no key is gven, then take the default consntant
	if key == None:
		key = HASH_CONST

	data = data2planes(in_data)
	state = data2planes(key)
	key = key2planes(key)


	for c in key:
		p = bitwise_xor(state[0], state[1])
		p = bitwise_xor(p, state[2])
		e = cyclic(p, 1, 5)
		p = cyclic(p, 1, 14) # same as (1,6) the algorithm asks for (1, 14) for some reason
		e = bitwise_xor(e, p)

		state[0] = bitwise_xor(state[0], c)
		state[1] = cyclic(state[1], 1, 0)
		state[2] = cyclic(state[1], 0, 11) # again same as (1, 3)

		b0 = bitwise_not(state[1])
		b1 = bitwise_not(state[2])
		b2 = bitwise_not(state[0])

		b0 = bitwise_xor(b0, state[2])
		b1 = bitwise_xor(b1, state[0])
		b2 = bitwise_xor(b2, state[1])

		state[0] = bitwise_xor(state[0], b0)
		state[1] = bitwise_xor(state[1], b1)
		state[2] = bitwise_xor(state[2], b2)

		state[1] = cyclic(state[1], 0, 1)
		state[2] = cyclic(state[1], 2, 8) # again same as (2, 0)

		data[0] = bitwise_xor(data[0], state[0])
		data[1] = bitwise_xor(data[1], state[1])
		data[2] = bitwise_xor(data[2], state[2])

		data[0], data[1], data[2] = data[1], data[2], data[0]


	return planes2data(data)

def xoodyak_dec(in_data, key=None):
	'''
		Reverses a round of xoodoo as explained in algorithm 1 C2

		Params:
		in_data (384-bit data): the input to be decrypted
		key (265-bit data): the key used for encryption, if left empty will use the defualt hash const

		Returns:
		data (348-bit data): the decrypted output
	'''
	# if no key is gven, then take the default consntant
	if key == None:
		key = HASH_CONST

	data = data2planes(in_data)
	state = data2planes(key)
	key = key2planes(key)
	xors = []

	for c in key:
		p = bitwise_xor(state[0], state[1])
		p = bitwise_xor(p, state[2])
		e = cyclic(p, 1, 5)
		p = cyclic(p, 1, 14) # same as (1,6) the algorithm asks for (1, 14) for some reason
		e = bitwise_xor(e, p)

		state[0] = bitwise_xor(state[0], c)
		state[1] = cyclic(state[1], 1, 0)
		state[2] = cyclic(state[1], 0, 11) # again same as (1, 3)

		b0 = bitwise_not(state[1])
		b1 = bitwise_not(state[2])
		b2 = bitwise_not(state[0])

		b0 = bitwise_xor(b0, state[2])
		b1 = bitwise_xor(b1, state[0])
		b2 = bitwise_xor(b2, state[1])

		state[0] = bitwise_xor(state[0], b0)
		state[1] = bitwise_xor(state[1], b1)
		state[2] = bitwise_xor(state[2], b2)

		state[1] = cyclic(state[1], 0, 1)
		state[2] = cyclic(state[1], 2, 8) # again same as (2, 0)

		xors.append(state.copy())

	xors.reverse()
	for xor in xors:
		data[1], data[2], data[0] = data[0], data[1], data[2]
		data[0] = bitwise_xor(data[0], xor[0])
		data[1] = bitwise_xor(data[1], xor[1])
		data[2] = bitwise_xor(data[2], xor[2])

	return planes2data(data)