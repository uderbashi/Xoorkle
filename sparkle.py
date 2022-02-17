'''
	Based on the paper: Lightweight AEAD and Hashing using the Sparkle Permutation Family
	found at: https://tosc.iacr.org/index.php/ToSC/article/view/8627/8193
	C X.Y is reference to the paper at chapter X, subchapter Y
'''

# C 2.1.1 (Algorithm 1)
HASH_CONST = 0xb7e15162bf71588038b4da56324e7738bb1185eb4f7c7b57cfbfa1c8c2b3293d

def remove_excess(data):
	'makes sure the data is 32-bit'
	return (data & 0xffffffff)

def rotate(data, offset):
	offset = offset % 32 #in case given large offset
	return remove_excess((data >> offset) | (data << (32 - offset)))


def diff_l(data):
	'the l function found at C 2.1.2'
	return rotate(data, 16) ^ (data & 0xffff)

def data2arr(data, lim=12):
	arr = []
	for i in range(lim):
		arr.append(data ^ (data & (~0xffffffff)))
		data = data >> 32
	arr.reverse()
	return arr

def arr2data(arr):
	data = 0x0
	for x in arr:
		data = data << 32
		data |= x
	return data

def sparkle_enc(in_data, key=None):
	'''
		Runs a round of sparkle as explained in algorithm 1 C2.1.1

		Params:
		in_data (384-bit data): the input to be encrypted
		key (256-bit data): the key used for encryption, if left empty will use the defualt hash const

		Returns:
		data (384-bit data): the encrypted output
	'''
	# if no key is gven, then take the default consntant
	if key == None:
		key = HASH_CONST

	# convert to arrays of 32-bit chunks
	data = data2arr(in_data)
	key = data2arr(key, 8)

	for i, c in enumerate(key):

		# XOR with round key and number
		data[1] ^= c
		data[3] ^= i

		# Alzette ARX-Box C 2.1.1 (referencing https://eprint.iacr.org/2019/1378.pdf)
		for j in range(0, 12, 2):
			rc = key[j>>1] # the c for the sub-round
			data[j] = remove_excess(data[j] + rotate(data[j+1], 31))
			data[j+1] ^= rotate(data[j], 24)
			data[j] ^= rc
			data[j] = remove_excess(data[j] + rotate(data[j+1], 17))
			data[j+1] ^= rotate(data[j], 17)
			data[j] ^= rc
			data[j] = remove_excess(data[j] + data[j+1])
			data[j+1] ^= rotate(data[j], 31)
			data[j] ^= rc
			data[j] = remove_excess(data[j] + rotate(data[j+1], 24))
			data[j+1] ^= rotate(data[j], 16)
			data[j] ^= rc

		# Linear Diffusion layer C 2.1.2
		tmpx = x = data[0]
		tmpy = y = data[1]

		for j in range(2, 6, 2):
			tmpx ^= data[j]
			tmpy ^= data[j+1]

		tmpx = diff_l(tmpx)
		tmpy = diff_l(tmpy)

		for j in range(2, 6, 2):
			data[j-2] = data[j+6] ^ data[j] ^ tmpy
			data[j-1] = data[j+7] ^ data[j+1] ^ tmpx
			data[j+6] = data[j]
			data[j+7] = data[j+1]

		data[4] = data[6] ^ x ^ tmpy
		data[5] = data[7] ^ y ^ tmpx
		data[6] = x
		data[7] = y

	return arr2data(data)

def sparkle_dec(in_data, key=None):
	'''
		Reverses a round of sparkle as explained in algorithm 1 C2.1.1

		Params:
		in_data (384-bit data): the input to be decrypted
		key (265-bit data): the key used for encryption, if left empty will use the defualt hash const

		Returns:
		data (348-bit data): the decrypted output
	'''
	# if no key is gven, then take the default consntant
	if key == None:
		key = HASH_CONST

	# convert to arrays of 32-bit chunks
	data = data2arr(in_data)
	key = data2arr(key, 8)

	for i in range(len(key)-1, -1, -1):

		# Linear Diffusion layer C 2.1.2
		tmpx = tmpy = 0
		x = data[4]
		y = data[5]

		for j in range(4, 0, -2):
			data[j] = data[j+6]
			tmpx ^= data[j]
			data[j+6] = data[j-2]
			data[j+1] = data[j+7]
			tmpy ^= data[j+1]
			data[j+7] = data[j-1]

		data[0] = data[6]
		tmpx ^= data[6]
		data[6] = x
		data[1] = data[7]
		tmpy ^= data[7]
		data[7] = y

		tmpx = diff_l(tmpx)
		tmpy = diff_l(tmpy)

		for j in range(4, -1, -2):
			data[j+6] ^= (tmpy ^ data[j])
			data[j+7] ^= (tmpx ^ data[j+1])

		# Alzette ARX-Box C 2.1.1 (referencing https://eprint.iacr.org/2019/1378.pdf)
		for j in range(0, 12, 2):
			rc = key[j>>1];
			data[j] ^= rc;
			data[j+1] ^= rotate(data[j], 16);
			data[j] = remove_excess(data[j] - rotate(data[j+1], 24))
			data[j] ^= rc;
			data[j+1] ^= rotate(data[j], 31);
			data[j] = remove_excess(data[j] - data[j+1])
			data[j] ^= rc;
			data[j+1] ^= rotate(data[j], 17);
			data[j] = remove_excess(data[j] - rotate(data[j+1], 17))
			data[j] ^= rc;
			data[j+1] ^= rotate(data[j], 24);
			data[j] = remove_excess(data[j] - rotate(data[j+1], 31))


		# XOR with round key and number
		data[1] ^= key[i]
		data[3] ^= i

	return arr2data(data)