from os.path import getsize

def xor_all(blocks):
	out = 0x0
	for block in blocks:
		out ^= block
	return [out]

def pad_bytes(block, size, block_size):
	block = block << (block_size - size) * 8
	output = []
	if block_size - size > 1:
		block ^= block_size - size
		output.append(block)
	else:
		output.append(block)
		output.append(2 * block_size - size)

	return output

def unpad_bytes(blocks):
	last = blocks[-1]
	checksum = last & 0xff
	if checksum > 49 or checksum < 2:
		return blocks, 0

	if checksum == 49:
		if checksum == last:
			if blocks[-2] & 0xff == 0:
				return blocks[:-1], 1
	else:
		mask = 2 ** (checksum * 8) - 1
		if last & mask == checksum:
			return blocks, checksum

	return blocks, 0

def read_file_bytes(path, block_size=48, allow_pad=True, ignore_last=False):
	output = []

	with open(path, 'rb') as file:

		block = file.read(block_size)
		while block:
			output.append(int.from_bytes(block, byteorder='big'))
			block = file.read(block_size)

	size = getsize(path)

	if ignore_last: # if a signature was attached
		output = output[:-1]
		csize = size % block_size
		if csize != 0:
			output[-1] = output[-1] >> ((block_size - csize) * 8)

	if size % block_size != 0:
		if not allow_pad:
			print(f'The file {path} is not in the required {block_size}-byte limit, and padding is not allowed.')
			exit()

		pad = pad_bytes(output[-1], size % block_size, block_size)
		output = output[:-1] + pad

	return output

def write_file_bytes(path, blocks, block_size=48, unpad=True):
	pad = 0
	if unpad:
		blocks, pad = unpad_bytes(blocks)
	with open(path, 'wb') as file:
		for block in blocks:
			if unpad and block is blocks[-1]:
				block_size -= pad
				block = block >> pad * 8
			file.write(block.to_bytes(block_size, byteorder='big'))