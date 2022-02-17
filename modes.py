# I took IV as the first 96 digits of pi
IV = 0x314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211

def ecb_enc(blocks, algo, key=None):
	output = []
	for block in blocks:
		output.append(algo(block, key))
	return output

def ecb_dyc(blocks, algo, key=None):
	return ecb_enc(blocks, algo, key)

def cbc_enc(blocks, algo, key=None):
	output = []
	chain = IV

	for block in blocks:
		block  ^= chain
		output.append(algo(block, key))
		chain = output[-1]

	return output

def cbc_dyc(blocks, algo, key=None):
	output = []
	chain = IV

	for block in blocks:
		output.append(algo(block, key))
		output[-1]  ^= chain
		chain = block

	return output

def cfb_enc(blocks, algo, key=None):
	output = []
	feedback = IV

	for block in blocks:
		output.append(algo(feedback, key))
		output[-1] ^= block
		feedback = output[-1]

	return output

def cfb_dyc(blocks, algo, key=None):
	output = []
	feedback = IV

	for block in blocks:
		output.append(algo(feedback, key))
		output[-1] ^= block
		feedback = block

	return output

def ofb_enc(blocks, algo, key=None):
	output = []
	feedback = IV

	for block in blocks:
		output.append(algo(feedback, key))
		feedback = output[-1]
		output[-1] ^= block

	return output

def ofb_dyc(blocks, algo, key=None):
	return ofb_enc(blocks, algo, key)