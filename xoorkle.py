import argparse
import sys
from modes import ecb_enc, ecb_dyc, cbc_enc, cbc_dyc, cfb_enc, cfb_dyc, ofb_enc, ofb_dyc
from sparkle import sparkle_enc, sparkle_dec
from xoodyak import xoodyak_enc, xoodyak_dec
from util import read_file_bytes, write_file_bytes, xor_all

def parser():
	des = """This is the homework of Usama Derbashi, student number 171044078 in Gebze Technical University, for his CSE470 Introduction to Cryptography class.
		The program encrypts, decrypts, signs, and generate hashes for files, as well as comparing a file's hash with a pre-generated hash,
		and checking if a file was signed using a certain certificate.
		The algorithms supported can be either Xoodyak or Sparkle as per the list announced in November 2021."""

	epi = """The requirement of an IO argument depends on the action selected, please read the description of the action to see what argumnet it requires.
	In the case of putting an unrequired argument in, the argument will be ignored."""

	parser = argparse.ArgumentParser(description=des, epilog=epi)

	r_group = parser.add_argument_group('Required Arguments')
	r_group.add_argument('-a', required=True, type=str, choices=['xoodyak', 'sparkle'], help="the algorithm to be used")
	r_group.add_argument('-m', required=True, type=str, choices=['ecb', 'cbc', 'cfb', 'ofb'], help="the mode of running")

	a_group = parser.add_argument_group('Action Arguments (only one is required)')
	action = a_group.add_mutually_exclusive_group(required=True)
	action.add_argument('-e', action='store_true', help='encrypts -i with -hi into -o')
	action.add_argument('-d', action='store_true', help='decrypts -i with -hi into -o')
	action.add_argument('-s', action='store_true', help='signs -i with -hi into -o')
	action.add_argument('-v', action='store_true', help='validates whether -i was signed with -hi')
	action.add_argument('-g', action='store_true', help='generates the hash of -i into -o')
	action.add_argument('-c', action='store_true', help='compare the hash of -i with the hash in -hi')

	io_group = parser.add_argument_group('IO Arguments')
	io_group.add_argument('-i', metavar='input', required=True, type=str, help="the input file name")
	io_group.add_argument('-hi', metavar='helper', required=any(item in ['-h','--help','-e','-d','-s','-v','-c'] for item in sys.argv), type=str, help="the helper input file name")
	io_group.add_argument('-o', metavar='output', required=any(item in ['-h','--help','-e','-d','-g'] for item in sys.argv), type=str, help="the output file name")

	return parser.parse_args()

def main():
	args = parser()

	if args.a == 'xoodyak':
		_enc, _dyc = xoodyak_enc, xoodyak_dec
	else:
		_enc, _dyc = sparkle_enc, sparkle_dec

	if args.m == 'ecb':
		enc, dyc = ecb_enc, ecb_dyc
	elif args.m == 'cbc':
		enc, dyc = cbc_enc, cbc_dyc
	elif args.m == 'cfb':
		enc, dyc = cfb_enc, cfb_dyc
		_dyc = _enc
	else:
		enc, dyc = ofb_enc, ofb_dyc
		_dyc = _enc

	if args.e:
		blocks = read_file_bytes(args.i)
		key = read_file_bytes(args.hi, block_size=32)[0]
		out = enc(blocks, _enc, key)
		write_file_bytes(args.o, out, unpad=False)
		print(f"\nDone encrypting {args.i} into {args.o} with the key from {args.hi}.\nUsed {args.a} in {args.m} mode.")

	elif args.d:
		blocks = read_file_bytes(args.i)
		key = read_file_bytes(args.hi, block_size=32)[0]
		out = dyc(blocks, _dyc, key)
		write_file_bytes(args.o, out)
		print(f"\nDone decrypting {args.i} into {args.o} with the key from {args.hi}.\nUsed {args.a} in {args.m} mode.")

	elif args.s:
		blocks = read_file_bytes(args.i)
		key = read_file_bytes(args.hi, block_size=32)[0]
		out = enc(blocks, _enc, key)
		out = xor_all(out)
		with open(args.i, 'ab') as file:
			file.write(out[0].to_bytes(48, byteorder='big'))
		print(f"\nDone signing {args.i} into {args.o} with the signature from {args.hi}.\nUsed {args.a} in {args.m} mode.")

	elif args.v:
		blocks = read_file_bytes(args.i, ignore_last=True)
		key = read_file_bytes(args.hi, block_size=32)[0]
		out = enc(blocks, _enc, key)
		out = xor_all(out)
		with open(args.i, 'rb') as file:
			file.seek(-48, 2)
			comp = int.from_bytes(file.read(48), byteorder='big')
		if out[0] == comp:
			print(f"\nThe signature from {args.hi} have signed {args.i} using {args.a} in {args.m} mode.")
		else:
			print(f'\nEither a differnt key (not the one in {args.hi}), algorithm (not {args.a}), or mode (not {args.m}) was used to sign {args.i}.\nIf all above match, then the file was tampered with.')

	elif args.g:
		blocks = read_file_bytes(args.i)
		out = enc(blocks, _enc)
		out = xor_all(out)
		print(f'\nHashing the file {args.i} with {args.a} in the mode {args.m} produces the following:\n{hex(out[0])}')
		write_file_bytes(args.o, out, unpad=False)

	elif args.c:
		blocks = read_file_bytes(args.i)
		comp = read_file_bytes(args.hi)
		out = enc(blocks, _enc)
		out = xor_all(out)
		if out[0] == comp[0]:
			print(f'\nThe file {args.i} produced THE SAME hash as the one found in {args.hi} using {args.a} in {args.m} mode.')
		else:
			print(f'\nThe file {args.i} produced A DIFFERENT hash compared to the one found in {args.hi} using {args.a} in {args.m} mode.\nCheck the algorithm, the mode, and the hash file.')

if __name__ == '__main__':
	main()
