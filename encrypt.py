"""
Encrypts a text file and produces a set amount of share according to
Shamir's Secret Sharing Scheme.
"""
import argparse
import json
from base64 import b64encode

import shamira
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def setup_parser():
    """
    This function sets up the parser for the command line arguments,
    and returns the arguments.
    """
    parser = argparse.ArgumentParser(
                prog="encrypt.py",
                description="Produce an encrypted file and a set of shares.")

    parser.add_argument("input", type=str, help="Input file name")
    parser.add_argument("output", type=str, help="Encrypted file name, should be in .json format")
    parser.add_argument("shares", type=str, help="Shares file name, usually in .txt format")
    parser.add_argument("-e", "--encoding", type=str, default='b32', choices=['b16', 'b32', 'b64'], 
                        metavar="e", help="{hex|b32|b64} Encoding to use for shares. Default: b32")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output.")

    group = parser.add_argument_group('Shamir\'s Secret Sharing Scheme')

    group.add_argument("-n", "--needed_shares", type=int, default=3, metavar="N",
                        help="The number of shares required to reconstruct the key. Default: 3")
    group.add_argument("-t", "--total_shares", type=int, default=7, metavar="T",
                        help="The total number of shares to produce. Default: 3")
    
    return parser.parse_args()


def generate_key_and_shares(needed_shares, total_shares, encoding):
    """
    This function generates a key and a set of shares according to
    Shamir's Secret Sharing Scheme.
    """

    key = get_random_bytes(16)
    shares = shamira.generate(key, needed_shares, total_shares,
                              encoding=encoding)

    return key, shares


def encrypt(key, input, output, share_file, verbose=False):
    """
    This function encrypts the input file using AES-256 in EAX mode,
    then it produces encrypted.json and shares.txt files.
    """
    with open(input, "rb") as file_in, \
            open(output, "w", encoding='UTF-8') as file_out, \
            open(share_file, "w", encoding='UTF-8') as file_shares:

        cipher = AES.new(key, AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(file_in.read())

        json_k = ['nonce', 'tag', 'ciphertext']
        json_v = [b64encode(x).decode('utf-8')
                  for x in (cipher.nonce, tag, cipher_text)]
        result = json.dumps(dict(zip(json_k, json_v)), indent=4)
        file_out.write(result)
        if verbose:
            print(f"File written to {output}")

        for share in shares:
            file_shares.write(f"{share}\n")
        if verbose:
            print(f"Shares written to {share_file}")


if __name__ == "__main__":
    args = setup_parser()

    key, shares = generate_key_and_shares(args.needed_shares, args.total_shares, args.encoding)
    encrypt(key, args.input, args.output, args.shares, args.verbose)
