"""
Decrypts encrypted.json 
"""
import argparse
import json
from base64 import b64decode

import shamira
from Crypto.Cipher import AES


def setup_parser():
    """
    This function sets up the parser for the command line arguments,
    and returns the arguments.
    """
    parser = argparse.ArgumentParser(
                prog="decrypt.py",
                description="Decrypts the encrypted file with a set of shares.")

    parser.add_argument("input", type=str, help="Encrypted file name, should be in .json format")
    parser.add_argument("output", type=str, help="Output file name")
    parser.add_argument("-e", "--encoding", type=str, default='b32', choices=['b16', 'b32', 'b64'], 
                        metavar="e", help="{hex|b32|b64} Encoding to use for shares. Default: b32")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output.")

    group = parser.add_argument_group('Share input')
    share_group = group.add_mutually_exclusive_group(required=True)

    share_group.add_argument("-s", "--shares", type=str, nargs="+", metavar="S", 
                        help="All shares required to reconstruct the key.")
    share_group.add_argument("-i", "--interactive", action="store_true",
                        help="Interactive mode. You will be prompted to enter the shares.")
  
    return parser.parse_args()


def interactive_mode(verbose=False):
    """
    This function prompts the user to enter the shares.
    """
    shares = []

    in_str = input("Submit the first share: ")

    shares.append(in_str)
    k, _, _, _ = [s.strip() for s in in_str.split(".")]

    for i in range(int(k)-1):
        in_str = input(f"Enter the next share, {int(k) - 1 - i} left: ")
        shares.append(in_str)

    if verbose:
        print("Shares have been loaded.")
        print(shares)

    return shares


def decrypt(key, input, output, verbose=False):
    """
    This function decrypts the encrypted.txt file using AES-256 in EAX mode,
    then it produces credentials.txt file.
    AES key is never revealed to the user and is only stored in memory.
    """

    with open(input, "rb") as file_in:
        b64 = json.load(file_in)
        json_k = ['nonce', 'tag', 'ciphertext']
        json_v = {k: b64decode(b64[k]) for k in json_k}
        if verbose:
            print(f"Input file {input} has been loaded.")

        try:
            cipher = AES.new(key, AES.MODE_EAX, nonce=json_v['nonce'])
            plaintext = cipher.decrypt_and_verify(
                json_v['ciphertext'], json_v['tag'])
            with open(output, "wb") as file_out:
                file_out.write(plaintext)
            if verbose:
                print(f"File written to {output}")
        except ValueError:
            print("The shares were incorrect")


if __name__ == "__main__":
    args = setup_parser()

    shares = []
    if args.interactive:
        shares = interactive_mode(args.verbose)
    else:
        shares = args.shares
    
    try:
        key = shamira.reconstruct(*shares, encoding=args.encoding, raw=True)
    except UnicodeDecodeError as e:
        print(e)

    decrypt(key, args.input, args.output, args.verbose)
