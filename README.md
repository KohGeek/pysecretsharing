# Python Secret Sharing

> [!WARNING]
> Not validated for high security use. Can be useful for simple secret sharing.

The program uses AES EAX mode to encrypt/decrypt a file and then uses Shamir's Secret Sharing to achieve secret sharing.

## Setup

Install all the dependencies listed in requirements.txt

## Example

To encrypt a file, run the following command:

```bash
python3 encrypt.py <input_filename> <output_filename> <shares_filename>
```

To decrypt a file, run the following command:

```bash
# runs in interactive mode
python3 decrypt.py <input_filename> <output_filename> -i
```

or

```bash
# provide shares as command line arguments
python3 decrypt.py <input_filename> <output_filename> -s <share_1> <share_2> ... <share_n>
```


## Help

Help for encrypt.py

```txt
usage: encrypt.py [-h] [-e e] [-v] [-n N] [-t T] input output shares

Produce an encrypted file and a set of shares.

positional arguments:
  input                 Input file name
  output                Encrypted file name, should be in .json format
  shares                Shares file name, usually in .txt format

options:
  -h, --help            show this help message and exit
  -e e, --encoding e    {hex|b32|b64} Encoding to use for shares. Default: b32
  -v, --verbose         Verbose output.

Shamir's Secret Sharing Scheme:
  -n N, --needed_shares N
                        The number of shares required to reconstruct the key. Default: 3
  -t T, --total_shares T
                        The total number of shares to produce. Default: 3
```

Help for decrypt.py

```txt
(secrets) PS C:\Users\KohCo\Desktop\secrets> python .\decrypt.py -h
usage: decrypt.py [-h] [-e e] [-v] (-s S [S ...] | -i) input output

Decrypts the encrypted file with a set of shares.

positional arguments:
  input                 Encrypted file name, should be in .json format
  output                Output file name

options:
  -h, --help            show this help message and exit
  -e e, --encoding e    {hex|b32|b64} Encoding to use for shares. Default: b32
  -v, --verbose         Verbose output.

Share input:
  -s S [S ...], --shares S [S ...]
                        All shares required to reconstruct the key.
  -i, --interactive     Interactive mode. You will be prompted to enter the shares.
```
